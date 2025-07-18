import os
import sys
import time
import schedule
import requests
import logging
import argparse
from pymongo import MongoClient, errors
from dotenv import load_dotenv
import backoff
from datetime import datetime
from contextlib import nullcontext

# OpenTelemetry imports
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.propagate import inject

# Load .env if present (optional)
load_dotenv()

# Setup logging
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s"
)
logger = logging.getLogger("threat-fetcher")

# MongoDB Setup
try:
    MONGO_URI = os.environ["MONGODB_URI"]
except KeyError:
    logger.error("❌ MONGODB_URI environment variable not set.")
    sys.exit(1)

try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.server_info()  # Test connection
    db = client["threatintel"]
    collection = db["threats"]
    logger.info("✅ Connected to MongoDB successfully.")
except errors.ServerSelectionTimeoutError as e:
    logger.exception("❌ MongoDB connection failed.")
    sys.exit(1)

# OTX API Key
try:
    OTX_API_KEY = os.environ["OTX_API_KEY"]
except KeyError:
    logger.error("❌ OTX_API_KEY environment variable not set.")
    sys.exit(1)

ALIENVAULT_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
HEADERS = {"X-OTX-API-KEY": OTX_API_KEY}

# OpenTelemetry Tracing setup
try:
    tracer_provider = TracerProvider(
        resource=Resource.create({SERVICE_NAME: "threat-fetcher"})
    )
    trace.set_tracer_provider(tracer_provider)

    exporter = OTLPSpanExporter(
        endpoint=os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://openobserve:5080/api/default/v1/traces"),
        headers={"Authorization": os.getenv("OTEL_EXPORTER_OTLP_AUTH", "")},
    )
    span_processor = BatchSpanProcessor(exporter)
    tracer_provider.add_span_processor(span_processor)
    tracer = trace.get_tracer("threat-fetcher")
    logger.info("🛰️ Tracing initialized")
except Exception:
    tracer = None
    logger.warning("⚠️ Tracing not initialized")

# Backoff logging callback
def log_backoff(details):
    logger.warning(f"🔁 Retry #{details['tries']} in {details['wait']:0.1f}s due to {details['target'].__name__}")

@backoff.on_exception(
    backoff.expo,
    (requests.RequestException, errors.PyMongoError),
    max_tries=5,
    on_backoff=log_backoff,
)
def fetch_threats():
    with tracer.start_as_current_span("alienvault.pull.threats") if tracer else nullcontext() as span:
        logger.info("📡 Fetching threats from AlienVault OTX...")

        # Inject trace context into headers
        headers = HEADERS.copy()
        if tracer:
            inject(headers)

        try:
            res = requests.get(ALIENVAULT_URL, headers=headers, timeout=10)
            res.raise_for_status()
            data = res.json()

            results = data.get("results", [])
            if span:
                span.set_attribute("otx.result.count", len(results))

            new_count = 0
            duplicate_count = 0

            for pulse in results:
                for indicator in pulse.get("indicators", []):
                    doc = {
                        "indicator": indicator.get("indicator"),
                        "type": indicator.get("type"),
                        "severity": pulse.get("threat_hunting", {}).get("severity", "unknown"),
                        "timestamp": pulse.get("modified") or datetime.utcnow().isoformat() + "Z",
                    }

                    result = collection.update_one(
                        {"indicator": doc["indicator"], "timestamp": doc["timestamp"]},
                        {"$setOnInsert": doc},
                        upsert=True,
                    )

                    if result.upserted_id:
                        logger.info(f"✅ New threat: {doc['indicator']}")
                        new_count += 1
                    else:
                        duplicate_count += 1

            logger.info(f"🧠 Upserted {new_count} new threats, 💤 Skipped {duplicate_count} duplicates.")
            if span:
                span.set_attribute("mongo.inserted", new_count)
                span.set_attribute("mongo.duplicates", duplicate_count)

        except requests.RequestException as e:
            logger.error(f"❌ HTTP {res.status_code if 'res' in locals() else 'ERR'} from OTX: {e}")
            if span:
                span.record_exception(e)
            raise
        except Exception as e:
            logger.exception("❌ Unexpected error during fetch")
            if span:
                span.record_exception(e)
            raise

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Threat fetcher from AlienVault OTX")
    parser.add_argument("--fetch-now", action="store_true", help="Run once immediately and exit")
    parser.add_argument("--loop-delay", type=int, default=60, help="Polling interval in seconds")
    args = parser.parse_args()

    if args.fetch_now:
        fetch_threats()
    else:
        schedule.every(args.loop_delay).seconds.do(fetch_threats)
        logger.info(f"🚀 Threat fetcher running every {args.loop_delay}s...")

        while True:
            schedule.run_pending()
            time.sleep(1)
