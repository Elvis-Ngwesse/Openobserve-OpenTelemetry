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
import psutil

# OpenTelemetry imports
from opentelemetry import trace, metrics
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.propagate import inject

# 🆕 Log exporter imports
from opentelemetry._logs import set_logger_provider
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter

# For injecting trace info into logs
from opentelemetry.trace import get_current_span

# 🌍 Load environment
load_dotenv()

# ------------------ Constants -------------------
SERVICE_NAME_STR = "threat-fetcher"

# ------------- Custom OTEL Log Formatter to add trace info -------------

class OTELLogFormatter(logging.Formatter):
    def format(self, record):
        span = get_current_span()
        span_context = span.get_span_context() if span else None

        trace_id = None
        span_id = None
        if span_context and span_context.trace_id != 0:
            trace_id = format(span_context.trace_id, "032x")
            span_id = format(span_context.span_id, "016x")

        record.trace_id = trace_id or "no-trace"
        record.span_id = span_id or "no-span"
        record.service_name = SERVICE_NAME_STR

        fmt_orig = self._style._fmt
        self._style._fmt = (
            f"%(asctime)s 🌐 %(levelname)s | %(message)s | "
            f"[service={record.service_name} trace_id={record.trace_id} span_id={record.span_id}]"
        )
        result = super().format(record)
        self._style._fmt = fmt_orig
        return result


# ——— Logging Setup ———
logger = logging.getLogger()
logger.setLevel(logging.INFO)

console_handler = logging.StreamHandler(sys.stdout)
console_formatter = OTELLogFormatter()
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)

# OpenTelemetry Log Exporter setup
try:
    log_exporter = OTLPLogExporter(
        endpoint=os.getenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"),
        headers={
            "Authorization": os.getenv("OTEL_EXPORTER_OTLP_AUTH"),
            "stream-name": os.getenv("OTEL_LOG_STREAM", "default"),
        }
    )
    logger_provider = LoggerProvider(resource=Resource.create({SERVICE_NAME: SERVICE_NAME_STR}))
    logger_provider.add_log_record_processor(BatchLogRecordProcessor(log_exporter))
    set_logger_provider(logger_provider)

    otel_log_handler = LoggingHandler(level=logging.INFO, logger_provider=logger_provider)
    otel_log_handler.setFormatter(console_formatter)
    logger.addHandler(otel_log_handler)

    logger.info("📝 OpenTelemetry Log Exporter initialized successfully.")
except Exception as e:
    logger.error(f"⚠️ Failed to initialize OpenTelemetry log exporter: {e}")

# -------------------- MongoDB Setup --------------------
try:
    MONGO_URI = os.environ["MONGODB_URI"]
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.server_info()
    db = client["threatintel"]
    collection = db["threats"]
    logger.info("✅ Connected to MongoDB successfully.")
except Exception:
    logger.exception("❌ MongoDB connection failed.")
    sys.exit(1)

# -------------------- API Keys --------------------
try:
    OTX_API_KEY = os.environ["OTX_API_KEY"]
    VT_API_KEY = os.environ["VT_API_KEY"]
except KeyError as e:
    logger.error(f"❌ Missing environment variable: {e}")
    sys.exit(1)

ALIENVAULT_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
HEADERS_OTX = {"X-OTX-API-KEY": OTX_API_KEY}
HEADERS_VT = {"x-apikey": VT_API_KEY}

# ------------------ Tracing Setup ------------------
try:
    tracer_provider = TracerProvider(resource=Resource.create({SERVICE_NAME: SERVICE_NAME_STR}))
    trace.set_tracer_provider(tracer_provider)

    trace_exporter = OTLPSpanExporter(
        endpoint=os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
        headers={"Authorization": os.getenv("OTEL_EXPORTER_OTLP_AUTH")},
    )
    span_processor = BatchSpanProcessor(trace_exporter)
    tracer_provider.add_span_processor(span_processor)
    tracer = trace.get_tracer(SERVICE_NAME_STR)
    logger.info("🛰️ Tracing initialized")
except Exception:
    tracer = None
    logger.warning("⚠️ Tracing not initialized")

# ------------------ Metrics Setup ------------------
try:
    metric_exporter = OTLPMetricExporter(
        endpoint=os.getenv("OTEL_EXPORTER_OTLP_METRIC_ENDPOINT"),
        headers={"Authorization": os.getenv("OTEL_EXPORTER_OTLP_AUTH")},
    )
    metric_reader = PeriodicExportingMetricReader(metric_exporter, export_interval_millis=60000)
    meter_provider = MeterProvider(metric_readers=[metric_reader])
    metrics.set_meter_provider(meter_provider)
    meter = metrics.get_meter(SERVICE_NAME_STR)

    otx_indicator_counter = meter.create_counter("otx_indicators_total", description="Indicators fetched")
    cpu_usage_counter = meter.create_counter("cpu_usage_percent", description="CPU usage %")
    memory_usage_counter = meter.create_counter("memory_usage_mb", description="Memory usage in MB")
    insert_counter = meter.create_counter("threats_inserted", description="New threats inserted")
    logger.info("📈 Metrics initialized")
except Exception:
    meter = None
    otx_indicator_counter = None
    cpu_usage_counter = None
    memory_usage_counter = None
    insert_counter = None
    meter_provider = None
    logger.warning("⚠️ Metrics not initialized")


# ------------------ Backoff logging ------------------
def log_backoff(details):
    logger.warning(f"🔁 Retry #{details['tries']} in {details['wait']:.1f}s due to {details['target'].__name__}")


# ------------------ Record resource metrics ------------------
def record_metrics():
    if not meter:
        return
    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.Process().memory_info().rss / 1024 / 1024
    cpu_usage_counter.add(cpu) if cpu_usage_counter else None
    memory_usage_counter.add(mem) if memory_usage_counter else None
    logger.info(f"📊 CPU: {cpu}%, Memory: {mem:.2f} MB")


# ------------------ Fetch OTX indicators ------------------
@backoff.on_exception(backoff.expo, (requests.RequestException, errors.PyMongoError), max_tries=5,
                      on_backoff=log_backoff)
def fetch_otx_threats():
    with tracer.start_as_current_span("alienvault.pull.indicators") if tracer else nullcontext() as span:
        logger.info("📡 Fetching threats from AlienVault OTX...")
        headers = HEADERS_OTX.copy()
        inject(headers) if tracer else None

        res = requests.get(ALIENVAULT_URL, headers=headers, timeout=10)
        res.raise_for_status()
        data = res.json()

        indicators = []
        for pulse in data.get("results", []):
            for ind in pulse.get("indicators", []):
                indicator = ind.get("indicator")
                ind_type = ind.get("type")
                if indicator and ind_type:
                    indicators.append({
                        "indicator": indicator,
                        "type": ind_type,
                        "timestamp": pulse.get("modified", datetime.utcnow().isoformat() + "Z")
                    })

        logger.info(f"ℹ️ Extracted {len(indicators)} indicators from OTX.")
        if span:
            span.set_attribute("otx.indicator.count", len(indicators))
        return indicators


# ------------------ Main logic: insert only new indicators ------------------
def fetch_threats():
    record_metrics()
    indicators = fetch_otx_threats()
    new_count = 0
    duplicate_count = 0

    for item in indicators:
        result = collection.update_one(
            {"indicator": item["indicator"], "type": item["type"], "timestamp": item["timestamp"]},
            {"$setOnInsert": item},
            upsert=True,
        )
        if result.upserted_id:
            logger.info(f"✅ Inserted: {item['indicator']} ({item['type']})")
            new_count += 1
            if insert_counter:
                insert_counter.add(1)
            if otx_indicator_counter:
                otx_indicator_counter.add(1, {"type": item["type"]})
        else:
            duplicate_count += 1

    logger.info(f"🧠 Inserted {new_count} new indicators, 💤 Skipped {duplicate_count} duplicates.")
    if meter_provider:
        meter_provider.force_flush()
        logger.info("📤 Metrics manually exported.")


# ------------------ Entry point ------------------
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
