# fetcher.py
import os
import requests
from pymongo import MongoClient, errors
from datetime import datetime
from contextlib import nullcontext
from dotenv import load_dotenv
import backoff
from opentelemetry.propagate import inject

load_dotenv()

def connect_mongo(logger):
    uri = os.getenv("MONGODB_URI")
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        client.server_info()
        db = client["threatintel"]
        logger.info("✅ Connected to MongoDB")
        return db["threats"]
    except Exception:
        logger.exception("❌ MongoDB connection failed")
        exit(1)

def get_api_keys(logger):
    try:
        otx = os.environ["OTX_API_KEY"]
        vt = os.environ["VT_API_KEY"]
        return otx, vt
    except KeyError as e:
        logger.error(f"❌ Missing env var: {e}")
        exit(1)

@backoff.on_exception(backoff.expo, (requests.RequestException, errors.PyMongoError), max_tries=5)
def fetch_otx_threats(logger, tracer, headers, url, stream, service):
    with tracer.start_as_current_span("alienvault.pull.indicators") if tracer else nullcontext() as span:
        logger.info("📡 Fetching threats from AlienVault OTX...")
        inject(headers) if tracer else None
        res = requests.get(url, headers=headers, timeout=10)
        res.raise_for_status()
        data = res.json()

        indicators = []
        for pulse in data.get("results", []):
            for ind in pulse.get("indicators", []):
                i = ind.get("indicator")
                t = ind.get("type")
                if i and t:
                    indicators.append({
                        "indicator": i,
                        "type": t,
                        "timestamp": pulse.get("modified", datetime.utcnow().isoformat() + "Z")
                    })

        logger.info(f"ℹ️ Extracted {len(indicators)} indicators")
        if span:
            span.set_attribute("otx.indicator.count", len(indicators))
            span.set_attribute("service.name", service)
            span.set_attribute("stream.name", stream)
        return indicators

def insert_threats(collection, logger, tracer, indicators, counters, stream, service):
    insert_counter, otx_counter = counters
    new, dup = 0, 0
    for item in indicators:
        result = collection.update_one(
            {"indicator": item["indicator"], "type": item["type"], "timestamp": item["timestamp"]},
            {"$setOnInsert": item},
            upsert=True,
        )
        if result.upserted_id:
            logger.info(f"✅ Inserted: {item['indicator']} ({item['type']})")
            new += 1
            if insert_counter:
                insert_counter.add(1, {"service.name": service, "stream.name": stream, "type": item["type"]})
            if otx_counter:
                otx_counter.add(1, {"service.name": service, "stream.name": stream, "type": item["type"]})
        else:
            dup += 1

    logger.info(f"🧠 {new} new indicators, 💤 {dup} duplicates")
    return new
