import os
import time
import schedule
import requests
import logging
import argparse
from pymongo import MongoClient, errors
from dotenv import load_dotenv
import backoff

# Optional: Load .env if running locally
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger("threat-fetcher")

# Validate and connect to MongoDB
try:
    MONGO_URI = os.environ["MONGODB_URI"]
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.server_info()
    db = client["threatintel"]
    collection = db["threats"]
    logger.info("✅ Connected to MongoDB successfully.")
except KeyError:
    logger.error("❌ MONGODB_URI environment variable not set.")
    exit(1)
except errors.ServerSelectionTimeoutError as e:
    logger.exception("❌ MongoDB connection failed.")
    exit(1)

# Load AlienVault API key
try:
    OTX_API_KEY = os.environ["OTX_API_KEY"]
except KeyError:
    logger.error("❌ OTX_API_KEY environment variable not set.")
    exit(1)

ALIENVAULT_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
HEADERS = {"X-OTX-API-KEY": OTX_API_KEY}


@backoff.on_exception(backoff.expo, (requests.RequestException, errors.PyMongoError), max_tries=5)
def fetch_threats():
    logger.info("🚨 Fetching threats from AlienVault OTX...")
    try:
        res = requests.get(ALIENVAULT_URL, headers=HEADERS, timeout=10)
        res.raise_for_status()
        data = res.json()
        new_count = 0
        duplicate_count = 0

        for pulse in data.get("results", []):
            for indicator in pulse.get("indicators", []):
                doc = {
                    "indicator": indicator.get("indicator"),
                    "type": indicator.get("type"),
                    "severity": pulse.get("threat_hunting", {}).get("severity", "unknown"),
                    "timestamp": pulse.get("modified"),
                }

                # Try inserting; if it exists, skip
                result = collection.update_one(
                    {"indicator": doc["indicator"], "timestamp": doc["timestamp"]},
                    {"$setOnInsert": doc},
                    upsert=True
                )
                if result.upserted_id:
                    logger.info(f"✅ New threat added: {doc['indicator']}")
                    new_count += 1
                else:
                    duplicate_count += 1

        logger.info(f"✅ Stored {new_count} new threat indicators. 💤 Skipped {duplicate_count} duplicates.")

    except requests.RequestException as e:
        logger.error(f"❌ Error fetching from AlienVault: {e}")
        raise
    except Exception as e:
        logger.exception("❌ Unexpected error during fetch_threats.")


# CLI or scheduled mode
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fetch-now", action="store_true", help="Trigger immediate fetch and exit")
    args = parser.parse_args()

    if args.fetch_now:
        fetch_threats()
    else:
        schedule.every(1).minutes.do(fetch_threats)
        logger.info("🚀 Threat fetcher service running...")
        while True:
            schedule.run_pending()
            time.sleep(1)
