import os
import time
import schedule
import requests
import logging
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
    client.server_info()  # Trigger connection test
    db = client["threatintel"]
    collection = db["threats"]
    logger.info("✅ Connected to MongoDB successfully.")
except KeyError:
    logger.error("❌ MONGODB_URI environment variable not set.")
    exit(1)
except errors.ServerSelectionTimeoutError as e:
    logger.exception("❌ MongoDB connection failed.")
    exit(1)

# Load AlienVault API key from environment
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
        inserted = 0
        for pulse in data.get("results", []):
            for indicator in pulse.get("indicators", []):
                doc = {
                    "indicator": indicator.get("indicator"),
                    "type": indicator.get("type"),
                    "severity": pulse.get("threat_hunting", {}).get("severity", "unknown"),
                    "timestamp": pulse.get("modified"),
                }
                try:
                    result = collection.update_one(
                        {"indicator": doc["indicator"], "timestamp": doc["timestamp"]},
                        {"$setOnInsert": doc},
                        upsert=True
                    )
                    if result.upserted_id:
                        inserted += 1
                except errors.PyMongoError as e:
                    logger.error(f"❌ MongoDB upsert error: {e}")
        logger.info(f"✅ Stored {inserted} new threat indicators.")
    except requests.RequestException as e:
        logger.error(f"❌ Error fetching from AlienVault: {e}")
        raise
    except Exception as e:
        logger.exception("❌ Unexpected error during fetch_threats.")

# Schedule every minute
schedule.every(1).minutes.do(fetch_threats)

logger.info("🚀 Threat fetcher service running...")
while True:
    schedule.run_pending()
    time.sleep(1)
