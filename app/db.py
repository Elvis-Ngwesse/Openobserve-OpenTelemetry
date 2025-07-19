import os
from pymongo import MongoClient
import logging
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGODB_URI")
MONGO_DB = os.getenv("MONGODB_DB")
MONGO_COLLECTION = os.getenv("MONGODB_COLLECTION")


def get_mongo_client(uri, logger: logging.Logger):
    try:
        logger.info(f"📡 Connecting to MongoDB at {uri}")
        client = MongoClient(uri)
        logger.info("✅ Connected to MongoDB")
        return client
    except Exception as e:
        logger.error(f"❌ MongoDB connection failed: {e}")
        return None


def get_collection(logger: logging.Logger):
    client = get_mongo_client(MONGO_URI, logger)
    if not client:
        logger.critical("💥 Exiting — MongoDB client could not be created.")
        exit(1)
    db = client[MONGO_DB]
    return db[MONGO_COLLECTION]
