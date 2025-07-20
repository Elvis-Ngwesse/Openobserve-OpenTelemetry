# main.py
import os
import time
import schedule
import argparse
from otel_setup import init_logger, init_tracer, init_metrics, record_metrics, STREAM_NAME, SERVICE_NAME_FETCHER
from fetcher import connect_mongo, get_api_keys, fetch_otx_threats, insert_threats

logger = init_logger()
tracer = init_tracer(logger)
meter, otx_counter, insert_counter, cpu_counter, mem_counter, meter_provider = init_metrics(logger)
collection = connect_mongo(logger)
OTX_API_KEY, _ = get_api_keys(logger)

HEADERS_OTX = {"X-OTX-API-KEY": OTX_API_KEY}
ALIENVAULT_URL = os.getenv("ALIENVAULT_URL")


def fetch_and_insert():
    record_metrics(meter, cpu_counter, mem_counter, logger)
    indicators = fetch_otx_threats(logger, tracer, HEADERS_OTX, ALIENVAULT_URL, STREAM_NAME, SERVICE_NAME_FETCHER)
    insert_threats(collection, logger, tracer, indicators, (insert_counter, otx_counter), STREAM_NAME,
                   SERVICE_NAME_FETCHER)
    if meter_provider:
        meter_provider.force_flush()
        logger.info("📤 Metrics flushed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fetch-now", action="store_true")
    parser.add_argument("--loop-delay", type=int, default=60)
    args = parser.parse_args()

    if args.fetch_now:
        fetch_and_insert()
    else:
        schedule.every(args.loop_delay).seconds.do(fetch_and_insert)
        logger.info(f"🚀 Running every {args.loop_delay}s")
        while True:
            schedule.run_pending()
            time.sleep(1)
