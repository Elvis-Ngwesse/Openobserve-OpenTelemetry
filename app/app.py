from flask import Flask
from opentelemetry.instrumentation.flask import FlaskInstrumentor

from otel_setup import init_logger, init_tracer, init_metrics, record_metrics, STREAM_NAME, SERVICE_NAME_UI
from db import get_collection
from views import register_routes

logger = init_logger()
tracer = init_tracer(logger)
meter, cpu_counter, mem_counter, reqs_counter = init_metrics(logger)
collection = get_collection(logger)

app = Flask(__name__)
FlaskInstrumentor().instrument_app(app)

register_routes(
    app,
    logger,
    tracer,
    collection,
    cpu_counter,
    mem_counter,
    reqs_counter,
    lambda: record_metrics(meter, cpu_counter, mem_counter, logger),
    SERVICE_NAME_UI,
    STREAM_NAME
)

if __name__ == "__main__":
    logger.info("🚀 Starting Flask UI app on port 5020")
    try:
        app.run(debug=True, port=5020, host="0.0.0.0", use_reloader=False)
    except Exception:
        logger.exception("❌ Failed to start Flask app")
