import logging
import sys
import os
from flask import Flask, render_template, request
from pymongo import MongoClient
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from contextlib import nullcontext  # For fallback span context
from datetime import datetime

# Setup logging
logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s:%(name)s:%(message)s",
)
logger = logging.getLogger(__name__)

# Setup OpenTelemetry tracing
try:
    logger.debug("Initializing OpenTelemetry tracer provider")
    resource = Resource(attributes={SERVICE_NAME: "ui-app"})
    tracer_provider = TracerProvider(resource=resource)

    exporter = OTLPSpanExporter(
        endpoint=os.environ.get(
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "http://openobserve:5080/api/default/v1/traces",
        ),
        headers={"Authorization": os.environ.get("OTEL_EXPORTER_OTLP_AUTH", "")},
    )

    span_processor = BatchSpanProcessor(exporter)
    tracer_provider.add_span_processor(span_processor)
    trace.set_tracer_provider(tracer_provider)
    tracer = trace.get_tracer(__name__)
    logger.info("Tracing initialized successfully")

except Exception:
    logger.exception("Failed to initialize OpenTelemetry tracing")
    tracer = None  # Defensive fallback

# Flask app setup
app = Flask(__name__)
FlaskInstrumentor().instrument_app(app)

# MongoDB config
MONGO_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("MONGODB_DB", "threatintel")
MONGO_COLLECTION = os.getenv("MONGODB_COLLECTION", "threats")


def get_mongo_client(uri):
    try:
        client = MongoClient(uri)
        logger.info("✅ Connected to MongoDB")
        return client
    except Exception as e:
        logger.error(f"❌ MongoDB connection failed: {e}")
        return None


mongo_client = get_mongo_client(MONGO_URI)
if not mongo_client:
    logger.error("Exiting because MongoDB client could not be created")
    sys.exit(1)

db = mongo_client[MONGO_DB]
collection = db[MONGO_COLLECTION]


@app.route("/")
def index():
    threat_type = request.args.get("type")
    severity = request.args.get("severity")

    query = {}
    if threat_type:
        query["type"] = threat_type
    if severity:
        query["severity"] = severity

    span_ctx = tracer.start_as_current_span("fetch-threats-ui") if tracer else nullcontext()

    with span_ctx as span:
        logger.debug(f"Fetching threats with query: {query}")
        try:
            raw_threats = collection.find(query).sort("timestamp", -1).limit(20)
            threats = []
            for doc in raw_threats:
                ts = doc.get("timestamp")
                # Try parsing timestamp to datetime object
                try:
                    if ts:
                        # Mongo stores ISO 8601 strings like "2025-07-17T10:39:46.042Z"
                        # Python datetime expects "+00:00" instead of "Z" for UTC offset
                        parsed_ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    else:
                        parsed_ts = None
                except Exception:
                    parsed_ts = None

                threats.append(
                    {
                        "timestamp": parsed_ts,
                        "indicator": doc.get("indicator", "N/A"),
                        "type": doc.get("type", "N/A"),
                        "severity": doc.get("severity", "N/A"),
                    }
                )
            logger.info(f"Fetched {len(threats)} threats")
        except Exception as e:
            logger.exception("Error fetching threats from MongoDB")
            if span:
                span.record_exception(e)
            threats = []

        return render_template("index.html", threats=threats)


if __name__ == "__main__":
    logger.info("Starting Flask UI app on port 5020")
    try:
        app.run(debug=True, port=5020, host="0.0.0.0", use_reloader=False)
    except Exception:
        logger.exception("Failed to start Flask app")
