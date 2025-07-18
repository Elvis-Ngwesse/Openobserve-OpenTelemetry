import logging
import sys
import os
import psutil  # ✅ NEW: for CPU and memory usage

from flask import Flask, render_template, request
from pymongo import MongoClient
from opentelemetry import trace, metrics
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.propagate import inject
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader

from contextlib import nullcontext
from datetime import datetime

# 🎯 Logging setup
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s 🌐 %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("ui-app")

# 🚀 Tracing setup
try:
    resource = Resource(attributes={SERVICE_NAME: "ui-app"})
    tracer_provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(
        endpoint=os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"),
        headers={"Authorization": os.environ.get("OTEL_EXPORTER_OTLP_AUTH")},
    )
    span_processor = BatchSpanProcessor(exporter)
    tracer_provider.add_span_processor(span_processor)
    trace.set_tracer_provider(tracer_provider)
    tracer = trace.get_tracer(__name__)
    logger.info("🛰️ Tracing initialized successfully")
except Exception:
    tracer = None
    logger.warning("⚠️ Tracing not initialized")

# 📈 Metrics setup
try:
    metric_exporter = OTLPMetricExporter(
        endpoint=os.getenv("OTEL_EXPORTER_OTLP_METRIC_ENDPOINT", "http://openobserve:5080/api/default/v1/metrics"),
        headers={"Authorization": os.getenv("OTEL_EXPORTER_OTLP_AUTH", "")},
    )
    metric_reader = PeriodicExportingMetricReader(metric_exporter, export_interval_millis=5000)
    meter_provider = MeterProvider(metric_readers=[metric_reader])
    metrics.set_meter_provider(meter_provider)
    meter = metrics.get_meter("ui-app")

    cpu_usage_counter = meter.create_counter(
        name="cpu_usage_percent",
        description="Recorded CPU usage percent",
    )
    memory_usage_counter = meter.create_counter(
        name="memory_usage_mb",
        description="Recorded memory usage in megabytes",
    )
    http_requests_counter = meter.create_counter(
        name="http_requests_total",
        description="Total number of HTTP requests served",
    )

    logger.info("📈 Metrics initialized successfully")
except Exception:
    meter = None
    cpu_usage_counter = None
    memory_usage_counter = None
    http_requests_counter = None
    logger.warning("⚠️ Metrics not initialized")


# 🔄 Function to record system metrics
def record_metrics():
    if not meter:
        return
    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.Process().memory_info().rss / 1024 / 1024
    logger.debug(f"📊 CPU: {cpu}%, Memory: {mem:.2f}MB")
    if cpu_usage_counter:
        cpu_usage_counter.add(cpu)
    if memory_usage_counter:
        memory_usage_counter.add(mem)


# 🐍 Flask setup
app = Flask(__name__)
FlaskInstrumentor().instrument_app(app)

# 🗄️ MongoDB setup
MONGO_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("MONGODB_DB", "threatintel")
MONGO_COLLECTION = os.getenv("MONGODB_COLLECTION", "threats")


def get_mongo_client(uri):
    try:
        logger.info(f"📡 Connecting to MongoDB at {uri}")
        client = MongoClient(uri)
        logger.info("✅ Connected to MongoDB")
        return client
    except Exception as e:
        logger.error(f"❌ MongoDB connection failed: {e}")
        return None


mongo_client = get_mongo_client(MONGO_URI)
if not mongo_client:
    logger.critical("💥 Exiting — MongoDB client could not be created.")
    sys.exit(1)

db = mongo_client[MONGO_DB]
collection = db[MONGO_COLLECTION]


@app.route("/")
def index():
    record_metrics()  # ✅ NEW: Log metrics on each page load

    if http_requests_counter:
        http_requests_counter.add(1)
        logger.debug("➡️ Incremented HTTP request counter")

    threat_type = request.args.get("type")
    severity = request.args.get("severity")

    query = {}
    if threat_type:
        query["type"] = threat_type
    if severity:
        query["severity"] = severity

    span_name = "query_threats"
    if threat_type and severity:
        span_name += "_type_severity"
    elif threat_type:
        span_name += "_type"
    elif severity:
        span_name += "_severity"

    span_ctx = tracer.start_as_current_span(span_name) if tracer else nullcontext()

    with span_ctx as span:
        logger.info(f"🔍 Searching for threats with: {query}")
        if span:
            span.set_attribute("query.type", threat_type or "any")
            span.set_attribute("query.severity", severity or "any")
            span.set_attribute("collection", MONGO_COLLECTION)

        try:
            with tracer.start_as_current_span("mongo_query") if tracer else nullcontext():
                raw_threats = collection.find(query).sort("timestamp", -1).limit(20)

            threats = []
            for doc in raw_threats:
                ts = doc.get("timestamp")
                try:
                    parsed_ts = datetime.fromisoformat(ts.replace("Z", "+00:00")) if ts else None
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

            logger.info(f"🧠 Retrieved {len(threats)} threats from MongoDB")
            if span:
                span.set_attribute("result.count", len(threats))

        except Exception as e:
            logger.exception("❗ Error fetching threats from MongoDB")
            if span:
                span.record_exception(e)
            threats = []

        return render_template("index.html", threats=threats)


@app.route("/health")
def health():
    return {"status": "ok"}, 200


if __name__ == "__main__":
    logger.info("🚀 Starting Flask UI app on port 5020")
    try:
        app.run(debug=True, port=5020, host="0.0.0.0", use_reloader=False)
    except Exception:
        logger.exception("❌ Failed to start Flask app")
