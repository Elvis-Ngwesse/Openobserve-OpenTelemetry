from flask import Blueprint, render_template, request
from datetime import datetime
from contextlib import nullcontext

ui = Blueprint("ui", __name__)


def register_routes(app, logger, tracer, collection, cpu, mem, reqs, record_metrics, service_name, stream_name):
    @ui.route("/")
    def index():
        record_metrics()

        if reqs:
            reqs.add(1, {"service.name": service_name, "stream.name": stream_name})
            logger.debug("➡️ Incremented HTTP request counter")

        threat_type = request.args.get("type")
        severity = request.args.get("severity")
        query = {k: v for k, v in [("type", threat_type), ("severity", severity)] if v}

        span_ctx = tracer.start_as_current_span("query_threats") if tracer else nullcontext()
        with span_ctx as span:
            logger.info(f"🔍 Searching for threats: {query}")
            if span:
                for k, v in {"service.name": service_name, "stream.name": stream_name,
                             "query.type": threat_type or "any", "query.severity": severity or "any"}.items():
                    span.set_attribute(k, v)

            try:
                with (tracer.start_as_current_span("mongo_query") if tracer else nullcontext()) as mongo_span:
                    if mongo_span:
                        for k, v in {
                            "service.name": service_name,
                            "stream.name": stream_name,
                            "db.system": "mongodb",
                            "db.operation": "find",
                            "db.mongodb.collection": collection.name,
                        }.items():
                            mongo_span.set_attribute(k, v)

                    raw = collection.find(query).sort("timestamp", -1).limit(20)

                threats = []
                for doc in raw:
                    ts = doc.get("timestamp")
                    try:
                        parsed_ts = datetime.fromisoformat(ts.replace("Z", "+00:00")) if ts else None
                    except Exception:
                        parsed_ts = None

                    threats.append({
                        "timestamp": parsed_ts,
                        "indicator": doc.get("indicator", "N/A"),
                        "type": doc.get("type", "N/A"),
                        "severity": doc.get("severity", "N/A"),
                    })

                logger.info(f"🧠 Retrieved {len(threats)} threats")
                if span: span.set_attribute("result.count", len(threats))

            except Exception as e:
                logger.exception("❗ Error fetching threats")
                if span: span.record_exception(e)
                threats = []

            return render_template("index.html", threats=threats)

    @ui.route("/health")
    def health():
        return {"status": "ok"}, 200

    app.register_blueprint(ui)
