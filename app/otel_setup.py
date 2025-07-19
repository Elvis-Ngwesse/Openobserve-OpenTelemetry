import os
import sys
import logging
import psutil
from dotenv import load_dotenv
from opentelemetry import trace, metrics
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry._logs import set_logger_provider
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.trace import get_current_span

load_dotenv()

STREAM_NAME = os.getenv("OTEL_STREAM_NAME")
SERVICE_NAME_UI = os.getenv("SERVICE_NAME_UI")


class OTELLogFormatter(logging.Formatter):
    def format(self, record):
        span = get_current_span()
        span_context = span.get_span_context() if span else None
        record.trace_id = format(span_context.trace_id,
                                 "032x") if span_context and span_context.trace_id else "no-trace"
        record.span_id = format(span_context.span_id, "016x") if span_context and span_context.span_id else "no-span"
        record.service_name = SERVICE_NAME_UI
        record.stream_name = STREAM_NAME
        self._style._fmt, original = (
            f"%(asctime)s 🌐 %(levelname)s | %(name)s | [service={record.service_name} stream={record.stream_name} "
            f"trace_id={record.trace_id} span_id={record.span_id}] | %(message)s", self._style._fmt,
        )
        result = super().format(record)
        self._style._fmt = original
        return result


def init_logger():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    formatter = OTELLogFormatter()
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    try:
        log_exporter = OTLPLogExporter(
            endpoint=os.getenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"),
            headers={"Authorization": os.getenv("OTEL_EXPORTER_OTLP_AUTH"), "stream-name": STREAM_NAME},
        )
        provider = LoggerProvider(resource=Resource.create({SERVICE_NAME: SERVICE_NAME_UI, "stream.name": STREAM_NAME}))
        provider.add_log_record_processor(BatchLogRecordProcessor(log_exporter))
        set_logger_provider(provider)
        handler = LoggingHandler(level=logging.INFO, logger_provider=provider)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.info("📝 OpenTelemetry Log Exporter initialized successfully.")
    except Exception as e:
        logger.error(f"⚠️ Failed to initialize log exporter: {e}")
    return logger


def init_tracer(logger):
    try:
        provider = TracerProvider(resource=Resource.create({SERVICE_NAME: SERVICE_NAME_UI, "stream.name": STREAM_NAME}))
        exporter = OTLPSpanExporter(
            endpoint=os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
            headers={"Authorization": os.getenv("OTEL_EXPORTER_OTLP_AUTH")},
        )
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        logger.info("🛰️ Tracing initialized successfully")
        return trace.get_tracer(__name__)
    except Exception as e:
        logger.warning(f"⚠️ Tracing not initialized: {e}")
        return None


def init_metrics(logger):
    try:
        exporter = OTLPMetricExporter(
            endpoint=os.getenv("OTEL_EXPORTER_OTLP_METRIC_ENDPOINT"),
            headers={"Authorization": os.getenv("OTEL_EXPORTER_OTLP_AUTH")},
        )
        reader = PeriodicExportingMetricReader(exporter, export_interval_millis=5000)
        meter_provider = MeterProvider(metric_readers=[reader])
        metrics.set_meter_provider(meter_provider)
        meter = metrics.get_meter(SERVICE_NAME_UI)
        cpu = meter.create_counter("cpu_usage_percent", description="CPU usage %")
        mem = meter.create_counter("memory_usage_mb", description="Memory usage MB")
        reqs = meter.create_counter("http_requests_total", description="Total HTTP requests")
        logger.info("📈 Metrics initialized successfully")
        return meter, cpu, mem, reqs
    except Exception as e:
        logger.warning(f"⚠️ Metrics not initialized: {e}")
        return None, None, None, None


def record_metrics(meter, cpu_counter, mem_counter):
    if not meter: return
    cpu = psutil.cpu_percent()
    mem = psutil.Process().memory_info().rss / 1024 / 1024
    if cpu_counter: cpu_counter.add(cpu, {"service.name": SERVICE_NAME_UI, "stream.name": STREAM_NAME})
    if mem_counter: mem_counter.add(mem, {"service.name": SERVICE_NAME_UI, "stream.name": STREAM_NAME})
