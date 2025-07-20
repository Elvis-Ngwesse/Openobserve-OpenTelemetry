# otel_setup.py
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
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry._logs import set_logger_provider
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.trace import get_current_span

load_dotenv()
SERVICE_NAME_FETCHER = os.getenv("SERVICE_NAME_FETCHER")
STREAM_NAME = os.getenv("OTEL_STREAM_NAME")


class OTELLogFormatter(logging.Formatter):
    def format(self, record):
        span = get_current_span()
        span_context = span.get_span_context() if span else None
        record.trace_id = format(span_context.trace_id,
                                 "032x") if span_context and span_context.trace_id else "no-trace"
        record.span_id = format(span_context.span_id, "016x") if span_context and span_context.span_id else "no-span"
        record.service_name = SERVICE_NAME_FETCHER
        record.stream_name = STREAM_NAME
        fmt_orig = self._style._fmt
        self._style._fmt = (
            f"%(asctime)s 🌐 %(levelname)s | %(message)s | "
            f"[service={record.service_name} stream={record.stream_name} trace_id={record.trace_id} span_id={record.span_id}]"
        )
        result = super().format(record)
        self._style._fmt = fmt_orig
        return result


def init_logger():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    formatter = OTELLogFormatter()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    try:
        exporter = OTLPLogExporter(
            endpoint=os.getenv("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"),
            headers={"Authorization": os.getenv("OTEL_EXPORTER_OTLP_AUTH"), "stream-name": STREAM_NAME},
        )
        provider = LoggerProvider(
            resource=Resource.create({SERVICE_NAME: SERVICE_NAME_FETCHER, "stream.name": STREAM_NAME}))
        provider.add_log_record_processor(BatchLogRecordProcessor(exporter))
        set_logger_provider(provider)
        otel_handler = LoggingHandler(level=logging.INFO, logger_provider=provider)
        otel_handler.setFormatter(formatter)
        logger.addHandler(otel_handler)
        logger.info("📝 Log exporter initialized.")
    except Exception as e:
        logger.error(f"⚠️ Failed to init log exporter: {e}")
    return logger


def init_tracer(logger):
    try:
        resource = Resource.create({SERVICE_NAME: SERVICE_NAME_FETCHER, "stream.name": STREAM_NAME})
        provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(
            endpoint=os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
            headers={"Authorization": os.getenv("OTEL_EXPORTER_OTLP_AUTH")},
        )
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        tracer = trace.get_tracer(SERVICE_NAME_FETCHER)
        logger.info("🛰️ Tracing initialized")
        return tracer
    except Exception:
        logger.warning("⚠️ Tracing not initialized")
        return None


def init_metrics(logger):
    try:
        exporter = OTLPMetricExporter(
            endpoint=os.getenv("OTEL_EXPORTER_OTLP_METRIC_ENDPOINT"),
            headers={"Authorization": os.getenv("OTEL_EXPORTER_OTLP_AUTH")},
        )
        reader = PeriodicExportingMetricReader(exporter, export_interval_millis=60000)
        provider = MeterProvider(metric_readers=[reader])
        metrics.set_meter_provider(provider)
        meter = metrics.get_meter(SERVICE_NAME_FETCHER)

        otx_counter = meter.create_counter("otx_indicators_total")
        insert_counter = meter.create_counter("threats_inserted")
        cpu_counter = meter.create_counter("cpu_usage_percent")
        mem_counter = meter.create_counter("memory_usage_mb")
        logger.info("📈 Metrics initialized")
        return meter, otx_counter, insert_counter, cpu_counter, mem_counter, provider
    except Exception:
        logger.warning("⚠️ Metrics not initialized")
        return None, None, None, None, None, None


def record_metrics(meter, cpu_counter, mem_counter, logger):
    if not meter:
        return
    cpu = psutil.cpu_percent()
    mem = psutil.Process().memory_info().rss / 1024 / 1024
    cpu_counter.add(cpu, {"service.name": SERVICE_NAME_FETCHER, "stream.name": STREAM_NAME})
    mem_counter.add(mem, {"service.name": SERVICE_NAME_FETCHER, "stream.name": STREAM_NAME})
    logger.info(f"📊 CPU usage: {cpu:.1f}%, Memory usage: {mem:.2f} MB")