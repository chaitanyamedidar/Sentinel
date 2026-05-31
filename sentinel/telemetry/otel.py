from __future__ import annotations

import os

from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
_provider: MeterProvider | None = None
_alert_counter = None
_query_histogram = None
_score_histogram = None

def init_telemetry() -> None:
    global _provider, _alert_counter, _query_histogram, _score_histogram
    if _provider is None:
        endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
        readers = []
        if endpoint:
            from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter

            readers.append(PeriodicExportingMetricReader(OTLPMetricExporter(endpoint=endpoint)))
        _provider = MeterProvider(metric_readers=readers); metrics.set_meter_provider(_provider)
    m = metrics.get_meter("sentinel")
    if _alert_counter is None:
        _alert_counter = m.create_counter("sentinel.alert.fired")
        _query_histogram = m.create_histogram("sentinel.query.duration")
        _score_histogram = m.create_histogram("sentinel.score")

def meter():
    init_telemetry(); return metrics.get_meter("sentinel")


def record_alert(vector_type: str, provider: str, repository: str = "") -> None:
    init_telemetry()
    if _alert_counter is not None:
        _alert_counter.add(1, {"vector_type": vector_type, "provider": provider or "n/a", "repository": repository})


def record_query_duration(seconds: float, macro: str) -> None:
    init_telemetry()
    if _query_histogram is not None:
        _query_histogram.record(seconds, {"macro": macro})


def record_score(score: int, vector_type: str) -> None:
    init_telemetry()
    if _score_histogram is not None:
        _score_histogram.record(score, {"vector_type": vector_type})
