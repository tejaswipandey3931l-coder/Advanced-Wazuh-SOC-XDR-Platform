"""
Phase 6 — Observability stubs for ML metrics.

Provides no-op stubs when prometheus_client is not installed.
Prometheus counter/histogram/gauge objects are used when available.

Counters / metrics exposed
--------------------------
  ml_inference_total        - Total inference attempts
  ml_inference_success      - Successful inferences
  ml_fallback_total         - Fallbacks to risk-v1
  ml_inference_latency_secs - Latency histogram
  ml_model_version_info     - Model version gauge/info
"""

from __future__ import annotations

try:
    from prometheus_client import Counter, Gauge, Histogram

    ml_inference_total = Counter(
        "ml_inference_total",
        "Total ML inference attempts.",
    )
    ml_inference_success = Counter(
        "ml_inference_success_total",
        "Successful ML inferences.",
    )
    ml_fallback_total = Counter(
        "ml_fallback_total",
        "ML inference fallbacks to risk-v1.",
    )
    ml_inference_latency_secs = Histogram(
        "ml_inference_latency_seconds",
        "ML inference latency.",
        buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0],
    )
    ml_model_version_info = Gauge(
        "ml_model_version_info",
        "ML model version in use.",
        labelnames=["model_version"],
    )
    _PROMETHEUS_AVAILABLE = True

except ImportError:
    # No-op stubs so all callers work without prometheus_client installed.
    class _NoOpCounter:  # type: ignore[no-redef]
        def inc(self, amount: float = 1) -> None: ...
        def labels(self, **_kw) -> "_NoOpCounter": return self

    class _NoOpHistogram:  # type: ignore[no-redef]
        def observe(self, _val: float) -> None: ...
        def time(self): return _NoOpContextManager()
        def labels(self, **_kw) -> "_NoOpHistogram": return self

    class _NoOpGauge:  # type: ignore[no-redef]
        def set(self, _val: float) -> None: ...
        def labels(self, **_kw) -> "_NoOpGauge": return self

    class _NoOpContextManager:
        def __enter__(self): return self
        def __exit__(self, *a): pass

    ml_inference_total = _NoOpCounter()  # type: ignore[assignment]
    ml_inference_success = _NoOpCounter()  # type: ignore[assignment]
    ml_fallback_total = _NoOpCounter()  # type: ignore[assignment]
    ml_inference_latency_secs = _NoOpHistogram()  # type: ignore[assignment]
    ml_model_version_info = _NoOpGauge()  # type: ignore[assignment]
    _PROMETHEUS_AVAILABLE = False
