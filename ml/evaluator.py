"""
Phase 6 — Offline evaluation metrics.

Evaluates both the deterministic risk-v1 baseline AND the independent ML
model on the same frozen test set.

No single metric captures SOC prioritization quality; a full suite is reported.

Metrics computed (where test-set size permits)
----------------------------------------------
Classification:
  - Per-class Precision, Recall, F1
  - Macro-averaged PR-AUC
  - ROC-AUC (macro one-vs-rest)

Ranking:
  - Precision@K, Recall@K for K in {10, 25, 50, 100}
  - Top-K capture (fraction of CRITICAL+HIGH incidents in top-K)
  - Workload reduction (incidents to inspect for 90% CRITICAL recall)

Other:
  - Confusion matrix
  - FPR / FNR per class

K values are limited to those supported by the actual test-set size.
No results are fabricated.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

import numpy as np

from .constants import PRIORITY_CLASS_ORDER
from .scorer import calculate_ml_score, map_ml_priority_band


@dataclass
class PerClassMetrics:
    class_name: str
    precision: float
    recall: float
    f1: float
    fpr: float
    fnr: float
    support: int


@dataclass
class RankingMetrics:
    k: int
    precision_at_k: float
    recall_at_k: float
    top_k_capture: float  # fraction of HIGH+CRITICAL in top-k


@dataclass
class EvaluationResult:
    """Complete evaluation output for one model/ranker."""

    name: str  # e.g. "risk-v1" or "ml-v0.1.0"
    test_set_size: int = 0
    per_class: list[PerClassMetrics] = field(default_factory=list)
    macro_pr_auc: float = 0.0
    macro_roc_auc: float = 0.0
    ranking_metrics: list[RankingMetrics] = field(default_factory=list)
    confusion_matrix: list[list[int]] = field(default_factory=list)
    workload_reduction: dict[str, Any] = field(default_factory=dict)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _class_to_idx() -> dict[str, int]:
    return {cls: i for i, cls in enumerate(PRIORITY_CLASS_ORDER)}


def evaluate_classifier(
    name: str,
    y_true_bands: list[str],
    y_pred_bands: list[str],
    y_score_matrix: list[dict[str, float]],  # per-incident class probabilities
    scores: list[float],                       # scalar ranking scores (higher = more urgent)
) -> EvaluationResult:
    """
    Compute the full evaluation suite for one model.

    Parameters
    ----------
    name:
        Human-readable name for the model/ranker.
    y_true_bands:
        Ground-truth priority band strings for each test incident.
    y_pred_bands:
        Predicted priority band strings.
    y_score_matrix:
        Calibrated class probability dicts for each incident.
    scores:
        Scalar ranking scores (e.g. ml_score or risk-v1 overall_score).

    Returns
    -------
    EvaluationResult
    """
    try:
        from sklearn.metrics import (
            average_precision_score,
            confusion_matrix as sk_cm,
            f1_score,
            precision_score,
            recall_score,
            roc_auc_score,
        )
    except ImportError:
        raise RuntimeError("scikit-learn is required for evaluation.")

    c2i = _class_to_idx()
    n = len(y_true_bands)

    result = EvaluationResult(name=name, test_set_size=n)

    if n == 0:
        result.notes = "Empty test set — no metrics computed."
        return result

    # ── Integer labels ────────────────────────────────────────────────────────
    y_true_idx = np.array([c2i.get(b, 0) for b in y_true_bands], dtype=np.int64)
    y_pred_idx = np.array([c2i.get(b, 0) for b in y_pred_bands], dtype=np.int64)

    # ── Probability matrix ────────────────────────────────────────────────────
    y_proba = np.array(
        [[d.get(cls, 0.0) for cls in PRIORITY_CLASS_ORDER] for d in y_score_matrix],
        dtype=np.float64,
    )

    # ── Per-class metrics ─────────────────────────────────────────────────────
    classes_present = sorted(set(y_true_idx))
    per_class_p = precision_score(y_true_idx, y_pred_idx, average=None, zero_division=0, labels=list(range(len(PRIORITY_CLASS_ORDER))))
    per_class_r = recall_score(y_true_idx, y_pred_idx, average=None, zero_division=0, labels=list(range(len(PRIORITY_CLASS_ORDER))))
    per_class_f = f1_score(y_true_idx, y_pred_idx, average=None, zero_division=0, labels=list(range(len(PRIORITY_CLASS_ORDER))))

    for i, cls in enumerate(PRIORITY_CLASS_ORDER):
        support = int((y_true_idx == i).sum())
        # FPR and FNR for binary one-vs-rest.
        fp = int(((y_pred_idx == i) & (y_true_idx != i)).sum())
        fn = int(((y_pred_idx != i) & (y_true_idx == i)).sum())
        tn = int(((y_pred_idx != i) & (y_true_idx != i)).sum())
        tp = int(((y_pred_idx == i) & (y_true_idx == i)).sum())
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
        result.per_class.append(
            PerClassMetrics(
                class_name=cls,
                precision=float(per_class_p[i]),
                recall=float(per_class_r[i]),
                f1=float(per_class_f[i]),
                fpr=fpr,
                fnr=fnr,
                support=support,
            )
        )

    # ── Macro PR-AUC ─────────────────────────────────────────────────────────
    try:
        # One-hot encode y_true.
        y_true_onehot = np.zeros((n, len(PRIORITY_CLASS_ORDER)))
        for row_i, label_i in enumerate(y_true_idx):
            y_true_onehot[row_i, label_i] = 1
        result.macro_pr_auc = float(
            average_precision_score(y_true_onehot, y_proba, average="macro")
        )
    except Exception:
        result.macro_pr_auc = float("nan")

    # ── ROC-AUC ───────────────────────────────────────────────────────────────
    try:
        unique_classes = np.unique(y_true_idx)
        if len(unique_classes) >= 2:
            result.macro_roc_auc = float(
                roc_auc_score(
                    y_true_onehot,
                    y_proba,
                    average="macro",
                    multi_class="ovr",
                )
            )
    except Exception:
        result.macro_roc_auc = float("nan")

    # ── Confusion matrix ─────────────────────────────────────────────────────
    cm = sk_cm(y_true_idx, y_pred_idx, labels=list(range(len(PRIORITY_CLASS_ORDER))))
    result.confusion_matrix = cm.tolist()

    # ── Ranking metrics ───────────────────────────────────────────────────────
    scores_arr = np.array(scores, dtype=np.float64)
    sorted_indices = np.argsort(-scores_arr)  # descending
    y_true_sorted = np.array(y_true_bands)[sorted_indices]

    high_critical = {"HIGH", "CRITICAL"}

    for k in [10, 25, 50, 100]:
        if k > n:
            continue  # skip K values unsupported by test-set size
        topk_true = y_true_sorted[:k]
        topk_all_true = y_true_sorted

        # Precision@K: fraction of top-K that are HIGH/CRITICAL.
        precision_at_k = float(
            sum(1 for b in topk_true if b in high_critical) / k
        )

        # Recall@K: fraction of ALL HIGH/CRITICAL captured in top-K.
        total_hc = sum(1 for b in y_true_bands if b in high_critical)
        recall_at_k = (
            float(sum(1 for b in topk_true if b in high_critical) / total_hc)
            if total_hc > 0
            else 0.0
        )

        # Top-K capture: same as precision@K for HIGH+CRITICAL.
        top_k_capture = precision_at_k

        result.ranking_metrics.append(
            RankingMetrics(
                k=k,
                precision_at_k=precision_at_k,
                recall_at_k=recall_at_k,
                top_k_capture=top_k_capture,
            )
        )

    # ── Workload reduction ────────────────────────────────────────────────────
    total_hc = sum(1 for b in y_true_bands if b in high_critical)
    if total_hc > 0:
        target_recall = 0.90
        target_count = int(np.ceil(total_hc * target_recall))
        found = 0
        for rank_i, inc_idx in enumerate(sorted_indices, start=1):
            if y_true_bands[inc_idx] in high_critical:
                found += 1
            if found >= target_count:
                result.workload_reduction = {
                    "target_recall": target_recall,
                    "total_high_critical": total_hc,
                    "incidents_to_review_for_90pct_recall": rank_i,
                    "fraction_of_total_reviewed": round(rank_i / n, 4),
                }
                break
    else:
        result.workload_reduction = {
            "note": "No HIGH/CRITICAL incidents in test set."
        }

    return result


def compare_models(
    riskv1_result: EvaluationResult,
    ml_result: EvaluationResult,
) -> str:
    """
    Produce a human-readable comparison summary of two evaluation results.

    Does NOT claim superiority — reports measurements only.
    """
    lines = [
        "=" * 70,
        "PHASE 6 — EVALUATION COMPARISON SUMMARY",
        "=" * 70,
        f"Test-set size: {riskv1_result.test_set_size}",
        "",
        f"{'Metric':<30} {'risk-v1':>12} {'ML':>12}",
        "-" * 54,
        f"{'macro_pr_auc':<30} {riskv1_result.macro_pr_auc:>12.4f} {ml_result.macro_pr_auc:>12.4f}",
        f"{'macro_roc_auc':<30} {riskv1_result.macro_roc_auc:>12.4f} {ml_result.macro_roc_auc:>12.4f}",
        "",
        "Per-class metrics:",
    ]

    for r_cls, m_cls in zip(riskv1_result.per_class, ml_result.per_class):
        lines.append(
            f"  {r_cls.class_name:<16} "
            f"P={r_cls.precision:.3f}/R={r_cls.recall:.3f}/F1={r_cls.f1:.3f}  "
            f"vs  "
            f"P={m_cls.precision:.3f}/R={m_cls.recall:.3f}/F1={m_cls.f1:.3f}"
        )

    lines.append("")
    lines.append("Ranking (Precision@K / Recall@K / Top-K-Capture):")
    for r_rm in riskv1_result.ranking_metrics:
        m_rm = next(
            (m for m in ml_result.ranking_metrics if m.k == r_rm.k), None
        )
        if m_rm:
            lines.append(
                f"  K={r_rm.k:<4} risk-v1 P={r_rm.precision_at_k:.3f} R={r_rm.recall_at_k:.3f} "
                f"Cap={r_rm.top_k_capture:.3f}  |  "
                f"ML P={m_rm.precision_at_k:.3f} R={m_rm.recall_at_k:.3f} "
                f"Cap={m_rm.top_k_capture:.3f}"
            )

    lines += ["", "NOTE: These are empirical measurements on the frozen test set.",
              "      No superiority claim is made without statistical context.", "=" * 70]
    return "\n".join(lines)
