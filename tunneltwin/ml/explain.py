"""TreeSHAP explanations.

Every prediction the system surfaces carries a confidence score and the
top three contributing features, so a finding can never be "the model
said so". If SHAP is unavailable we degrade to the model's own
feature_importances_ and say so explicitly in the returned object --
we never present a global importance as if it were a local explanation.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Explanation:
    predicted: str
    confidence: float
    top_features: list[tuple[str, float]]
    method: str  # "tree_shap" | "global_importance_fallback"


def _predict_proba(model, row):
    import numpy as np

    x = np.asarray([row], dtype=np.float64)
    proba = model.predict_proba(x)
    return proba[0]


def explain_prediction(
    model,
    feature_names: list[str],
    row: list[float],
    *,
    top_k: int = 3,
) -> Explanation:
    import numpy as np

    proba = _predict_proba(model, row)
    classes = list(getattr(model, "classes_", []))
    best = int(np.argmax(proba))
    predicted = str(classes[best]) if classes else str(best)
    confidence = float(proba[best])

    try:
        import shap  # type: ignore[import-not-found]

        explainer = shap.TreeExplainer(model)
        values = explainer.shap_values(np.asarray([row], dtype=np.float64))
        # Binary and multiclass return different shapes across SHAP versions.
        if isinstance(values, list):
            sv = np.asarray(values[best])[0]
        else:
            arr = np.asarray(values)
            sv = arr[0, :, best] if arr.ndim == 3 else arr[0]
        ranked = sorted(
            zip(feature_names, (float(v) for v in sv), strict=False),
            key=lambda kv: abs(kv[1]),
            reverse=True,
        )
        return Explanation(
            predicted=predicted,
            confidence=confidence,
            top_features=ranked[:top_k],
            method="tree_shap",
        )
    except ImportError:
        importances = getattr(model, "feature_importances_", None)
        if importances is None:
            return Explanation(predicted, confidence, [], "global_importance_fallback")
        ranked = sorted(
            zip(feature_names, (float(v) for v in importances), strict=False),
            key=lambda kv: abs(kv[1]),
            reverse=True,
        )
        return Explanation(
            predicted=predicted,
            confidence=confidence,
            top_features=ranked[:top_k],
            method="global_importance_fallback",
        )
