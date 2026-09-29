"""Train the Phase 5 CORE classifiers: profile, traffic_pattern.

Two things the exit criteria are strict about:

1. The held-out split is grouped by *capture file*, not by row. Flows
   from the same capture share a daemon, a suite and an impairment
   condition, so a row-level split leaks and produces a meaningless
   accuracy number.

2. CORE uses the base feature set only (spectral=False). Spectral
   features are OPTIONAL and not wired into the CORE pipeline.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from tunneltwin.ml.dataset import LabelledFlow

# CORE targets: 4-way profile + binary traffic_pattern
TARGETS = ("profile", "traffic_pattern")


@dataclass
class TrainResult:
    target: str
    backend: str
    n_train: int
    n_test: int
    accuracy: float
    per_class: dict[str, float]
    feature_names: list[str]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "backend": self.backend,
            "n_train": self.n_train,
            "n_test": self.n_test,
            "accuracy": self.accuracy,
            "per_class": self.per_class,
            "feature_names": self.feature_names,
        }


def _make_model(seed: int):
    """LightGBM when available, Random Forest otherwise.

    Returns ``(estimator, backend_name)``. The fallback exists so the
    pipeline is runnable before the ML extra is installed, not as a
    substitute for installing it -- the final numbers must come from the
    same backend used in the demo video.
    """
    try:
        import lightgbm as lgb  # type: ignore[import-not-found]

        return (
            lgb.LGBMClassifier(
                n_estimators=300,
                learning_rate=0.05,
                num_leaves=31,
                min_child_samples=5,
                random_state=seed,
                verbose=-1,
            ),
            "lightgbm",
        )
    except ImportError:
        from sklearn.ensemble import RandomForestClassifier

        return (
            RandomForestClassifier(n_estimators=400, random_state=seed, min_samples_leaf=1),
            "random_forest",
        )


def _grouped_split(rows: list[LabelledFlow], test_frac: float, seed: int) -> tuple[list[int], list[int]]:
    groups = sorted({r.source.split("#")[0] for r in rows})
    try:
        import numpy as np

        rng = np.random.default_rng(seed)
        rng.shuffle(groups)
    except ImportError:
        import random

        random.Random(seed).shuffle(groups)  # nosec B311 # noqa: S311

    n_test = max(1, int(len(groups) * test_frac))
    test_groups = set(groups[:n_test])
    train_idx = [i for i, r in enumerate(rows) if r.source.split("#")[0] not in test_groups]
    test_idx = [i for i, r in enumerate(rows) if r.source.split("#")[0] in test_groups]
    return train_idx, test_idx


def _fit_eval(
    rows: list[LabelledFlow],
    target: str,
    feature_names: tuple[str, ...],
    train_idx: list[int],
    test_idx: list[int],
    seed: int,
) -> tuple[float, dict[str, float], str, object, list[str]]:
    import numpy as np
    from sklearn.metrics import accuracy_score, classification_report

    x = np.array(
        [[rows[i].features.get(n, 0.0) for n in feature_names] for i in range(len(rows))],
        dtype=np.float64,
    )
    y = np.array([getattr(rows[i], target) for i in range(len(rows))])

    model, backend = _make_model(seed)
    model.fit(x[train_idx], y[train_idx])
    pred = model.predict(x[test_idx])
    acc = float(accuracy_score(y[test_idx], pred))
    report = classification_report(y[test_idx], pred, output_dict=True, zero_division=0)
    per_class = {
        k: float(v["recall"])
        for k, v in report.items()
        if isinstance(v, dict) and k not in ("macro avg", "weighted avg")
    }
    return acc, per_class, backend, model, list(feature_names)


def train_all(
    rows: list[LabelledFlow],
    *,
    test_frac: float = 0.25,
    seed: int = 1337,
    out_dir: str | Path = "lab/models",
) -> list[TrainResult]:
    from tunneltwin.capture.esp_features import (
        BASE_FEATURE_NAMES,
        CONV_FEATURE_NAMES,
    )

    # CORE uses base + conv features only (no spectral)
    feature_names = BASE_FEATURE_NAMES + CONV_FEATURE_NAMES

    train_idx, test_idx = _grouped_split(rows, test_frac, seed)
    results: list[TrainResult] = []
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    for target in TARGETS:
        acc, per_class, backend, model, names = _fit_eval(rows, target, feature_names, train_idx, test_idx, seed)
        results.append(
            TrainResult(
                target=target,
                backend=backend,
                n_train=len(train_idx),
                n_test=len(test_idx),
                accuracy=acc,
                per_class=per_class,
                feature_names=names,
            )
        )
        try:
            import joblib

            joblib.dump(model, out_dir / f"{target}.joblib")
        except ImportError:
            pass

    (out_dir / "train_report.json").write_text(json.dumps([r.to_dict() for r in results], indent=2), encoding="utf-8")
    return results
