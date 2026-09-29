"""End-to-end Phase 5 CORE runner.

Produces, from real captures:
  * lab/models/train_report.json   -- held-out accuracy (CORE targets)
  * lab/models/impairment.json     -- accuracy under netem conditions
  * lab/models/shap_sample.json    -- one TreeSHAP explanation

Must be run on the Linux/WSL2 lab host. On Windows it will build and
evaluate the feature table but will refuse to emit impairment numbers.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path

from tunneltwin.capture.esp_features import BASE_FEATURE_NAMES, CONV_FEATURE_NAMES
from tunneltwin.ml.dataset import build_dataset
from tunneltwin.ml.explain import explain_prediction
from tunneltwin.ml.train import train_all


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="TunnelTwin Phase 5 CORE runner")
    ap.add_argument("--captures", default="lab/captures", type=Path)
    ap.add_argument("--out", default="lab/models", type=Path)
    ap.add_argument("--test-frac", type=float, default=0.25)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--skip-impairment", action="store_true")
    args = ap.parse_args(argv)

    print(f"[phase5] platform={platform.system()} captures={args.captures}")
    rows = build_dataset(args.captures, spectral=False)  # CORE uses spectral=False
    if not rows:
        print(
            "[phase5] no ESP conversations found. Populate lab/captures/ using lab/generate_captures.sh first.",
            file=sys.stderr,
        )
        return 2

    # Separate baseline training flows from netem impairment flows
    train_rows = [r for r in rows if r.traffic_pattern in ("bulk", "chatty")]
    impairment_rows = [r for r in rows if r.traffic_pattern not in ("bulk", "chatty")]

    print(f"[phase5] {len(train_rows)} baseline training flows, {len(impairment_rows)} impairment flows")
    results = train_all(train_rows, test_frac=args.test_frac, seed=args.seed, out_dir=args.out)

    print("\n=== held-out accuracy (CORE targets) ===")
    print(f"{'target':<16}{'backend':<14}{'accuracy':>10}")
    for r in results:
        print(f"{r.target:<16}{r.backend:<14}{r.accuracy:>10.4f}")

    if not args.skip_impairment:
        if platform.system() != "Linux":
            print(
                "\n[phase5] REFUSING to emit impairment table: netem requires "
                "Linux. Re-run this script on the WSL2/lab host. No numbers "
                "will be invented here.",
                file=sys.stderr,
            )
        else:
            import joblib
            import numpy as np
            from sklearn.metrics import accuracy_score

            from tunneltwin.ml.robustness import NETEM_CONDITIONS

            profile_model = joblib.load(args.out / "profile.joblib")
            feature_names = BASE_FEATURE_NAMES + CONV_FEATURE_NAMES

            impairment_results = []
            clean_acc = 1.0

            clean_flows = [r for r in rows if r.traffic_pattern == "clean"]
            if clean_flows:
                x_clean = np.array([[r.features.get(n, 0.0) for n in feature_names] for r in clean_flows])
                y_clean = np.array([r.profile for r in clean_flows])
                clean_acc = float(accuracy_score(y_clean, profile_model.predict(x_clean)))

            for cond, _ in NETEM_CONDITIONS:
                cond_flows = [r for r in rows if r.traffic_pattern == cond]
                if cond_flows:
                    x_cond = np.array([[r.features.get(n, 0.0) for n in feature_names] for r in cond_flows])
                    y_cond = np.array([r.profile for r in cond_flows])
                    acc = float(accuracy_score(y_cond, profile_model.predict(x_cond)))
                    delta = acc - clean_acc
                    impairment_results.append(
                        {
                            "condition": cond,
                            "accuracy": acc,
                            "delta_vs_clean": delta,
                            "n_flows": len(cond_flows),
                        }
                    )

            impairment = {
                "note": "Evaluated on real PCAPs captured under Linux tc netem conditions",
                "conditions": [c for c, _ in NETEM_CONDITIONS],
                "results": impairment_results,
            }
            (args.out / "impairment.json").write_text(json.dumps(impairment, indent=2), encoding="utf-8")

            print("\n=== Robustness Check: Clean vs. Impaired Accuracy ===")
            print(f"{'condition':<16}{'accuracy':>10}{'delta_vs_clean':>16}")
            for res in impairment_results:
                print(f"{res['condition']:<16}{res['accuracy']:>10.4f}{res['delta_vs_clean']:>+16.4f}")

    sample = _shap_sample(train_rows, args.out)
    if sample:
        (args.out / "shap_sample.json").write_text(json.dumps(sample, indent=2), encoding="utf-8")
        print(
            f"\n[phase5] SHAP sample: {sample['predicted']} "
            f"(conf {sample['confidence']:.3f}, method {sample['method']})"
        )
        for name, val in sample["top_features"]:
            print(f"    {name:<24}{val:+.4f}")

    return 0


def _shap_sample(rows, out_dir: Path) -> dict | None:
    try:
        import joblib
    except ImportError:
        return None
    model_path = Path(out_dir) / "profile.joblib"
    if not model_path.is_file():
        return None
    model = joblib.load(model_path)
    feature_names = BASE_FEATURE_NAMES + CONV_FEATURE_NAMES
    row = [rows[0].features.get(n, 0.0) for n in feature_names]
    expl = explain_prediction(model, list(feature_names), row)
    return {
        "source": rows[0].source,
        "predicted": expl.predicted,
        "confidence": expl.confidence,
        "method": expl.method,
        "top_features": expl.top_features,
    }


if __name__ == "__main__":
    raise SystemExit(main())
