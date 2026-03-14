import os
import joblib
import pandas as pd
import matplotlib.pyplot as plt


MODEL_PATH = "model/phishguard_live_model.pkl"
FEATURE_COLUMNS_PATH = "model/live_feature_columns.pkl"
OUTPUT_DIR = "evaluation"
OUTPUT_IMAGE = os.path.join(OUTPUT_DIR, "feature_importance.png")
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "feature_importance.csv")


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    if not os.path.exists(MODEL_PATH):
        print(f"Model file not found: {MODEL_PATH}")
        return

    if not os.path.exists(FEATURE_COLUMNS_PATH):
        print(f"Feature column file not found: {FEATURE_COLUMNS_PATH}")
        return

    model = joblib.load(MODEL_PATH)
    feature_columns = joblib.load(FEATURE_COLUMNS_PATH)

    if not hasattr(model, "feature_importances_"):
        print("This model does not support feature importance.")
        return

    importances = model.feature_importances_

    df = pd.DataFrame({
        "Feature": feature_columns,
        "Importance": importances
    }).sort_values(by="Importance", ascending=False)

    print("\n=== Feature Importance Ranking ===")
    print(df)

    df.to_csv(OUTPUT_CSV, index=False)

    # Plot top features
    plt.figure(figsize=(10, 7))
    plt.barh(df["Feature"], df["Importance"])
    plt.xlabel("Importance Score")
    plt.ylabel("Feature")
    plt.title("PhishGuard Live Model - Feature Importance")
    plt.gca().invert_yaxis()
    plt.tight_layout()
    plt.savefig(OUTPUT_IMAGE, dpi=300, bbox_inches="tight")
    plt.close()

    print(f"\nFeature importance chart saved to: {OUTPUT_IMAGE}")
    print(f"Feature importance table saved to: {OUTPUT_CSV}")


if __name__ == "__main__":
    main()