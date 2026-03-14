import os
import json
import joblib
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_curve,
    auc,
    ConfusionMatrixDisplay
)
from sklearn.model_selection import train_test_split

from utils.features import extract_url_features


DATA_PATH = "data/phiusiil.csv"
MODEL_PATH = "model/phishguard_live_model.pkl"
OUTPUT_DIR = "evaluation"


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Load dataset
    df = pd.read_csv(DATA_PATH)

    if "URL" not in df.columns or "label" not in df.columns:
        print("Dataset must contain 'URL' and 'label' columns.")
        return

    print("Extracting features from dataset URLs...")
    feature_rows = df["URL"].apply(extract_url_features)
    X = pd.DataFrame(feature_rows.tolist()).fillna(0)
    y = df["label"]

    # Split same way as training
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    # Load trained model
    if not os.path.exists(MODEL_PATH):
        print(f"Model not found: {MODEL_PATH}")
        return

    model = joblib.load(MODEL_PATH)

    # Predictions
    y_pred = model.predict(X_test)

    # Metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, pos_label=0)
    recall = recall_score(y_test, y_pred, pos_label=0)
    f1 = f1_score(y_test, y_pred, pos_label=0)

    print("\n=== Evaluation Metrics ===")
    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1 Score : {f1:.4f}")

    print("\n=== Classification Report ===")
    print(classification_report(y_test, y_pred))

    # Save metrics
    metrics = {
        "accuracy": round(float(accuracy), 4),
        "precision_phishing": round(float(precision), 4),
        "recall_phishing": round(float(recall), 4),
        "f1_phishing": round(float(f1), 4),
    }

    with open(os.path.join(OUTPUT_DIR, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=4)

    with open(os.path.join(OUTPUT_DIR, "classification_report.txt"), "w") as f:
        f.write(classification_report(y_test, y_pred))

    # Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Phishing", "Legitimate"])
    disp.plot()
    plt.title("Confusion Matrix - PhishGuard Live Model")
    plt.savefig(os.path.join(OUTPUT_DIR, "confusion_matrix.png"), bbox_inches="tight")
    plt.close()

    # Class Distribution Chart
    label_counts = y.value_counts().sort_index()
    plt.figure(figsize=(6, 4))
    plt.bar(["Phishing (0)", "Legitimate (1)"], [label_counts[0], label_counts[1]])
    plt.title("Dataset Class Distribution")
    plt.ylabel("Number of URLs")
    plt.savefig(os.path.join(OUTPUT_DIR, "class_distribution.png"), bbox_inches="tight")
    plt.close()

    # ROC Curve
    if hasattr(model, "predict_proba"):
        y_scores = model.predict_proba(X_test)[:, 0]  # phishing probability
        fpr, tpr, _ = roc_curve(y_test, y_scores, pos_label=0)
        roc_auc = auc(fpr, tpr)

        plt.figure(figsize=(6, 5))
        plt.plot(fpr, tpr, label=f"AUC = {roc_auc:.4f}")
        plt.plot([0, 1], [0, 1], linestyle="--")
        plt.xlabel("False Positive Rate")
        plt.ylabel("True Positive Rate")
        plt.title("ROC Curve - PhishGuard Live Model")
        plt.legend(loc="lower right")
        plt.savefig(os.path.join(OUTPUT_DIR, "roc_curve.png"), bbox_inches="tight")
        plt.close()

        with open(os.path.join(OUTPUT_DIR, "roc_auc.txt"), "w") as f:
            f.write(f"ROC AUC: {roc_auc:.4f}\n")

    print(f"\nEvaluation files saved to: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()