import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.ensemble import RandomForestClassifier

from utils.features import extract_url_features


DATA_PATH = "data/phiusiil.csv"
MODEL_PATH = "model/phishguard_live_model.pkl"
FEATURE_COLUMNS_PATH = "model/live_feature_columns.pkl"


def main():
    df = pd.read_csv(DATA_PATH)

    print("Dataset shape:", df.shape)

    if "URL" not in df.columns or "label" not in df.columns:
        print("Dataset must contain 'URL' and 'label' columns.")
        return

    print("\nExtracting live features from raw URLs...")
    feature_rows = df["URL"].apply(extract_url_features)

    X = pd.DataFrame(feature_rows.tolist())
    y = df["label"]

    X = X.fillna(0)

    print("\nLive feature columns:")
    print(X.columns.tolist())

    print("\nLabel distribution:")
    print(y.value_counts())

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42
    )

    print("\nTraining live deployment model...")
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average="weighted")

    print("\nLive Model Accuracy:", acc)
    print("Live Model F1 Score:", f1)

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    os.makedirs("model", exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    joblib.dump(X.columns.tolist(), FEATURE_COLUMNS_PATH)

    print(f"\nLive model saved to: {MODEL_PATH}")
    print(f"Live feature list saved to: {FEATURE_COLUMNS_PATH}")


if __name__ == "__main__":
    main()