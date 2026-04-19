import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.ensemble import RandomForestClassifier


DATA_PATH = "data/phiusiil.csv"
MODEL_PATH = "model/phishguard_deployment_model.pkl"
FEATURE_COLUMNS_PATH = "model/deployment_feature_columns.pkl"


def main():
    df = pd.read_csv(DATA_PATH)

    selected_features = [
        "URLLength",
        "DomainLength",
        "IsDomainIP",
        "TLDLength",
        "NoOfSubDomain",
        "HasObfuscation",
        "NoOfObfuscatedChar",
        "ObfuscationRatio",
        "NoOfLettersInURL",
        "LetterRatioInURL",
        "NoOfDegitsInURL",
        "DegitRatioInURL",
        "NoOfEqualsInURL",
        "NoOfQMarkInURL",
        "NoOfAmpersandInURL",
        "NoOfOtherSpecialCharsInURL",
        "SpacialCharRatioInURL",
        "IsHTTPS"
    ]

    X = df[selected_features].copy()
    y = df["label"]

    X = X.fillna(0)

    print("Selected deployment features:")
    print(selected_features)
    print("\nDataset shape:", X.shape)
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

    print("\nTraining deployment model...")
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average="weighted")

    print("\nDeployment Model Accuracy:", acc)
    print("Deployment Model F1 Score:", f1)

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    os.makedirs("model", exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    joblib.dump(selected_features, FEATURE_COLUMNS_PATH)

    print(f"\nDeployment model saved to: {MODEL_PATH}")
    print(f"Deployment feature list saved to: {FEATURE_COLUMNS_PATH}")


if __name__ == "__main__":
    main()