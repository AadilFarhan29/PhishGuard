import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC


DATA_PATH = "data/phiusiil.csv"
MODEL_PATH = "model/phishguard_model.pkl"
FEATURE_COLUMNS_PATH = "model/feature_columns.pkl"


def main():

    df = pd.read_csv(DATA_PATH)

    print("Dataset shape:", df.shape)
    print("\nLabel distribution:")
    print(df["label"].value_counts())

    # Remove non-numeric / text columns
    drop_columns = ["FILENAME", "URL", "Domain", "TLD", "Title"]

    X = df.drop(columns=drop_columns + ["label"], errors="ignore")
    y = df["label"]

    # Replace missing values
    X = X.fillna(0)

    print("\nNumber of training features:", X.shape[1])

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    models = {
        "Logistic Regression": LogisticRegression(max_iter=1000),
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42),
        "SVM": SVC(kernel="rbf", probability=True)
    }

    results = []

    best_model = None
    best_model_name = None
    best_f1 = -1


    for name, model in models.items():

        print("\n==============================")
        print("Training:", name)

        model.fit(X_train, y_train)

        y_pred = model.predict(X_test)

        acc = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred, average="weighted")

        print("\nAccuracy:", acc)
        print("\nF1 Score:", f1)

        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))

        print("\nConfusion Matrix:")
        print(confusion_matrix(y_test, y_pred))

        results.append({
            "model": name,
            "accuracy": acc,
            "f1": f1
        })

        if f1 > best_f1:
            best_f1 = f1
            best_model = model
            best_model_name = name


    results_df = pd.DataFrame(results).sort_values(by="f1", ascending=False)

    print("\n==============================")
    print("Model Comparison")
    print(results_df)


    os.makedirs("model", exist_ok=True)

    joblib.dump(best_model, MODEL_PATH)
    joblib.dump(X.columns.tolist(), FEATURE_COLUMNS_PATH)

    print("\nBest model:", best_model_name)
    print("Model saved to:", MODEL_PATH)
    print("Feature list saved to:", FEATURE_COLUMNS_PATH)


if __name__ == "__main__":
    main()
