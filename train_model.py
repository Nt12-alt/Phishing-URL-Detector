import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib

def train_uci_dataset(csv_path="dataset_phishing.csv", out_path="phishing_model.pkl"):
    print("Loading dataset...")
    df = pd.read_csv(csv_path)
    
    # This dataset usually has a column at the end called 'phishing' or 'Result' 
    # If you scroll all the way to the right in Excel, you will see it. 
    # We will assume the last column is the label.
    target_col = df.columns[-1] 
    
    print(f"Using '{target_col}' as the target label.")
    
    # Drop the URL column since the model uses the pre-calculated features
    X = df.drop(columns=['url', target_col])
    y = df[target_col]
    
    # Some versions of this dataset use -1 for phishing and 1 for legitimate. 
    # Let's map it to 1 for phishing and 0 for legitimate.
    if y.min() == -1:
        y = y.replace(-1, 1)  # Phishing
        y = y.replace(1, 0)   # Legitimate
        
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    print("Training model (this may take a few seconds)...")
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight='balanced'
    )
    model.fit(X_train, y_train)

    preds = model.predict(X_test)
    print("\n✅ Accuracy:", accuracy_score(y_test, preds))
    print(classification_report(y_test, preds, zero_division=0))

    joblib.dump(model, out_path)
    print(f"✅ Model saved to {out_path}")

if __name__ == "__main__":
    train_uci_dataset()