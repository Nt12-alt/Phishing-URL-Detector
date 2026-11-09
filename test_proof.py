import pandas as pd
import joblib

# Load the model and dataset
model = joblib.load("phishing_model.pkl")
df = pd.read_csv("dataset_phishing.csv")

target_col = 'status'

# Grab one of each label
row_legit = df[df[target_col] == 'legitimate'].iloc[0]
row_phish = df[df[target_col] == 'phishing'].iloc[0]

def predict_row(row, actual_label):
    url = row['url']
    # Drop url and target column to get the 87 features
    features = row.drop(labels=['url', target_col]).to_frame().T
    
    # Get the prediction (the model outputs a class based on how it was trained)
    prediction = model.predict(features)[0]
    
    # Let's just print exactly what the model outputs so we can see it
    print(f"Actual Label in Data: {actual_label}")
    print(f"Raw Model Output    : {prediction}")
    print(f"URL                 : {url}\n")

print("--- TESTING LEGITIMATE URL ---")
predict_row(row_legit, 'legitimate')

print("--- TESTING PHISHING URL ---")
predict_row(row_phish, 'phishing')