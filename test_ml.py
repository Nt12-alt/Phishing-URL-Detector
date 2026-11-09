
import pandas as pd
import joblib

# Load the model and the dataset
model = joblib.load("phishing_model.pkl")
df = pd.read_csv("dataset_phishing.csv")

# Grab 5 random URLs from the dataset to test
sample = df.sample(5)

for index, row in sample.iterrows():
    url = row['url']
    
    # We drop the URL column and the target column to get the 87 features
    features = row.drop(labels=['url', df.columns[-1]]).to_frame().T
    
    # Predict
    prediction = model.predict(features)[0]
    status = "PHISHING 🚨" if prediction == 1 else "SAFE ✅"
    
    print(f"{status} | {url}")