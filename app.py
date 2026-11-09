from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import joblib
import pandas as pd
from extract_87_features import get_features
from urllib.parse import urlparse

app = FastAPI()

# Load the trained model
model = joblib.load("phishing_model.pkl")
target_col = 'status'

# Whitelist of safe domains (Universities, Gov, Tech)
SAFE_DOMAINS = [
    'nsbm.ac.lk', 'google.com', 'github.com', 'microsoft.com', 
    'apple.com', 'amazon.com', 'wikipedia.org', 'stackoverflow.com',
    'gov.lk', 'edu'
]

class URLRequest(BaseModel):
    url: str

@app.post("/scan")
def scan_url(request: URLRequest):
    try:
        url = request.url
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        parsed = urlparse(url)
        hostname = parsed.hostname or ''
        
        # 1. Rule-Based Whitelist Check
        # If the hostname ends with any of our safe domains, mark it safe
        if any(hostname.endswith(safe) for safe in SAFE_DOMAINS):
            return {
                "url": url,
                "status": "legitimate (Whitelisted Domain)",
                "is_phishing": False
            }

        # 2. Machine Learning Check
        features_dict = get_features(url)
        df = pd.DataFrame([features_dict])
        
        prediction = model.predict(df)[0]
        
        return {
            "url": url,
            "status": prediction,
            "is_phishing": (str(prediction).lower() == 'phishing')
        }
    except Exception as e:
        return {"error": str(e)}

# (The rest of the HTML UI remains exactly the same)
@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Phishing URL Detector</title>
        <style>
            body { font-family: Arial, sans-serif; background: #1e1e2f; color: white; text-align: center; padding-top: 50px; }
            .container { background: #2a2a40; padding: 40px; border-radius: 10px; width: 500px; margin: auto; box-shadow: 0 4px 15px rgba(0,0,0,0.5); }
            input { width: 80%; padding: 10px; border-radius: 5px; border: none; margin-bottom: 20px; font-size: 16px; }
            button { padding: 10px 20px; background: #4CAF50; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer; }
            button:hover { background: #45a049; }
            .result { margin-top: 20px; font-size: 20px; font-weight: bold; }
            .phishing { color: #ff4c4c; }
            .safe { color: #4CAF50; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>🔎 Phishing Detector</h2>
            <p>Paste a URL below to scan it.</p>
            <input type="text" id="urlInput" placeholder="https://example.com" />
            <br>
            <button onclick="scan()">Scan URL</button>
            <div class="result" id="result"></div>
        </div>

        <script>
            async function scan() {
                const url = document.getElementById('urlInput').value;
                const resDiv = document.getElementById('result');
                if (!url) return;

                resDiv.innerHTML = "Scanning...";
                resDiv.className = "result";

                try {
                    const response = await fetch('/scan', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ url: url })
                    });
                    const data = await response.json();

                    if (data.error) {
                        resDiv.innerHTML = "Error: " + data.error;
                    } else if (data.is_phishing) {
                        resDiv.innerHTML = "🚨 PHISHING DETECTED 🚨";
                        resDiv.className = "result phishing";
                    } else {
                        resDiv.innerHTML = "✅ SAFE URL ✅";
                        resDiv.className = "result safe";
                    }
                } catch (e) {
                    resDiv.innerHTML = "Failed to connect to server.";
                }
            }
        </script>
    </body>
    </html>
    """