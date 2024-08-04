from flask import Flask, request, jsonify, send_from_directory
import pandas as pd
import numpy as np
from urllib.parse import urlparse

app = Flask(__name__)

# Load the CSV model data
model_data = pd.read_csv('model.csv')

def extract_features(url):
    if not isinstance(url, str):
        raise ValueError("URL must be a string")

    parsed_url = urlparse(url)
    length = len(url)
    num_dots = url.count('.')
    has_https = 1 if parsed_url.scheme == 'https' else 0
    contains_suspicious_keywords = int(any(keyword in url for keyword in ['phishing', 'login', 'secure', 'bank', 'verify']))
    num_subdomains = len(parsed_url.netloc.split('.')) - 2

    # Debug print statements
    print(f"Extracted features: length={length}, num_dots={num_dots}, has_https={has_https}, contains_suspicious_keywords={contains_suspicious_keywords}, num_subdomains={num_subdomains}")

    return np.array([length, num_dots, has_https, contains_suspicious_keywords, num_subdomains])

def predict_from_csv(features):
    # Find the closest match in the CSV data
    distances = ((model_data[['length', 'num_dots', 'has_https', 'contains_suspicious_keywords', 'num_subdomains']] - features) ** 2).sum(axis=1)
    closest_match = model_data.loc[distances.idxmin()]
    return closest_match['is_phishing']

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    url = data.get('url', '')

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    try:
        features = extract_features(url)
        print(f"Features for prediction: {features}")
        is_phishing = predict_from_csv(features)
        result = 'phishing' if is_phishing == 1 else 'safe'
        return jsonify({'url': url, 'is_phishing': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
