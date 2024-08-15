from flask import Flask, request, jsonify, send_from_directory
import pandas as pd
import numpy as np
from urllib.parse import urlparse
import requests
import re
import socket
import time

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

    print(f"Extracted features: length={length}, num_dots={num_dots}, has_https={has_https}, contains_suspicious_keywords={contains_suspicious_keywords}, num_subdomains={num_subdomains}")

    return np.array([length, num_dots, has_https, contains_suspicious_keywords, num_subdomains])

def predict_from_csv(features):
    distances = ((model_data[['length', 'num_dots', 'has_https', 'contains_suspicious_keywords', 'num_subdomains']] - features) ** 2).sum(axis=1)
    closest_match = model_data.loc[distances.idxmin()]
    return closest_match['is_phishing']

def detect_sql_injection(url):
    test_payloads = ["' OR '1'='1", "' OR '1'='1' --", "1' OR 1=1 --", "admin' --"]
    for payload in test_payloads:
        test_url = f"{url}?search={payload}"
        try:
            response = requests.get(test_url, timeout=5)
            if "SQL syntax" in response.text or "error" in response.text.lower():
                return True
        except Exception as e:
            print(f"Error testing SQL injection: {e}")
    return False

def detect_malware(url):
    # This is a simple placeholder. For real detection, integrate with a malware scanning API.
    try:
        response = requests.get(url, timeout=5)
        malware_patterns = ['virus', 'malware', 'suspicious']
        if any(pattern in response.text.lower() for pattern in malware_patterns):
            return True
    except Exception as e:
        print(f"Error testing for malware: {e}")
    return False

def detect_port_scanning(url):
    # Check for open ports (requires more sophisticated implementation for real detection)
    ip = socket.gethostbyname(urlparse(url).hostname)
    open_ports = []
    for port in range(1, 1024):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return len(open_ports) > 10

def detect_bruteforce(url):
    # This is a simple placeholder. Real detection requires more advanced techniques.
    try:
        response = requests.get(url, timeout=5)
        if "too many requests" in response.text.lower():
            return True
    except Exception as e:
        print(f"Error testing for brute force: {e}")
    return False

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
        is_phishing = predict_from_csv(features)
        result = 'phishing' if is_phishing == 1 else 'safe'

        sql_injection = detect_sql_injection(url)
        malware_infection = detect_malware(url)
        port_scanning = detect_port_scanning(url)
        brute_force = detect_bruteforce(url)

        return jsonify({
            'url': url,
            'is_phishing': result,
            'sql_injection': sql_injection,
            'malware_infection': malware_infection,
            'port_scanning': port_scanning,
            'brute_force': brute_force
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
