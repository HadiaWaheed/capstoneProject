from flask import Flask, render_template, request

import joblib
import pandas as pd
import requests

app = Flask(__name__)

# Load model and encoders
model = joblib.load('models/xgb_model.pkl')
label_encoder = joblib.load('models/xgb_label_encoder.pkl')
feature_columns = joblib.load('models/xgb_feature_columns.pkl')

def extract_features(url):
    features = {
        'Strict-Transport-Security': 0,
        'Set-Cookie': 0,
        'X-Content-Type-Options': 0,
        'X-Frame-Options': 0,
        'Cookie Name': 0,
        'HttpOnly': 0,
        'Secure': 0,
        'SameSite': 0,
        'Session in URL': 0,
        'Session in Cookies': 0,
        'Session in Referer': 0,
        'Authentication Mechanism': 0,
        'missing_cookie': 0,
        'Missing_HttpOnly': 0,
        'Missing_Secure': 0,
        'Missing_HSTS': 0,
        'Missing_X-Content-Type-Options': 0,
        'Missing_X-Frame-Options': 0,
        'Missing_SameSite': 0
    }

    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        if response.status_code >= 400:
            response = requests.get(url, timeout=5)
        headers = response.headers

        if 'Strict-Transport-Security' in headers:
            features['Strict-Transport-Security'] = 1
        else:
            features['Missing_HSTS'] = 1

        if 'X-Content-Type-Options' in headers:
            features['X-Content-Type-Options'] = 1
        else:
            features['Missing_X-Content-Type-Options'] = 1

        if 'X-Frame-Options' in headers:
            features['X-Frame-Options'] = 1
        else:
            features['Missing_X-Frame-Options'] = 1

        if 'Set-Cookie' in headers:
            features['Set-Cookie'] = 1
            cookie = headers['Set-Cookie'].lower()
            features['HttpOnly'] = int('httponly' in cookie)
            features['Missing_HttpOnly'] = int('httponly' not in cookie)
            features['Secure'] = int('secure' in cookie)
            features['Missing_Secure'] = int('secure' not in cookie)
            features['SameSite'] = int('samesite' in cookie)
            features['Missing_SameSite'] = int('samesite' not in cookie)
        else:
            features['missing_cookie'] = 1
            features['Missing_HttpOnly'] = 1
            features['Missing_Secure'] = 1
            features['Missing_SameSite'] = 1

        if "session" in url.lower():
            features['Session in URL'] = 1

    except Exception as e:
        print(f"[ERROR] Failed to fetch headers from {url}: {e}")

    return features


def get_attack_vectors(features):
    attack_vectors = []

    if features.get('Missing_HSTS', 0) == 1:
        attack_vectors.append("Risk of SSL stripping attacks (missing Strict-Transport-Security header).")

    if features.get('Missing_HttpOnly', 0) == 1:
        attack_vectors.append("Risk of cookie theft via Cross-Site Scripting (HttpOnly flag missing).")

    if features.get('Missing_Secure', 0) == 1:
        attack_vectors.append("Cookies can be sent over unencrypted channels (Secure flag missing).")

    if features.get('Missing_X-Content-Type-Options', 0) == 1:
        attack_vectors.append("Risk of MIME sniffing attacks (missing X-Content-Type-Options header).")

    if features.get('Missing_X-Frame-Options', 0) == 1:
        attack_vectors.append("Risk of clickjacking attacks (missing X-Frame-Options header).")

    if features.get('Missing_SameSite', 0) == 1:
        attack_vectors.append("Cookies are vulnerable to Cross-Site Request Forgery (SameSite attribute missing).")

    if features.get('Session in URL', 0) == 1:
        attack_vectors.append("Session ID exposed in URL — risk of session hijacking.")

    if features.get('missing_cookie', 0) == 1:
        attack_vectors.append("No cookies detected — potential authentication or session management issue.")

    return attack_vectors


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/contact')
def contact():
    return render_template('contact.html')


@app.route('/result', methods=['POST'])
def result():
    url_input = request.form.get('url', '').strip()

    if not url_input:
        return render_template('index.html', error="Please enter a valid URL.")

    if not url_input.startswith(('http://', 'https://')):
        url_input = 'http://' + url_input

    raw_features = extract_features(url_input)
    feature_data = {col: raw_features.get(col, 0) for col in feature_columns}
    df_input = pd.DataFrame([feature_data])

    prediction = model.predict(df_input)[0]
    prediction_label = label_encoder.inverse_transform([prediction])[0]

    confidence = None
    if hasattr(model, 'predict_proba'):
        proba = model.predict_proba(df_input)[0]
        confidence = max(proba) * 100

    attack_vectors = get_attack_vectors(feature_data)

    return render_template(
        'result.html',
        url=url_input,
        prediction=prediction_label,
        confidence=confidence,
        features=feature_data,
        attack_vectors=attack_vectors
    )


if __name__ == '__main__':
    app.run(debug=True)
