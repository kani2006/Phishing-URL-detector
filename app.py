import sys
import os

# Ensure src/ is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from flask import Flask, request, jsonify, render_template
from risk_engine import analyze
from safe_inspector import inspect as safe_inspect
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/analyze", methods=["POST"])
def analyze_email():
    data = request.get_json(force=True)
    email_text = data.get("email_text", "").strip()

    if not email_text:
        return jsonify({"error": "email_text is required"}), 400

    try:
        result = analyze(email_text)
        return jsonify(result)
    except FileNotFoundError:
        return jsonify({
            "error": "Models not found. Train the models first via POST /train"
        }), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/train", methods=["POST"])
def train_models():
    import url_classifier
    import email_classifier

    data = request.get_json(force=True)
    url_data = data.get("url_data")
    email_data = data.get("email_data")

    results = {}

    if url_data:
        try:
            url_classifier.train(url_data)
            results["url_model"] = "trained"
        except Exception as e:
            results["url_model"] = f"error: {e}"

    if email_data:
        try:
            email_classifier.train(email_data)
            results["email_model"] = "trained"
        except Exception as e:
            results["email_model"] = f"error: {e}"

    if not results:
        return jsonify({"error": "Provide url_data and/or email_data paths"}), 400

    return jsonify(results)


@app.route("/inspect", methods=["POST"])
def inspect_url():
    data = request.get_json(force=True)
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "url is required"}), 400

    if not url.startswith(("http://", "https://")):
        return jsonify({"error": "url must start with http:// or https://"}), 400

    result = safe_inspect(url)
    return jsonify(result)


@app.route("/analyze_and_inspect", methods=["POST"])
def analyze_and_inspect():
    """
    Full pipeline: analyze email, then auto-inspect any URLs flagged as phishing.

    Request body (JSON):
      { "email_text": "<raw email body>" }
    """
    data = request.get_json(force=True)
    email_text = data.get("email_text", "").strip()

    if not email_text:
        return jsonify({"error": "email_text is required"}), 400

    try:
        analysis = analyze(email_text)
    except FileNotFoundError:
        return jsonify({"error": "Models not found. Train first via POST /train"}), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    inspections = []
    if analysis["is_phishing"] and analysis["urls_found"]:
        for url in analysis["urls_found"][:3]:   # cap at 3 URLs per email
            inspection = safe_inspect(url)
            inspections.append(inspection)

    return jsonify({
        "analysis": analysis,
        "url_inspections": inspections,
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
