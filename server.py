from flask import Flask, request, jsonify

app = Flask(__name__)

security_flags = {}

@app.route('/log_security_event', methods=['POST'])
def log_event():
    data = request.json
    account_id = data.get("account_id")
    issue = data.get("issue")

    # Track security issues per account
    if account_id not in security_flags:
        security_flags[account_id] = []
    security_flags[account_id].append(issue)

    # Check if account should be flagged for review
    if len(security_flags[account_id]) >= 3:
        return jsonify({"status": "alert", "message": "Manual review needed!"})

    return jsonify({"status": "logged", "message": "Event recorded."})

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
