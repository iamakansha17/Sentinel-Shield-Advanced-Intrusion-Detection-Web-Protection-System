from flask import Flask, request
from detector import inspect_request

app = Flask(__name__)

@app.before_request
def before():
    inspect_request(request)

@app.route("/")
def home():
    return "Sentinel Shield Active"

if __name__ == "__main__":
    app.run(debug=True)
