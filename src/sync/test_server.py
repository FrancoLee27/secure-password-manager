from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/')
def hello():
    return jsonify({"message": "Hello World!"})

if __name__ == "__main__":
    print("Starting test server on http://localhost:5001")
    app.run(debug=True, port=5001) 