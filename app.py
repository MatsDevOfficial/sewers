import json
from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def home():
    with open('config.json', 'r') as f:
        config = json.load(f)
    return render_template('index.html', config=config)

if __name__ == '__main__':
    app.run(debug=True)