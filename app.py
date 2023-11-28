from flask import Flask, render_template, request
from bytebandits import get_pw
from waitress import serve

app = Flask(__name__)

@app.route('/')
@app.route('/index')
def index():
    return render_template(
        "index.html",
        name="Aryana"
    )


@app.route('/password')
def get_pw():
    return render_template(
        "password.html"
    )

if __name__ == "__main__":
    serve(app, host="0.0.0.0", port=8000)
    
