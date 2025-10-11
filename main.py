from flask import *
from _mysql_connector import *
import mysql.connector
# Initialize the Flask application
app = Flask(__name__)

# Define the route for the home page ('/')
@app.route('/')
def home():
    # Render a simple HTML string directly, or...
    # return "<h1>Hello, World! This is my first Flask Web Page.</h1>"

    # ... more commonly, render an HTML template (e.g., 'index.html')
    return render_template('index.html')
@app.route('/login')
def login():
    return render_template('login.html')
@app.route('/signup')
def signup():
    return render_template('signup.html')
@app.route('/demo')
def demo():
    return render_template('demo.html')


# Run the application
if __name__ == '__main__':
    # 'debug=True' is good for development as it auto-reloads the server on code changes
    app.run(debug=True)

