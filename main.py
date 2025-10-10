from flask import *
from _mysql_connector import *
# Initialize the Flask application
app = Flask(__name__)

# Define the route for the home page ('/')
@app.route('/')
def home():
    # Render a simple HTML string directly, or...
    # return "<h1>Hello, World! This is my first Flask Web Page.</h1>"

    # ... more commonly, render an HTML template (e.g., 'index.html')
    return render_template('index.html')

# Run the application
if __name__ == '__main__':
    # 'debug=True' is good for development as it auto-reloads the server on code changes
    app.run(debug=True)


conn = mysql.connector.connect(
    host="localhost", user="root", password="", database="Car-Pool-Management-System")

cursor = conn.cursor()
print(c.fetchall())