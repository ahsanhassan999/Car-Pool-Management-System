from flask import Flask, render_template, request, redirect, url_for, flash, session
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize the Flask application
app = Flask(__name__)
app.secret_key = 'abcd'

# Database configuration for XAMPP - Multiple connection attempts
def get_db_connection():
    # Try different connection methods
    connection_configs = [
        {
            'host': '127.0.0.1',
            'user': 'root',
            'password': '',
            'database': 'Car-Pool-Management-System',
            'port': 3306
        },
        {
            'host': 'localhost',
            'user': 'root',
            'password': '',
            'database': 'Car-Pool-Management-System',
            'port': 3306
        },
        {
            'unix_socket': '/Applications/XAMPP/xamppfiles/var/mysql/mysql.sock',
            'user': 'root',
            'password': '',
            'database': 'Car-Pool-Management-System'
        }
    ]
    
    for i, config in enumerate(connection_configs, 1):
        try:
            print(f"🔌 Connection attempt {i}...")
            if 'unix_socket' in config:
                print(f"   Using Unix socket: {config['unix_socket']}")
            else:
                print(f"   Host: {config['host']}, Port: {config['port']}")
            
            conn = mysql.connector.connect(**config)
            print("✅ Database connected successfully!")
            return conn
        except mysql.connector.Error as err:
            print(f"❌ Attempt {i} failed: {err}")
            continue
    
    print("❌ All connection attempts failed!")
    return None

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        print("\n" + "="*50)
        print("📝 Form submitted!")
        print("="*50)
        
        # Get form data
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        role = request.form.get('role')
        password = request.form.get('password')
        
        print(f"📋 Form Data:")
        print(f"  Name: {name}")
        print(f"  Email: {email}")
        print(f"  Phone: {phone}")
        print(f"  Role: {role}")
        print(f"  Password: {password}")
        
        try:
            conn = get_db_connection()
            if not conn:
                print("❌ Failed to establish database connection")
                flash('Database connection failed! Please make sure XAMPP MySQL is running.', 'error')
                return redirect(url_for('signup'))
                
            cursor = conn.cursor()
            print("✅ Database cursor created")
            
            # Check if email already exists
            print(f"🔍 Checking if email {email} exists...")
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            existing_user = cursor.fetchone()
            
            if existing_user:
                print(f"❌ Email {email} already exists")
                flash('Email already registered!', 'error')
                cursor.close()
                conn.close()
                return redirect(url_for('signup'))
            
            print("✅ Email is unique")
            
            # Hash the password
            hashed_password = generate_password_hash(password)
            print(f"🔒 Password hashed successfully")
            
            # Insert user into database
            query = """
                INSERT INTO users (name, email, phone_number, role, password) 
                VALUES (%s, %s, %s, %s, %s)
            """
            print(f"📤 Executing insert query...")
            cursor.execute(query, (name, email, phone, role, hashed_password))
            conn.commit()
            
            user_id = cursor.lastrowid
            print(f"✅ User '{name}' registered successfully with ID: {user_id}")
            print("="*50 + "\n")
            
            cursor.close()
            conn.close()
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
            
        except mysql.connector.Error as err:
            print(f"❌ Database error: {err}")
            flash(f'Database error: {err}', 'error')
            return redirect(url_for('signup'))
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            flash(f'An error occurred: {e}', 'error')
            return redirect(url_for('signup'))
    
    return render_template('signup.html')

@app.route('/demo')
def demo():
    return render_template('demo.html')

# Run the application
if __name__ == '__main__':
    print("\n" + "="*50)
    print("🚀 Starting Flask Application")
    print("="*50)
    print("Testing database connection on startup...")
    test_conn = get_db_connection()
    if test_conn:
        test_conn.close()
        print("✅ Initial database connection successful!")
    else:
        print("⚠️  WARNING: Could not connect to database!")
    print("="*50 + "\n")
    
    app.run(debug=True)