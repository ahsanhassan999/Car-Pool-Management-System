from flask import Flask, render_template, request, redirect, url_for, flash, session
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import os
# Initialize the Flask application
app = Flask(__name__)
app.secret_key = os.urandom(24)  # Change this to a more secure key in production

# Database configuration for XAMPP - Multiple connection attempts
def get_db_connection():
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
    
    for config in connection_configs:
        try:
            conn = mysql.connector.connect(**config)
            return conn
        except mysql.connector.Error:
            continue
    
    return None

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        print("\n" + "="*50)
        print("🔐 Login attempt")
        print("="*50)
        
        # Get form data
        email = request.form.get('email')
        password = request.form.get('password')
        
        print(f"📧 Email: {email}")
        
        # Server-side validation
        if not email or not password:
            print("❌ Validation failed: Missing fields")
            flash('Email and password are required!', 'error')
            return redirect(url_for('login'))
        
        try:
            conn = get_db_connection()
            if not conn:
                print("❌ Failed to establish database connection")
                flash('Database connection failed!', 'error')
                return redirect(url_for('login'))
            
            cursor = conn.cursor()
            
            # Find user by email - Using correct column names
            print(f"🔍 Searching for user with email: {email}")
            cursor.execute("SELECT user_id, name, email, role, password, phone_number FROM users WHERE email = %s", (email,))
            user_tuple = cursor.fetchone()
            
            cursor.close()
            conn.close()
            
            if not user_tuple:
                print(f"❌ No user found with email: {email}")
                flash('Invalid email or password!', 'error')
                return redirect(url_for('login'))
            
            # Convert tuple to dictionary
            user = {
                'user_id': user_tuple[0],
                'name': user_tuple[1],
                'email': user_tuple[2],
                'role': user_tuple[3],
                'password': user_tuple[4],
                'phone_number': user_tuple[5]
            }
            
            print(f"✅ User found: {user['name']} (ID: {user['user_id']}, Role: {user['role']})")
            
            # Verify password
            print("🔒 Verifying password...")
            if check_password_hash(user['password'], password):
                print(f"✅ Login successful for user: {user['name']}")
                
                # Store user info in session
                session['user_id'] = user['user_id']
                session['user_name'] = user['name']
                session['user_email'] = user['email']
                session['user_role'] = user['role']
                
                print(f"📦 Session created: user_id={user['user_id']}, role={user['role']}")
                print("="*50 + "\n")
                
                flash(f'Welcome back, {user["name"]}!', 'success')
                
                # Redirect based on role (note: your DB has 'Driver' and 'Rider' with capital letters)
                if user['role'].lower() == 'driver':
                    print(f"🚗 Redirecting to driver dashboard")
                    return redirect(url_for('driver_dashboard'))
                elif user['role'].lower() == 'rider':
                    print(f"🎒 Redirecting to rider dashboard")
                    return redirect(url_for('rider_dashboard'))
                elif user['role'].lower() == 'admin':
                    print(f"🎒 Redirecting to admin dashboard")
                    return redirect(url_for('admin_dashboard'))
            else:
                print("❌ Invalid password")
                flash('Invalid email or password!', 'error')
                return redirect(url_for('login'))
                
        except mysql.connector.Error as err:
            print(f"❌ Database error: {err}")
            flash(f'Database error: {err}', 'error')
            return redirect(url_for('login'))
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            import traceback
            traceback.print_exc()
            flash(f'An error occurred: {e}', 'error')
            return redirect(url_for('login'))
    
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
        confirm_password = request.form.get('confirmPassword')
        
        print(f"📋 Form Data:")
        print(f"  Name: {name}")
        print(f"  Email: {email}")
        print(f"  Phone: {phone}")
        print(f"  Role: {role}")
        
        # Server-side validation
        if not all([name, email, phone, role, password, confirm_password]):
            print("❌ Validation failed: Missing fields")
            flash('All fields are required!', 'error')
            return redirect(url_for('signup'))
        
        if password != confirm_password:
            print("❌ Validation failed: Passwords don't match")
            flash('Passwords do not match!', 'error')
            return redirect(url_for('signup'))
        
        if len(password) < 6:
            print("❌ Validation failed: Password too short")
            flash('Password must be at least 6 characters!', 'error')
            return redirect(url_for('signup'))
        
        try:
            conn = get_db_connection()
            if not conn:
                print("❌ Failed to establish database connection")
                flash('Database connection failed!', 'error')
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
            
            # Capitalize role to match DB ENUM ('Driver', 'Rider')
            role_capitalized = role.capitalize()
            
            # Insert user into database - Using correct column names
            query = """
                INSERT INTO users (name, email, phone_number, role, password) 
                VALUES (%s, %s, %s, %s, %s)
            """
            print(f"📤 Executing insert query...")
            cursor.execute(query, (name, email, phone, role_capitalized, hashed_password))
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

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/driver-dashboard')
def driver_dashboard():
    if 'user_id' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('login'))
    
    if session.get('user_role', '').lower() != 'driver':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    # FIXED: Added .html extension
    return render_template('driver_dashboard.html')

@app.route('/rider-dashboard')
def rider_dashboard():
    if 'user_id' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('login'))
    
    if session.get('user_role', '').lower() != 'rider':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    # FIXED: Added .html extension
    return render_template('rider_dashboard.html')

@app.route('/admin-dashboard')
def admin_dashboard():
    if 'user_id' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('login'))
    
    if session.get('user_role', '').lower() == 'admin':
        return render_template('admin_dashboard.html')
    elif session.get('user_role', '').lower() != 'admin':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))

@app.route('/demo')
def demo():
    return render_template('demo.html')

if __name__ == '__main__':
    app.run(debug=True)