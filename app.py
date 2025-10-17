from flask import Flask, render_template, request, redirect, url_for, flash, session
import secrets
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import os
# Initialize the Flask application
app = Flask(__name__)
app.secret_key = os.urandom(24) # Change this to a more secure key in production

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

# --- Security utilities ---
def get_or_create_csrf_token() -> str:
    """Return a stable CSRF token for the current session, creating one if needed."""
    token = session.get('csrf_token')
    if not token:
        token = secrets.token_hex(32)
        session['csrf_token'] = token
    return token

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
        print(f"   Name: {name}")
        print(f"   Email: {email}")
        print(f"   Phone: {phone}")
        print(f"   Role: {role}")
        
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
    
    user_name = session.get('user_name', 'Guest')
    user_role = session.get('user_role', 'Unknown')
    
    return render_template('driver_dashboard.html', user_name=user_name, user_role=user_role)

@app.route('/rider-dashboard')
def rider_dashboard():
    if 'user_id' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('login'))
    
    if session.get('user_role', '').lower() != 'rider':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    user_name = session.get('user_name', 'Guest')
    user_role = session.get('user_role', 'Unknown')
    
    return render_template('rider_dashboard.html', user_name=user_name, user_role=user_role)

@app.route('/admin-dashboard')
def admin_dashboard():
    if 'user_id' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('login'))
    
    if session.get('user_role', '').lower() != 'admin':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
        
    user_name = session.get('user_name', 'Guest')
    user_role = session.get('user_role', 'Unknown')
    
    # Logic to create user avatar initials for the dashboard header
    words = user_name.strip().split()
    user_avatar = (words[0][0] + words[-1][0]) if len(words) >= 2 else words[0][:2]

    return render_template('admin_dashboard.html', user_name=user_name, user_role=user_role, user_avatar=user_avatar)
    
# --- NEWLY MODIFIED ROUTE: Fetches All Users from DB ---
@app.route('/admin-dashboard/all-users')
def all_users():
    # 1. Access Control Check (Ensures Admin is logged in)
    if 'user_id' not in session or session.get('user_role', '').lower() != 'admin':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
        
    # User data for header display
    user_name = session.get('user_name', 'Guest')
    user_role = session.get('user_role', 'Unknown')
    words = user_name.strip().split()
    user_avatar = (words[0][0] + words[-1][0]) if len(words) >= 2 else words[0][:2]
    
    all_users_data = []
    
    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection failed while fetching users!', 'error')
            return redirect(url_for('admin_dashboard'))
            
        cursor = conn.cursor()
        
        # 2. Execute Query to fetch all users (excluding the sensitive 'password' column)
        # We need to explicitly name the columns we select to match the column_names later.
        query = "SELECT user_id, name, email, phone_number, role FROM users"
        cursor.execute(query)
        
        # Get column names to create dictionaries
        column_names = [i[0] for i in cursor.description]
        
        # Fetch all results
        user_records = cursor.fetchall()
        
        # 3. Process Results into a list of dictionaries
        for record in user_records:
            user_dict = dict(zip(column_names, record))
            all_users_data.append(user_dict)
            
        cursor.close()
        conn.close()
        
    except mysql.connector.Error as err:
        print(f"❌ Database error fetching users: {err}")
        flash(f'Database error: {err}', 'error')
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        print(f"❌ Unexpected error fetching users: {e}")
        flash(f'An unexpected error occurred: {e}', 'error')
        return redirect(url_for('admin_dashboard'))
        
    # Generate CSRF token for forms on this page and
    # pass the list of user dictionaries to the template
    csrf_token = get_or_create_csrf_token()
    return render_template(
        'all_users.html', 
        user_name=user_name, 
        user_role=user_role, 
        user_avatar=user_avatar,
        users=all_users_data,
        csrf_token=csrf_token
    )
# -----------------------------------------------------------

# --- ROUTE: Fetches All Cars from DB ---
@app.route('/admin-dashboard/all-cars')
def all_cars():
    # Access Control
    if 'user_id' not in session or session.get('user_role', '').lower() != 'admin':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))

    # User data for header display
    user_name = session.get('user_name', 'Guest')
    user_role = session.get('user_role', 'Unknown')
    words = user_name.strip().split()
    user_avatar = (words[0][0] + words[-1][0]) if len(words) >= 2 else words[0][:2]

    all_cars_data = []

    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection failed while fetching cars!', 'error')
            return redirect(url_for('admin_dashboard'))

        cursor = conn.cursor()

        # Explicitly select columns for consistent mapping
        query = "SELECT car_id, user_id, make, model, license_plate, seats FROM cars"
        cursor.execute(query)

        column_names = [i[0] for i in cursor.description]
        car_records = cursor.fetchall()
        for record in car_records:
            car_dict = dict(zip(column_names, record))
            all_cars_data.append(car_dict)

        cursor.close()
        conn.close()

    except mysql.connector.Error as err:
        print(f"❌ Database error fetching cars: {err}")
        flash(f'Database error: {err}', 'error')
        return redirect(url_for('admin_dashboard'))
    except Exception as e:
        print(f"❌ Unexpected error fetching cars: {e}")
        flash(f'An unexpected error occurred: {e}', 'error')
        return redirect(url_for('admin_dashboard'))

    return render_template(
        'all_cars.html',
        user_name=user_name,
        user_role=user_role,
        user_avatar=user_avatar,
        cars=all_cars_data
    )


@app.route('/admin-dashboard/edit-user', methods=['POST'])
def edit_user():
    # Access control
    if 'user_id' not in session or session.get('user_role', '').lower() != 'admin':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))

    # Read form data
    user_id = request.form.get('user_id')
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()
    phone_number = request.form.get('phone_number', '').strip()
    role = request.form.get('role', '').strip()
    new_password = request.form.get('new_password', '').strip()
    confirm_password = request.form.get('confirm_password', '').strip()

    # CSRF validation
    submitted_csrf = request.form.get('csrf_token', '')
    if not submitted_csrf or submitted_csrf != session.get('csrf_token'):
        flash('Invalid form submission. Please try again.', 'error')
        return redirect(url_for('all_users'))

    # Basic validation
    if not user_id or not name or not email or not role:
        flash('Missing required fields.', 'error')
        return redirect(url_for('all_users'))

    # Normalize and validate role
    role_map = { 'driver': 'Driver', 'rider': 'Rider', 'admin': 'Admin' }
    role_normalized = role_map.get(role.lower())
    if not role_normalized:
        flash('Invalid role selected.', 'error')
        return redirect(url_for('all_users'))

    try:
        user_id_int = int(user_id)
    except ValueError:
        flash('Invalid user id.', 'error')
        return redirect(url_for('all_users'))

    # Optional password change validation (admin-initiated)
    hashed_password = None
    password_change_requested = bool(new_password or confirm_password)
    if password_change_requested:
        if not new_password or not confirm_password:
            flash('To change the password, fill both password fields.', 'error')
            return redirect(url_for('all_users'))
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return redirect(url_for('all_users'))
        if len(new_password) < 6:
            flash('Password must be at least 6 characters!', 'error')
            return redirect(url_for('all_users'))
        hashed_password = generate_password_hash(new_password)

    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection failed while updating user!', 'error')
            return redirect(url_for('all_users'))

        cursor = conn.cursor()

        # Ensure email is unique to this user
        cursor.execute("SELECT user_id FROM users WHERE email = %s AND user_id != %s", (email, user_id_int))
        conflict = cursor.fetchone()
        if conflict:
            cursor.close()
            conn.close()
            flash('Email already in use by another user.', 'error')
            return redirect(url_for('all_users'))

        # Empty string should become NULL in DB
        phone_value = phone_number if phone_number else None

        # Perform the update (optionally updating password)
        if hashed_password is not None:
            update_sql = (
                "UPDATE users SET name = %s, email = %s, phone_number = %s, role = %s, password = %s WHERE user_id = %s"
            )
            cursor.execute(update_sql, (name, email, phone_value, role_normalized, hashed_password, user_id_int))
        else:
            update_sql = (
                "UPDATE users SET name = %s, email = %s, phone_number = %s, role = %s WHERE user_id = %s"
            )
            cursor.execute(update_sql, (name, email, phone_value, role_normalized, user_id_int))
        conn.commit()

        cursor.close()
        conn.close()

        flash('User updated successfully.', 'success')
        return redirect(url_for('all_users'))

    except mysql.connector.Error as err:
        flash(f'Database error: {err}', 'error')
        return redirect(url_for('all_users'))
    except Exception as e:
        flash(f'Unexpected error: {e}', 'error')
        return redirect(url_for('all_users'))


@app.route('/admin-dashboard/add-user', methods=['POST'])
def add_user():
    # Access control
    if 'user_id' not in session or session.get('user_role', '').lower() != 'admin':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))

    # CSRF validation
    submitted_csrf = request.form.get('csrf_token', '')
    if not submitted_csrf or submitted_csrf != session.get('csrf_token'):
        flash('Invalid form submission. Please try again.', 'error')
        return redirect(url_for('all_users'))

    # Read form data
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()
    phone_number = request.form.get('phone_number', '').strip()
    role = request.form.get('role', '').strip()
    password = request.form.get('password', '').strip()
    confirm_password = request.form.get('confirm_password', '').strip()

    # Basic validation
    if not all([name, email, role, password, confirm_password]):
        flash('Please fill in all required fields.', 'error')
        return redirect(url_for('all_users'))

    # Normalize and validate role
    role_map = { 'driver': 'Driver', 'rider': 'Rider', 'admin': 'Admin' }
    role_normalized = role_map.get(role.lower())
    if not role_normalized:
        flash('Invalid role selected.', 'error')
        return redirect(url_for('all_users'))

    if password != confirm_password:
        flash('Passwords do not match.', 'error')
        return redirect(url_for('all_users'))
    if len(password) < 6:
        flash('Password must be at least 6 characters!', 'error')
        return redirect(url_for('all_users'))

    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection failed while creating user!', 'error')
            return redirect(url_for('all_users'))

        cursor = conn.cursor()

        # Ensure email is unique
        cursor.execute("SELECT user_id FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            flash('Email already registered to another user.', 'error')
            return redirect(url_for('all_users'))

        hashed_password = generate_password_hash(password)
        phone_value = phone_number if phone_number else None

        insert_sql = (
            "INSERT INTO users (name, email, phone_number, role, password) VALUES (%s, %s, %s, %s, %s)"
        )
        cursor.execute(insert_sql, (name, email, phone_value, role_normalized, hashed_password))
        conn.commit()

        cursor.close()
        conn.close()

        flash('User created successfully.', 'success')
        return redirect(url_for('all_users'))

    except mysql.connector.Error as err:
        flash(f'Database error: {err}', 'error')
        return redirect(url_for('all_users'))
    except Exception as e:
        flash(f'Unexpected error: {e}', 'error')
        return redirect(url_for('all_users'))

@app.route('/admin-dashboard/edit-car', methods=['POST'])
def edit_car():
    # Access control
    if 'user_id' not in session or session.get('user_role', '').lower() != 'admin':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))

    # Read form data
    car_id = request.form.get('car_id')
    owner_user_id = request.form.get('user_id', '').strip()
    make = request.form.get('make', '').strip()
    model = request.form.get('model', '').strip()
    license_plate = request.form.get('license_plate', '').strip()
    seats = request.form.get('seats', '').strip()

    # Basic validation
    if not all([car_id, owner_user_id, make, model, license_plate, seats]):
        flash('Missing required fields.', 'error')
        return redirect(url_for('all_cars'))

    try:
        car_id_int = int(car_id)
        owner_user_id_int = int(owner_user_id)
        seats_int = int(seats)
        if seats_int <= 0:
            raise ValueError('Seats must be positive')
    except (TypeError, ValueError):
        flash('Invalid numeric value for user id or seats.', 'error')
        return redirect(url_for('all_cars'))

    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection failed while updating car!', 'error')
            return redirect(url_for('all_cars'))

        cursor = conn.cursor()

        # Ensure owner user exists
        cursor.execute("SELECT user_id FROM users WHERE user_id = %s", (owner_user_id_int,))
        owner_exists = cursor.fetchone()
        if not owner_exists:
            cursor.close()
            conn.close()
            flash('Owner user not found.', 'error')
            return redirect(url_for('all_cars'))

        # Ensure license plate is unique to this car
        cursor.execute("SELECT car_id FROM cars WHERE license_plate = %s AND car_id != %s", (license_plate, car_id_int))
        conflict = cursor.fetchone()
        if conflict:
            cursor.close()
            conn.close()
            flash('License plate already in use by another car.', 'error')
            return redirect(url_for('all_cars'))

        update_sql = (
            "UPDATE cars SET user_id = %s, make = %s, model = %s, license_plate = %s, seats = %s WHERE car_id = %s"
        )
        cursor.execute(update_sql, (owner_user_id_int, make, model, license_plate, seats_int, car_id_int))
        conn.commit()

        cursor.close()
        conn.close()

        flash('Car updated successfully.', 'success')
        return redirect(url_for('all_cars'))

    except mysql.connector.Error as err:
        flash(f'Database error: {err}', 'error')
        return redirect(url_for('all_cars'))
    except Exception as e:
        flash(f'Unexpected error: {e}', 'error')
        return redirect(url_for('all_cars'))


@app.route('/admin-dashboard/delete-user', methods=['POST'])
def delete_user():
    # Access control
    if 'user_id' not in session or session.get('user_role', '').lower() != 'admin':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))

    # CSRF validation
    submitted_csrf = request.form.get('csrf_token', '')
    if not submitted_csrf or submitted_csrf != session.get('csrf_token'):
        flash('Invalid form submission. Please try again.', 'error')
        return redirect(url_for('all_users'))

    user_id = request.form.get('user_id')
    try:
        user_id_int = int(user_id)
    except (TypeError, ValueError):
        flash('Invalid user id.', 'error')
        return redirect(url_for('all_users'))

    # Optional: prevent an admin from deleting their own account to avoid lockout
    if user_id_int == session.get('user_id'):
        flash('You cannot delete your own account while logged in.', 'error')
        return redirect(url_for('all_users'))

    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection failed while deleting user!', 'error')
            return redirect(url_for('all_users'))

        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE user_id = %s", (user_id_int,))
        conn.commit()
        cursor.close()
        conn.close()

        flash('User deleted successfully.', 'success')
        return redirect(url_for('all_users'))

    except mysql.connector.Error as err:
        flash(f'Database error: {err}', 'error')
        return redirect(url_for('all_users'))
    except Exception as e:
        flash(f'Unexpected error: {e}', 'error')
        return redirect(url_for('all_users'))


@app.route('/admin-dashboard/delete-car', methods=['POST'])
def delete_car():
    # Access control
    if 'user_id' not in session or session.get('user_role', '').lower() != 'admin':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))

    car_id = request.form.get('car_id')
    try:
        car_id_int = int(car_id)
    except (TypeError, ValueError):
        flash('Invalid car id.', 'error')
        return redirect(url_for('all_cars'))

    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection failed while deleting car!', 'error')
            return redirect(url_for('all_cars'))

        cursor = conn.cursor()
        cursor.execute("DELETE FROM cars WHERE car_id = %s", (car_id_int,))
        conn.commit()
        cursor.close()
        conn.close()

        flash('Car deleted successfully.', 'success')
        return redirect(url_for('all_cars'))

    except mysql.connector.Error as err:
        flash(f'Database error: {err}', 'error')
        return redirect(url_for('all_cars'))
    except Exception as e:
        flash(f'Unexpected error: {e}', 'error')
        return redirect(url_for('all_cars'))

@app.route('/demo')
def demo():
    return render_template('demo.html')



if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
