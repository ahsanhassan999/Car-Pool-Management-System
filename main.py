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

@app.route('/about')
def about():
    return render_template('about.html')

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
    
    success, message, rides = get_all_active_rides()
    
    if not success:
        flash(message, 'error')
        rides = []

    user_name = session.get('user_name', 'Guest')
    user_role = session.get('user_role', 'Unknown')
    
    return render_template('driver_dashboard.html', 
                           user_name=user_name, 
                           user_role=user_role, 
                           rides=rides if rides else [])

@app.route('/rider-dashboard')
def rider_dashboard():
    if 'user_id' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('login'))
    
    if session.get('user_role', '').lower() != 'rider':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    success, message, rides = get_all_active_rides()
    
    if not success:
        flash(message, 'error')
        rides = []

    user_name = session.get('user_name', 'Guest')
    user_role = session.get('user_role', 'Unknown')
    
    return render_template('rider_dashboard.html', 
                           user_name=user_name, 
                           user_role=user_role, 
                           rides=rides if rides else [])

@app.route('/admin-dashboard')
def admin_dashboard():
    if 'user_id' not in session:
        flash('Please login first!', 'error')
        return redirect(url_for('login'))
    
    if session.get('user_role', '').lower() != 'admin':
        flash('Access denied!', 'error')
        return redirect(url_for('login'))
    
    success, message, rides = get_all_active_rides()
    
    if not success:
        flash(message, 'error')
        rides = []
        
    user_name = session.get('user_name', 'Guest')
    user_role = session.get('user_role', 'Unknown')
    
    # Logic to create user avatar initials for the dashboard header
    words = user_name.strip().split()
    user_avatar = (words[0][0] + words[-1][0]) if len(words) >= 2 else words[0][:2]

    return render_template('admin_dashboard.html', 
                           user_name=user_name, 
                           user_role=user_role, 
                           user_avatar=user_avatar,
                           rides=rides if rides else [])
    
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

# ============================================================================
# CARPOOL MANAGEMENT SYSTEM - RIDE AND BOOKING FUNCTIONS
# ============================================================================

# --- Function 1: Create New Ride ---
def create_new_ride(driver_id, car_id, start, end, dep_time, price, notes=None):
    """
    Allows a driver to initiate a new ride.
    
    Args:
        driver_id (int): The user_id of the driver
        car_id (int): The car_id to use for the ride
        start (str): Starting point location
        end (str): Destination point location
        dep_time (datetime): Departure time
        price (float): Price per seat (using single price field from schema)
        notes (str, optional): Driver notes
    
    Returns:
        tuple: (success: bool, message: str, ride_id: int or None)
    """
    try:
        conn = get_db_connection()
        if not conn:
            return (False, "Database connection failed", None)
        
        cursor = conn.cursor()
        
        # Check 1: Ensure driver doesn't already have an active ride
        check_query = """
            SELECT ride_id FROM rides 
            WHERE driver_id = %s AND is_active = TRUE
        """
        cursor.execute(check_query, (driver_id,))
        existing_ride = cursor.fetchone()
        
        if existing_ride:
            cursor.close()
            conn.close()
            return (False, "You already have an active ride. Complete or cancel it before creating a new one.", None)
        
        # Check that the car belongs to the driver
        cursor.execute("SELECT user_id, seats FROM cars WHERE car_id = %s", (car_id,))
        car_data = cursor.fetchone()
        
        if not car_data:
            cursor.close()
            conn.close()
            return (False, "Car not found", None)
        
        if car_data[0] != driver_id:
            cursor.close()
            conn.close()
            return (False, "You can only create rides with your own car", None)
        
        # Get total seats from car (reserve 1 for driver)
        total_seats = max(1, car_data[1] - 1)  # Driver takes 1 seat
        
        # Action: Insert new ride
        insert_query = """
            INSERT INTO rides 
            (driver_id, car_id, starting_point, destination_point, departure_time, 
             total_seats, available_seats, price_per_seat, driver_notes, is_active)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE)
        """
        cursor.execute(insert_query, (
            driver_id, car_id, start, end, dep_time,
            total_seats, total_seats, price, notes
        ))
        conn.commit()
        
        ride_id = cursor.lastrowid
        
        cursor.close()
        conn.close()
        
        return (True, "Ride created successfully", ride_id)
        
    except mysql.connector.Error as err:
        print(f"❌ Database error in create_new_ride: {err}")
        return (False, f"Database error: {err}", None)
    except Exception as e:
        print(f"❌ Unexpected error in create_new_ride: {e}")
        return (False, f"Unexpected error: {e}", None)


# --- Function 2: Get All Active Rides ---
def get_all_active_rides():
    """
    Retrieve all active rides for the 'All Rides' page on the Rider dashboard.
    
    Returns:
        tuple: (success: bool, message: str, rides_list: list of dicts or None)
    """
    try:
        conn = get_db_connection()
        if not conn:
            return (False, "Database connection failed", None)
        
        cursor = conn.cursor()
        
        # Select all active rides with available seats, including driver info
        query = """
            SELECT 
                r.ride_id, r.driver_id, r.car_id, r.starting_point, r.destination_point,
                r.departure_time, r.total_seats, r.available_seats, r.price_per_seat,
                r.driver_notes, r.created_at,
                u.name AS driver_name, u.phone_number AS driver_phone,
                c.make AS car_make, c.model AS car_model, c.license_plate
            FROM rides r
            INNER JOIN users u ON r.driver_id = u.user_id
            LEFT JOIN cars c ON r.car_id = c.car_id
            WHERE r.is_active = TRUE AND r.available_seats > 0
            ORDER BY r.departure_time ASC
        """
        cursor.execute(query)
        
        column_names = [i[0] for i in cursor.description]
        ride_records = cursor.fetchall()
        
        rides_list = []
        for record in ride_records:
            ride_dict = dict(zip(column_names, record))
            rides_list.append(ride_dict)
        
        cursor.close()
        conn.close()
        
        return (True, f"Found {len(rides_list)} active rides", rides_list)
        
    except mysql.connector.Error as err:
        print(f"❌ Database error in get_all_active_rides: {err}")
        return (False, f"Database error: {err}", None)
    except Exception as e:
        print(f"❌ Unexpected error in get_all_active_rides: {e}")
        return (False, f"Unexpected error: {e}", None)


# --- Function 3: Request to Join Ride ---
def request_to_join_ride(rider_id, ride_id):
    """
    Allows a Rider to request a seat.
    
    Args:
        rider_id (int): The user_id of the rider
        ride_id (int): The ride_id to join
    
    Returns:
        tuple: (success: bool, message: str, booking_id: int or None)
    """
    try:
        conn = get_db_connection()
        if not conn:
            return (False, "Database connection failed", None)
        
        cursor = conn.cursor()
        
        # Check 1 (Availability): Ensure available_seats > 0
        cursor.execute("SELECT available_seats, driver_id FROM rides WHERE ride_id = %s AND is_active = TRUE", (ride_id,))
        ride_data = cursor.fetchone()
        
        if not ride_data:
            cursor.close()
            conn.close()
            return (False, "Ride not found or is no longer active", None)
        
        available_seats, driver_id = ride_data
        
        if available_seats <= 0:
            cursor.close()
            conn.close()
            return (False, "No seats available for this ride", None)
        
        # Check that rider is not the driver
        if rider_id == driver_id:
            cursor.close()
            conn.close()
            return (False, "You cannot book your own ride", None)
        
        # Check 2 (Existing Request): Ensure rider doesn't already have a booking
        check_query = """
            SELECT booking_id, booking_status 
            FROM bookings 
            WHERE rider_id = %s AND ride_id = %s 
            AND booking_status IN ('Pending', 'Confirmed')
        """
        cursor.execute(check_query, (rider_id, ride_id))
        existing_booking = cursor.fetchone()
        
        if existing_booking:
            cursor.close()
            conn.close()
            status = existing_booking[1]
            return (False, f"You already have a {status.lower()} booking for this ride", None)
        
        # Action: Insert new booking with Pending status
        insert_query = """
            INSERT INTO bookings (ride_id, rider_id, booking_status, seats_booked)
            VALUES (%s, %s, 'Pending', 1)
        """
        cursor.execute(insert_query, (ride_id, rider_id))
        conn.commit()
        
        booking_id = cursor.lastrowid
        
        cursor.close()
        conn.close()
        
        return (True, "Booking request submitted successfully. Waiting for driver approval.", booking_id)
        
    except mysql.connector.Error as err:
        print(f"❌ Database error in request_to_join_ride: {err}")
        return (False, f"Database error: {err}", None)
    except Exception as e:
        print(f"❌ Unexpected error in request_to_join_ride: {e}")
        return (False, f"Unexpected error: {e}", None)


# --- Function 4: Driver Manage Request ---
def driver_manage_request(booking_id, action, driver_id):
    """
    Allows the Driver to accept or reject a pending request.
    
    Args:
        booking_id (int): The booking_id to manage
        action (str): Either 'Accept' or 'Reject'
        driver_id (int): The driver's user_id (for verification)
    
    Returns:
        tuple: (success: bool, message: str)
    """
    try:
        conn = get_db_connection()
        if not conn:
            return (False, "Database connection failed")
        
        cursor = conn.cursor()
        
        # Get booking details and verify it belongs to driver's ride
        query = """
            SELECT b.booking_id, b.ride_id, b.booking_status, b.seats_booked,
                   r.driver_id, r.available_seats
            FROM bookings b
            INNER JOIN rides r ON b.ride_id = r.ride_id
            WHERE b.booking_id = %s
        """
        cursor.execute(query, (booking_id,))
        booking_data = cursor.fetchone()
        
        if not booking_data:
            cursor.close()
            conn.close()
            return (False, "Booking not found")
        
        _, ride_id, booking_status, seats_booked, ride_driver_id, available_seats = booking_data
        
        # Verify the driver owns this ride
        if ride_driver_id != driver_id:
            cursor.close()
            conn.close()
            return (False, "You can only manage bookings for your own rides")
        
        # Check booking is still pending
        if booking_status != 'Pending':
            cursor.close()
            conn.close()
            return (False, f"This booking is already {booking_status.lower()}")
        
        if action == 'Accept':
            # Check if there are still seats available
            if available_seats < seats_booked:
                cursor.close()
                conn.close()
                return (False, "Not enough seats available")
            
            # Action 1: Update booking status to Confirmed
            cursor.execute(
                "UPDATE bookings SET booking_status = 'Confirmed' WHERE booking_id = %s",
                (booking_id,)
            )
            
            # CRITICAL Action 2: Decrement available_seats
            cursor.execute(
                "UPDATE rides SET available_seats = available_seats - %s WHERE ride_id = %s",
                (seats_booked, ride_id)
            )
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return (True, "Booking accepted successfully")
            
        elif action == 'Reject':
            # Action: Update booking status to Rejected (or Cancelled based on schema)
            cursor.execute(
                "UPDATE bookings SET booking_status = 'Rejected' WHERE booking_id = %s",
                (booking_id,)
            )
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return (True, "Booking rejected")
            
        else:
            cursor.close()
            conn.close()
            return (False, "Invalid action. Use 'Accept' or 'Reject'")
        
    except mysql.connector.Error as err:
        print(f"❌ Database error in driver_manage_request: {err}")
        return (False, f"Database error: {err}")
    except Exception as e:
        print(f"❌ Unexpected error in driver_manage_request: {e}")
        return (False, f"Unexpected error: {e}")


# --- Function 5: Get Driver Active Ride Details ---
def get_driver_active_ride_details(driver_id):
    """
    Retrieves the driver's active ride and all confirmed riders.
    
    Args:
        driver_id (int): The driver's user_id
    
    Returns:
        tuple: (success: bool, message: str, data: dict or None)
               data contains: {'ride': dict, 'confirmed_riders': list, 'pending_requests': list}
    """
    try:
        conn = get_db_connection()
        if not conn:
            return (False, "Database connection failed", None)
        
        cursor = conn.cursor()
        
        # Action 1: Get active ride details
        ride_query = """
            SELECT 
                r.ride_id, r.driver_id, r.car_id, r.starting_point, r.destination_point,
                r.departure_time, r.total_seats, r.available_seats, r.price_per_seat,
                r.driver_notes, r.created_at, r.is_active,
                c.make AS car_make, c.model AS car_model, c.license_plate, c.seats AS car_seats
            FROM rides r
            LEFT JOIN cars c ON r.car_id = c.car_id
            WHERE r.driver_id = %s AND r.is_active = TRUE
            LIMIT 1
        """
        cursor.execute(ride_query, (driver_id,))
        column_names = [i[0] for i in cursor.description]
        ride_record = cursor.fetchone()
        
        if not ride_record:
            cursor.close()
            conn.close()
            return (False, "No active ride found", None)
        
        ride_dict = dict(zip(column_names, ride_record))
        ride_id = ride_dict['ride_id']
        
        # Action 2: Get all confirmed riders
        confirmed_query = """
            SELECT 
                b.booking_id, b.rider_id, b.seats_booked, b.booked_at,
                u.name AS rider_name, u.phone_number AS rider_phone, u.email AS rider_email
            FROM bookings b
            INNER JOIN users u ON b.rider_id = u.user_id
            WHERE b.ride_id = %s AND b.booking_status = 'Confirmed'
            ORDER BY b.booked_at ASC
        """
        cursor.execute(confirmed_query, (ride_id,))
        column_names = [i[0] for i in cursor.description]
        confirmed_records = cursor.fetchall()
        
        confirmed_riders = []
        for record in confirmed_records:
            rider_dict = dict(zip(column_names, record))
            confirmed_riders.append(rider_dict)
        
        # Also get pending requests
        pending_query = """
            SELECT 
                b.booking_id, b.rider_id, b.seats_booked, b.booked_at,
                u.name AS rider_name, u.phone_number AS rider_phone, u.email AS rider_email
            FROM bookings b
            INNER JOIN users u ON b.rider_id = u.user_id
            WHERE b.ride_id = %s AND b.booking_status = 'Pending'
            ORDER BY b.booked_at ASC
        """
        cursor.execute(pending_query, (ride_id,))
        column_names = [i[0] for i in cursor.description]
        pending_records = cursor.fetchall()
        
        pending_requests = []
        for record in pending_records:
            request_dict = dict(zip(column_names, record))
            pending_requests.append(request_dict)
        
        cursor.close()
        conn.close()
        
        result_data = {
            'ride': ride_dict,
            'confirmed_riders': confirmed_riders,
            'pending_requests': pending_requests
        }
        
        return (True, "Active ride details retrieved", result_data)
        
    except mysql.connector.Error as err:
        print(f"❌ Database error in get_driver_active_ride_details: {err}")
        return (False, f"Database error: {err}", None)
    except Exception as e:
        print(f"❌ Unexpected error in get_driver_active_ride_details: {e}")
        return (False, f"Unexpected error: {e}", None)


# --- Function 6: Get Rider Current Ride ---
def get_rider_current_ride(rider_id):
    """
    Retrieves the rider's confirmed ride details.
    
    Args:
        rider_id (int): The rider's user_id
    
    Returns:
        tuple: (success: bool, message: str, data: dict or None)
    """
    try:
        conn = get_db_connection()
        if not conn:
            return (False, "Database connection failed", None)
        
        cursor = conn.cursor()
        
        # Query for confirmed booking with ride, driver, and car info
        query = """
            SELECT 
                b.booking_id, b.ride_id, b.booking_status, b.seats_booked, b.booked_at,
                r.starting_point, r.destination_point, r.departure_time, 
                r.price_per_seat, r.driver_notes, r.available_seats, r.total_seats,
                u.name AS driver_name, u.phone_number AS driver_phone, u.email AS driver_email,
                c.make AS car_make, c.model AS car_model, c.license_plate, c.seats AS car_seats
            FROM bookings b
            INNER JOIN rides r ON b.ride_id = r.ride_id
            INNER JOIN users u ON r.driver_id = u.user_id
            LEFT JOIN cars c ON r.car_id = c.car_id
            WHERE b.rider_id = %s AND b.booking_status = 'Confirmed' AND r.is_active = TRUE
            ORDER BY r.departure_time ASC
            LIMIT 1
        """
        cursor.execute(query, (rider_id,))
        
        column_names = [i[0] for i in cursor.description]
        ride_record = cursor.fetchone()
        
        if not ride_record:
            cursor.close()
            conn.close()
            return (False, "No confirmed ride found", None)
        
        ride_dict = dict(zip(column_names, ride_record))
        
        cursor.close()
        conn.close()
        
        return (True, "Current ride details retrieved", ride_dict)
        
    except mysql.connector.Error as err:
        print(f"❌ Database error in get_rider_current_ride: {err}")
        return (False, f"Database error: {err}", None)
    except Exception as e:
        print(f"❌ Unexpected error in get_rider_current_ride: {e}")
        return (False, f"Unexpected error: {e}", None)


# --- Function 7: End Ride and Archive ---
def end_ride_and_archive(ride_id, driver_id):
    """
    Moves the completed ride and confirmed bookings to the history table.
    
    Args:
        ride_id (int): The ride_id to end
        driver_id (int): The driver's user_id (for verification)
    
    Returns:
        tuple: (success: bool, message: str)
    """
    try:
        conn = get_db_connection()
        if not conn:
            return (False, "Database connection failed")
        
        cursor = conn.cursor()
        
        # Get ride details and verify driver
        cursor.execute(
            "SELECT driver_id, starting_point, destination_point, departure_time, price_per_seat FROM rides WHERE ride_id = %s",
            (ride_id,)
        )
        ride_data = cursor.fetchone()
        
        if not ride_data:
            cursor.close()
            conn.close()
            return (False, "Ride not found")
        
        ride_driver_id, starting_point, destination_point, departure_time, price_per_seat = ride_data
        
        # Verify the driver owns this ride
        if ride_driver_id != driver_id:
            cursor.close()
            conn.close()
            return (False, "You can only end your own rides")
        
        # Count confirmed riders
        cursor.execute(
            "SELECT COUNT(*) FROM bookings WHERE ride_id = %s AND booking_status = 'Confirmed'",
            (ride_id,)
        )
        total_riders = cursor.fetchone()[0]
        
        # Action 1: Archive ride to RideHistory
        archive_query = """
            INSERT INTO ridehistory 
            (original_ride_id, driver_id, starting_point, destination_point, 
             departure_time, final_price, total_riders)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(archive_query, (
            ride_id, ride_driver_id, starting_point, destination_point,
            departure_time, price_per_seat, total_riders
        ))
        
        # Action 2: Update all Confirmed bookings to Completed
        cursor.execute(
            "UPDATE bookings SET booking_status = 'Completed' WHERE ride_id = %s AND booking_status = 'Confirmed'",
            (ride_id,)
        )
        
        # Also update Pending bookings to Cancelled (since ride is ending)
        cursor.execute(
            "UPDATE bookings SET booking_status = 'Cancelled' WHERE ride_id = %s AND booking_status = 'Pending'",
            (ride_id,)
        )
        
        # Action 3: Delete the ride from active rides
        cursor.execute("DELETE FROM rides WHERE ride_id = %s", (ride_id,))
        
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return (True, f"Ride completed successfully. {total_riders} rider(s) served.")
        
    except mysql.connector.Error as err:
        print(f"❌ Database error in end_ride_and_archive: {err}")
        return (False, f"Database error: {err}")
    except Exception as e:
        print(f"❌ Unexpected error in end_ride_and_archive: {e}")
        return (False, f"Unexpected error: {e}")


# ============================================================================
# FLASK ROUTES FOR RIDE AND BOOKING MANAGEMENT
# ============================================================================

# --- Route: Create New Ride (Driver) ---
@app.route('/driver/create-ride', methods=['GET', 'POST'])
def driver_create_ride():
    if 'user_id' not in session or session.get('user_role', '').lower() != 'driver':
        flash('Access denied! Drivers only.', 'error')
        return redirect(url_for('login'))
    
    driver_id = session['user_id']
    
    if request.method == 'POST':
        car_id = request.form.get('car_id')
        starting_point = request.form.get('starting_point', '').strip()
        destination_point = request.form.get('destination_point', '').strip()
        departure_time = request.form.get('departure_time', '').strip()
        price = request.form.get('price', '').strip()
        notes = request.form.get('notes', '').strip()
        
        # Validation
        if not all([car_id, starting_point, destination_point, departure_time, price]):
            flash('All fields except notes are required!', 'error')
            return redirect(url_for('driver_create_ride'))
        
        try:
            car_id = int(car_id)
            price = float(price)
            # Parse datetime
            from datetime import datetime
            dep_time = datetime.strptime(departure_time, '%Y-%m-%dT%H:%M')
        except (ValueError, TypeError):
            flash('Invalid input format!', 'error')
            return redirect(url_for('driver_create_ride'))
        
        # Create ride
        success, message, ride_id = create_new_ride(
            driver_id, car_id, starting_point, destination_point,
            dep_time, price, notes if notes else None
        )
        
        if success:
            flash(message, 'success')
            return redirect(url_for('driver_dashboard'))
        else:
            flash(message, 'error')
            return redirect(url_for('driver_create_ride'))
    
    # GET: Show form with driver's cars
    try:
        conn = get_db_connection()
        if not conn:
            flash('Database connection failed!', 'error')
            return redirect(url_for('driver_dashboard'))
        
        cursor = conn.cursor()
        cursor.execute(
            "SELECT car_id, make, model, license_plate, seats FROM cars WHERE user_id = %s",
            (driver_id,)
        )
        column_names = [i[0] for i in cursor.description]
        car_records = cursor.fetchall()
        
        cars = []
        for record in car_records:
            cars.append(dict(zip(column_names, record)))
        
        cursor.close()
        conn.close()
        
        if not cars:
            flash('You need to register a car before creating a ride!', 'error')
            return redirect(url_for('driver_dashboard'))
        
        user_name = session.get('user_name', 'Guest')
        user_role = session.get('user_role', 'Unknown')
        
        return render_template('create_ride.html', 
                             user_name=user_name, 
                             user_role=user_role,
                             cars=cars)
    except Exception as e:
        flash(f'Error: {e}', 'error')
        return redirect(url_for('driver_dashboard'))


# --- Route: View All Active Rides (Rider) ---
@app.route('/rider/all-rides')
def rider_all_rides():
    if 'user_id' not in session or session.get('user_role', '').lower() != 'rider':
        flash('Access denied! Riders only.', 'error')
        return redirect(url_for('login'))
    
    success, message, rides = get_all_active_rides()
    
    if not success:
        flash(message, 'error')
        rides = []
    
    user_name = session.get('user_name', 'Guest')
    user_role = session.get('user_role', 'Unknown')
    
    return render_template('rider_all_rides.html',
                         user_name=user_name,
                         user_role=user_role,
                         rides=rides if rides else [])


# --- Route: Request to Join Ride (Rider) ---
@app.route('/rider/request-ride/<int:ride_id>', methods=['POST'])
def rider_request_ride(ride_id):
    if 'user_id' not in session or session.get('user_role', '').lower() != 'rider':
        flash('Access denied! Riders only.', 'error')
        return redirect(url_for('login'))
    
    rider_id = session['user_id']
    
    success, message, booking_id = request_to_join_ride(rider_id, ride_id)
    
    if success:
        flash(message, 'success')
    else:
        flash(message, 'error')
    
    return redirect(url_for('rider_all_rides'))


# --- Route: Driver Manage Ride Requests ---
@app.route('/driver/manage-request/<int:booking_id>/<action>', methods=['POST'])
def driver_manage_booking(booking_id, action):
    if 'user_id' not in session or session.get('user_role', '').lower() != 'driver':
        flash('Access denied! Drivers only.', 'error')
        return redirect(url_for('login'))
    
    driver_id = session['user_id']
    
    success, message = driver_manage_request(booking_id, action, driver_id)
    
    if success:
        flash(message, 'success')
    else:
        flash(message, 'error')
    
    return redirect(url_for('driver_view_ride'))


# --- Route: Driver View Active Ride ---
@app.route('/driver/my-ride')
def driver_view_ride():
    if 'user_id' not in session or session.get('user_role', '').lower() != 'driver':
        flash('Access denied! Drivers only.', 'error')
        return redirect(url_for('login'))
    
    driver_id = session['user_id']
    
    success, message, data = get_driver_active_ride_details(driver_id)
    
    if not success:
        flash(message, 'info')
        data = None
    
    user_name = session.get('user_name', 'Guest')
    user_role = session.get('user_role', 'Unknown')
    
    return render_template('driver_my_ride.html',
                         user_name=user_name,
                         user_role=user_role,
                         ride_data=data)


# --- Route: Rider View Current Ride ---
@app.route('/rider/my-ride')
def rider_view_ride():
    if 'user_id' not in session or session.get('user_role', '').lower() != 'rider':
        flash('Access denied! Riders only.', 'error')
        return redirect(url_for('login'))
    
    rider_id = session['user_id']
    
    success, message, ride_data = get_rider_current_ride(rider_id)
    
    if not success:
        flash(message, 'info')
        ride_data = None
    
    user_name = session.get('user_name', 'Guest')
    user_role = session.get('user_role', 'Unknown')
    
    return render_template('rider_my_ride.html',
                         user_name=user_name,
                         user_role=user_role,
                         ride_data=ride_data)


# --- Route: Driver End Ride ---
@app.route('/driver/end-ride/<int:ride_id>', methods=['POST'])
def driver_end_ride(ride_id):
    if 'user_id' not in session or session.get('user_role', '').lower() != 'driver':
        flash('Access denied! Drivers only.', 'error')
        return redirect(url_for('login'))
    
    driver_id = session['user_id']
    
    success, message = end_ride_and_archive(ride_id, driver_id)
    
    if success:
        flash(message, 'success')
    else:
        flash(message, 'error')
    
    return redirect(url_for('driver_dashboard'))


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=3000)
