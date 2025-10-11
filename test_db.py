import mysql.connector

print("Testing database connection...")

def db_connect(config):
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