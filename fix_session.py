#!/usr/bin/env python3

"""
Session fix and admin dashboard addition for PropIntel
"""

import os
import psycopg2
from psycopg2.extras import RealDictCursor
import configparser
import hashlib

def get_db_config():
    """Get database configuration from config file or environment variables"""
    # Check for DATABASE_URL environment variable
    database_url = os.environ.get('DATABASE_URL')
    
    if database_url:
        # Parse DATABASE_URL (for Heroku)
        from urllib.parse import urlparse
        
        if database_url.startswith('postgres://'):
            database_url = database_url.replace('postgres://', 'postgresql://', 1)
            
        result = urlparse(database_url)
        
        return {
            "user": result.username,
            "password": result.password,
            "host": result.hostname,
            "port": result.port or 5432,
            "database": result.path[1:],
        }
    else:
        # Try to read from config file
        config = configparser.ConfigParser()
        
        # Default connection parameters
        default_params = {
            "user": "postgres",
            "password": "postgres",
            "host": "localhost",
            "port": 5432,
            "database": "postgres",
        }
        
        if os.path.exists('db_config.ini'):
            try:
                config.read('db_config.ini')
                if 'database' in config:
                    return {
                        "user": config['database'].get('user', default_params['user']),
                        "password": config['database'].get('password', default_params['password']),
                        "host": config['database'].get('host', default_params['host']),
                        "port": int(config['database'].get('port', default_params['port'])),
                        "database": config['database'].get('database', default_params['database']),
                    }
            except Exception as e:
                print(f"Error reading config file: {e}. Using default parameters.")
        
        return default_params

def fix_session():
    """Fix session and add admin dashboard"""
    print("PropIntel Session Fix and Admin Dashboard")
    print("=========================================")
    
    # Get database connection parameters
    try:
        params = get_db_config()
        print(f"Using database: {params['host']}:{params['port']}/{params['database']}")
    except Exception as e:
        print(f"Error loading database configuration: {e}")
        return False

    try:
        # Connect to database
        print("\nConnecting to database...")
        conn = psycopg2.connect(**params)
        conn.autocommit = True
        cur = conn.cursor()
        
        # Create session table to store sessions server-side
        print("Creating session table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS propintel.sessions (
                session_id VARCHAR(255) PRIMARY KEY,
                user_id INTEGER REFERENCES propintel.users(user_id),
                data JSONB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP
            )
        """)
        
        # Create secret key for session encryption
        secret_key_path = "secret_key.txt"
        if not os.path.exists(secret_key_path):
            print("Generating new secret key...")
            secret_key = hashlib.sha256(os.urandom(32)).hexdigest()
            with open(secret_key_path, "w") as f:
                f.write(secret_key)
            print(f"Secret key stored in {secret_key_path}")
        else:
            print(f"Using existing secret key from {secret_key_path}")
        
        # Create admin dashboard templates directory
        templates_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
        admin_dir = os.path.join(templates_dir, 'admin')
        
        if not os.path.exists(admin_dir):
            print(f"Creating admin templates directory: {admin_dir}")
            os.makedirs(admin_dir)
        
        # Create admin dashboard template
        admin_dashboard_path = os.path.join(admin_dir, 'dashboard.html')
        print(f"Creating admin dashboard template: {admin_dashboard_path}")
        
        with open(admin_dashboard_path, 'w') as f:
            f.write("""{% extends "layout.html" %}
{% block title %}Admin Dashboard - PropIntel{% endblock %}

{% block content %}
<div class="container mt-4">
    <h1 class="mb-4">Admin Dashboard</h1>
    
    <div class="row">
        <div class="col-md-3 mb-4">
            <div class="list-group">
                <a href="{{ url_for('admin_dashboard') }}" class="list-group-item list-group-item-action active">
                    <i class="fas fa-tachometer-alt me-2"></i> Dashboard
                </a>
                <a href="{{ url_for('admin_users') }}" class="list-group-item list-group-item-action">
                    <i class="fas fa-users me-2"></i> Manage Users
                </a>
                <a href="{{ url_for('admin_properties') }}" class="list-group-item list-group-item-action">
                    <i class="fas fa-building me-2"></i> All Properties
                </a>
                <a href="{{ url_for('admin_settings') }}" class="list-group-item list-group-item-action">
                    <i class="fas fa-cogs me-2"></i> System Settings
                </a>
            </div>
        </div>
        
        <div class="col-md-9">
            <div class="row">
                <div class="col-md-4 mb-4">
                    <div class="card bg-primary text-white">
                        <div class="card-body">
                            <h5 class="card-title">Total Users</h5>
                            <h2 class="display-4">{{ user_count }}</h2>
                            <p class="card-text">Active users in the system</p>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-4 mb-4">
                    <div class="card bg-success text-white">
                        <div class="card-body">
                            <h5 class="card-title">Properties</h5>
                            <h2 class="display-4">{{ property_count }}</h2>
                            <p class="card-text">Properties in the system</p>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-4 mb-4">
                    <div class="card bg-info text-white">
                        <div class="card-body">
                            <h5 class="card-title">Total Value</h5>
                            <h2 class="display-4">${{ '{:,.0f}'.format(total_value) }}</h2>
                            <p class="card-text">Total property value</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0">Recent Activity</h5>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>User</th>
                                    <th>Action</th>
                                    <th>Details</th>
                                    <th>Date</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for log in recent_logs %}
                                <tr>
                                    <td>{{ log.username }}</td>
                                    <td>{{ log.action_type }}</td>
                                    <td>{{ log.details }}</td>
                                    <td>{{ log.created_at.strftime('%Y-%m-%d %H:%M') }}</td>
                                </tr>
                                {% else %}
                                <tr>
                                    <td colspan="4" class="text-center">No recent activity</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}""")
        
        # Create admin users management template
        admin_users_path = os.path.join(admin_dir, 'users.html')
        print(f"Creating admin users template: {admin_users_path}")
        
        with open(admin_users_path, 'w') as f:
            f.write("""{% extends "layout.html" %}
{% block title %}Manage Users - PropIntel{% endblock %}

{% block content %}
<div class="container mt-4">
    <h1 class="mb-4">Manage Users</h1>
    
    <div class="row">
        <div class="col-md-3 mb-4">
            <div class="list-group">
                <a href="{{ url_for('admin_dashboard') }}" class="list-group-item list-group-item-action">
                    <i class="fas fa-tachometer-alt me-2"></i> Dashboard
                </a>
                <a href="{{ url_for('admin_users') }}" class="list-group-item list-group-item-action active">
                    <i class="fas fa-users me-2"></i> Manage Users
                </a>
                <a href="{{ url_for('admin_properties') }}" class="list-group-item list-group-item-action">
                    <i class="fas fa-building me-2"></i> All Properties
                </a>
                <a href="{{ url_for('admin_settings') }}" class="list-group-item list-group-item-action">
                    <i class="fas fa-cogs me-2"></i> System Settings
                </a>
            </div>
            
            <div class="card mt-4">
                <div class="card-body">
                    <h5 class="card-title">User Actions</h5>
                    <a href="{{ url_for('admin_create_user') }}" class="btn btn-primary btn-sm d-block mb-2">
                        <i class="fas fa-user-plus me-2"></i> Create New User
                    </a>
                    <a href="{{ url_for('admin_export_users') }}" class="btn btn-secondary btn-sm d-block">
                        <i class="fas fa-file-export me-2"></i> Export Users
                    </a>
                </div>
            </div>
        </div>
        
        <div class="col-md-9">
            <div class="card">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h5 class="mb-0">All Users</h5>
                    <div class="input-group" style="max-width: 300px;">
                        <input type="text" id="userSearch" class="form-control" placeholder="Search users...">
                        <button class="btn btn-outline-secondary" type="button">
                            <i class="fas fa-search"></i>
                        </button>
                    </div>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Username</th>
                                    <th>Full Name</th>
                                    <th>Email</th>
                                    <th>Role</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for user in users %}
                                <tr>
                                    <td>{{ user.user_id }}</td>
                                    <td>{{ user.username }}</td>
                                    <td>{{ user.full_name }}</td>
                                    <td>{{ user.email }}</td>
                                    <td>
                                        <span class="badge bg-{{ 'primary' if user.role == 'admin' else 'secondary' }}">
                                            {{ user.role }}
                                        </span>
                                    </td>
                                    <td>
                                        <span class="badge bg-{{ 'success' if user.is_active else 'danger' }}">
                                            {{ 'Active' if user.is_active else 'Inactive' }}
                                        </span>
                                    </td>
                                    <td>
                                        <div class="dropdown">
                                            <button class="btn btn-sm btn-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown">
                                                Actions
                                            </button>
                                            <ul class="dropdown-menu">
                                                <li>
                                                    <a class="dropdown-item" href="{{ url_for('admin_edit_user', user_id=user.user_id) }}">
                                                        <i class="fas fa-edit me-2"></i> Edit
                                                    </a>
                                                </li>
                                                <li>
                                                    <a class="dropdown-item" href="{{ url_for('admin_user_properties', user_id=user.user_id) }}">
                                                        <i class="fas fa-building me-2"></i> View Properties
                                                    </a>
                                                </li>
                                                <li><hr class="dropdown-divider"></li>
                                                {% if user.is_active %}
                                                <li>
                                                    <form action="{{ url_for('admin_deactivate_user', user_id=user.user_id) }}" method="post">
                                                        <button type="submit" class="dropdown-item text-danger">
                                                            <i class="fas fa-user-slash me-2"></i> Deactivate
                                                        </button>
                                                    </form>
                                                </li>
                                                {% else %}
                                                <li>
                                                    <form action="{{ url_for('admin_activate_user', user_id=user.user_id) }}" method="post">
                                                        <button type="submit" class="dropdown-item text-success">
                                                            <i class="fas fa-user-check me-2"></i> Activate
                                                        </button>
                                                    </form>
                                                </li>
                                                {% endif %}
                                            </ul>
                                        </div>
                                    </td>
                                </tr>
                                {% else %}
                                <tr>
                                    <td colspan="7" class="text-center">No users found</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
    document.addEventListener('DOMContentLoaded', function() {
        // Simple client-side search functionality
        const searchInput = document.getElementById('userSearch');
        
        searchInput.addEventListener('keyup', function() {
            const searchTerm = this.value.toLowerCase();
            const rows = document.querySelectorAll('tbody tr');
            
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                if (text.includes(searchTerm)) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        });
    });
</script>
{% endblock %}""")
        
        # Create user creation template
        admin_create_user_path = os.path.join(admin_dir, 'create_user.html')
        print(f"Creating user creation template: {admin_create_user_path}")
        
        with open(admin_create_user_path, 'w') as f:
            f.write("""{% extends "layout.html" %}
{% block title %}Create User - PropIntel{% endblock %}

{% block content %}
<div class="container mt-4">
    <div class="row">
        <div class="col-md-3 mb-4">
            <div class="list-group">
                <a href="{{ url_for('admin_dashboard') }}" class="list-group-item list-group-item-action">
                    <i class="fas fa-tachometer-alt me-2"></i> Dashboard
                </a>
                <a href="{{ url_for('admin_users') }}" class="list-group-item list-group-item-action active">
                    <i class="fas fa-users me-2"></i> Manage Users
                </a>
                <a href="{{ url_for('admin_properties') }}" class="list-group-item list-group-item-action">
                    <i class="fas fa-building me-2"></i> All Properties
                </a>
                <a href="{{ url_for('admin_settings') }}" class="list-group-item list-group-item-action">
                    <i class="fas fa-cogs me-2"></i> System Settings
                </a>
            </div>
        </div>
        
        <div class="col-md-9">
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0">Create New User</h5>
                </div>
                <div class="card-body">
                    <form method="post" action="{{ url_for('admin_create_user') }}">
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="username" class="form-label">Username <span class="text-danger">*</span></label>
                                <input type="text" class="form-control" id="username" name="username" required>
                            </div>
                            <div class="col-md-6">
                                <label for="email" class="form-label">Email <span class="text-danger">*</span></label>
                                <input type="email" class="form-control" id="email" name="email" required>
                            </div>
                        </div>
                        
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="full_name" class="form-label">Full Name <span class="text-danger">*</span></label>
                                <input type="text" class="form-control" id="full_name" name="full_name" required>
                            </div>
                            <div class="col-md-6">
                                <label for="role" class="form-label">Role <span class="text-danger">*</span></label>
                                <select class="form-select" id="role" name="role" required>
                                    <option value="user">User</option>
                                    <option value="manager">Manager</option>
                                    <option value="admin">Admin</option>
                                </select>
                            </div>
                        </div>
                        
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <label for="password" class="form-label">Password <span class="text-danger">*</span></label>
                                <input type="password" class="form-control" id="password" name="password" required>
                                <div class="password-strength mt-2"></div>
                            </div>
                            <div class="col-md-6">
                                <label for="password_confirm" class="form-label">Confirm Password <span class="text-danger">*</span></label>
                                <input type="password" class="form-control" id="password_confirm" name="password_confirm" required>
                            </div>
                        </div>
                        
                        <div class="mb-3 form-check">
                            <input type="checkbox" class="form-check-input" id="is_active" name="is_active" checked>
                            <label class="form-check-label" for="is_active">Account Active</label>
                        </div>
                        
                        <div class="d-flex justify-content-between">
                            <button type="submit" class="btn btn-primary">Create User</button>
                            <a href="{{ url_for('admin_users') }}" class="btn btn-secondary">Cancel</a>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
    document.addEventListener('DOMContentLoaded', function() {
        // Password strength indicator
        const passwordInput = document.getElementById('password');
        const confirmInput = document.getElementById('password_confirm');
        const strengthIndicator = document.querySelector('.password-strength');
        
        passwordInput.addEventListener('input', function() {
            const password = this.value;
            let strength = 0;
            let message = '';
            
            if (password.length >= 8) strength += 1;
            if (password.match(/[a-z]+/)) strength += 1;
            if (password.match(/[A-Z]+/)) strength += 1;
            if (password.match(/[0-9]+/)) strength += 1;
            if (password.match(/[^a-zA-Z0-9]+/)) strength += 1;
            
            switch (strength) {
                case 0:
                case 1:
                    message = '<span class="text-danger">Very Weak</span>';
                    break;
                case 2:
                    message = '<span class="text-warning">Weak</span>';
                    break;
                case 3:
                    message = '<span class="text-info">Medium</span>';
                    break;
                case 4:
                    message = '<span class="text-primary">Strong</span>';
                    break;
                case 5:
                    message = '<span class="text-success">Very Strong</span>';
                    break;
            }
            
            strengthIndicator.innerHTML = message;
        });
        
        // Password confirmation check
        confirmInput.addEventListener('input', function() {
            if (this.value !== passwordInput.value) {
                this.setCustomValidity('Passwords do not match');
            } else {
                this.setCustomValidity('');
            }
        });
    });
</script>
{% endblock %}""")
        
        # Create admin routes python file
        admin_routes_path = "admin_routes.py"
        print(f"Creating admin routes file: {admin_routes_path}")
        
        with open(admin_routes_path, 'w') as f:
            f.write("""#!/usr/bin/env python3

# Admin routes to be added to app.py
# Import this at the top of app.py:
# from werkzeug.security import generate_password_hash, check_password_hash

@app.route('/admin/dashboard')
def admin_dashboard():
    """Admin dashboard"""
    # Only allow admin access
    if not g.user or g.user.get('role') != 'admin':
        flash('You do not have permission to access this page', 'danger')
        return redirect(url_for('index'))
    
    # Initialize stats
    user_count = 0
    property_count = 0
    total_value = 0
    recent_logs = []
    
    # Get stats from database
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get user count
            cur.execute("SELECT COUNT(*) as count FROM propintel.users WHERE is_active = TRUE")
            user_count = cur.fetchone()['count']
            
            # Get property count and total value
            cur.execute("""
                SELECT COUNT(*) as count, COALESCE(SUM(current_value), 0) as total_value 
                FROM propintel.properties
            """)
            result = cur.fetchone()
            property_count = result['count']
            total_value = result['total_value'] or 0
            
            # Get recent logs
            try:
                cur.execute("""
                    SELECT al.*, u.username
                    FROM propintel.audit_log al
                    LEFT JOIN propintel.users u ON al.user_id = u.user_id
                    ORDER BY al.created_at DESC
                    LIMIT 10
                """)
                recent_logs = cur.fetchall() or []
            except Exception as e:
                print(f"Error getting audit logs: {e}")
                # Create audit_log table if it doesn't exist
                try:
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS propintel.audit_log (
                            log_id SERIAL PRIMARY KEY,
                            user_id INTEGER REFERENCES propintel.users(user_id),
                            action_type VARCHAR(50) NOT NULL,
                            table_name VARCHAR(50),
                            record_id INTEGER,
                            details TEXT,
                            ip_address VARCHAR(45),
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """)
                    conn.commit()
                except Exception as create_e:
                    print(f"Error creating audit_log table: {create_e}")
    except Exception as e:
        flash(f"Error loading dashboard: {e}", 'danger')
    finally:
        conn.close()
    
    return render_template(
        'admin/dashboard.html',
        user_count=user_count,
        property_count=property_count,
        total_value=total_value,
        recent_logs=recent_logs
    )

@app.route('/admin/users')
def admin_users():
    """Admin users management"""
    # Only allow admin access
    if not g.user or g.user.get('role') != 'admin':
        flash('You do not have permission to access this page', 'danger')
        return redirect(url_for('index'))
    
    users = []
    
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT user_id, username, email, full_name, role, is_active, created_at
                FROM propintel.users
                ORDER BY user_id
            """)
            users = cur.fetchall() or []
    except Exception as e:
        flash(f"Error loading users: {e}", 'danger')
    finally:
        conn.close()
    
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/create', methods=['GET', 'POST'])
def admin_create_user():
    """Create new user (admin only)"""
    # Only allow admin access
    if not g.user or g.user.get('role') != 'admin':
        flash('You do not have permission to access this page', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username')
        email = request.form.get('email')
        full_name = request.form.get('full_name')
        role = request.form.get('role')
        password = request.form.get('password')
        is_active = 'is_active' in request.form
        
        # Validate inputs
        if not (username and email and full_name and role and password):
            flash('All fields are required', 'danger')
            return render_template('admin/create_user.html')
        
        # Create user in database
        try:
            conn = get_db_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Check if username or email already exists
                cur.execute("SELECT user_id FROM propintel.users WHERE username = %s OR email = %s", 
                            (username, email))
                if cur.fetchone():
                    flash('Username or email already exists', 'danger')
                    conn.close()
                    return render_template('admin/create_user.html')
                
                # Hash password
                password_hash = generate_password_hash(password)
                
                # Insert new user
                cur.execute("""
                    INSERT INTO propintel.users 
                    (username, password_hash, email, full_name, role, is_active)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING user_id
                """, (username, password_hash, email, full_name, role, is_active))
                
                conn.commit()
                new_user_id = cur.fetchone()['user_id']
                
                # Log action
                try:
                    log_action('create_user', 'users', new_user_id, f"Created user: {username}")
                except Exception as log_e:
                    print(f"Error logging action: {log_e}")
                
                flash(f'User {username} created successfully', 'success')
                return redirect(url_for('admin_users'))
        except Exception as e:
            flash(f"Error creating user: {e}", 'danger')
        finally:
            conn.close()
    
    return render_template('admin/create_user.html')

@app.route('/admin/users/<int:user_id>/edit', methods=['GET', 'POST'])
def admin_edit_user(user_id):
    """Edit user (admin only)"""
    # Only allow admin access
    if not g.user or g.user.get('role') != 'admin':
        flash('You do not have permission to access this page', 'danger')
        return redirect(url_for('index'))
    
    user = None
    
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT user_id, username, email, full_name, role, is_active
                FROM propintel.users
                WHERE user_id = %s
            """, (user_id,))
            user = cur.fetchone()
            
            if not user:
                flash('User not found', 'danger')
                conn.close()
                return redirect(url_for('admin_users'))
            
            if request.method == 'POST':
                # Get form data
                email = request.form.get('email')
                full_name = request.form.get('full_name')
                role = request.form.get('role')
                is_active = 'is_active' in request.form
                new_password = request.form.get('password')
                
                # Validate inputs
                if not (email and full_name and role):
                    flash('Email, full name, and role are required', 'danger')
                    return render_template('admin/edit_user.html', user=user)
                
                # Update user
                if new_password:
                    # Update with new password
                    password_hash = generate_password_hash(new_password)
                    cur.execute("""
                        UPDATE propintel.users
                        SET email = %s, full_name = %s, role = %s, is_active = %s, password_hash = %s
                        WHERE user_id = %s
                    """, (email, full_name, role, is_active, password_hash, user_id))
                else:
                    # Update without changing password
                    cur.execute("""
                        UPDATE propintel.users
                        SET email = %s, full_name = %s, role = %s, is_active = %s
                        WHERE user_id = %s
                    """, (email, full_name, role, is_active, user_id))
                
                conn.commit()
                
                # Log action
                try:
                    log_action('update_user', 'users', user_id, f"Updated user: {user['username']}")
                except Exception as log_e:
                    print(f"Error logging action: {log_e}")
                
                flash(f'User {user["username"]} updated successfully', 'success')
                return redirect(url_for('admin_users'))
    except Exception as e:
        flash(f"Error updating user: {e}", 'danger')
    finally:
        conn.close()
    
    return render_template('admin/edit_user.html', user=user)

@app.route('/admin/users/<int:user_id>/activate', methods=['POST'])
def admin_activate_user(user_id):
    """Activate user account (admin only)"""
    # Only allow admin access
    if not g.user or g.user.get('role') != 'admin':
        flash('You do not have permission to access this page', 'danger')
        return redirect(url_for('index'))
    
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                UPDATE propintel.users
                SET is_active = TRUE
                WHERE user_id = %s
                RETURNING username
            """, (user_id,))
            
            result = cur.fetchone()
            if result:
                conn.commit()
                flash(f'User {result["username"]} activated successfully', 'success')
            else:
                flash('User not found', 'danger')
    except Exception as e:
        flash(f"Error activating user: {e}", 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/deactivate', methods=['POST'])
def admin_deactivate_user(user_id):
    """Deactivate user account (admin only)"""
    # Only allow admin access
    if not g.user or g.user.get('role') != 'admin':
        flash('You do not have permission to access this page', 'danger')
        return redirect(url_for('index'))
    
    # Prevent deactivating own account
    if g.user['user_id'] == user_id:
        flash('You cannot deactivate your own account', 'danger')
        return redirect(url_for('admin_users'))
    
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                UPDATE propintel.users
                SET is_active = FALSE
                WHERE user_id = %s
                RETURNING username
            """, (user_id,))
            
            result = cur.fetchone()
            if result:
                conn.commit()
                flash(f'User {result["username"]} deactivated successfully', 'success')
            else:
                flash('User not found', 'danger')
    except Exception as e:
        flash(f"Error deactivating user: {e}", 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('admin_users'))

@app.route('/admin/properties')
def admin_properties():
    """Admin view all properties"""
    # Only allow admin access
    if not g.user or g.user.get('role') != 'admin':
        flash('You do not have permission to access this page', 'danger')
        return redirect(url_for('index'))
    
    # Placeholder - implement similar to admin_users
    flash('Properties management coming soon', 'info')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/settings')
def admin_settings():
    """Admin system settings"""
    # Only allow admin access
    if not g.user or g.user.get('role') != 'admin':
        flash('You do not have permission to access this page', 'danger')
        return redirect(url_for('index'))
    
    # Placeholder - implement system settings
    flash('System settings coming soon', 'info')
    return redirect(url_for('admin_dashboard'))

def log_action(action_type, table_name=None, record_id=None, details=None):
    """Log an action to the audit log"""
    user_id = g.user['user_id'] if g.user and g.user != 'guest' else None
    ip_address = request.remote_addr
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO propintel.audit_log
                (user_id, action_type, table_name, record_id, details, ip_address)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (user_id, action_type, table_name, record_id, details, ip_address))
            conn.commit()
    except Exception as e:
        print(f"Error logging action: {e}")
        # Try to create the table if it doesn't exist
        try:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS propintel.audit_log (
                    log_id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES propintel.users(user_id),
                    action_type VARCHAR(50) NOT NULL,
                    table_name VARCHAR(50),
                    record_id INTEGER,
                    details TEXT,
                    ip_address VARCHAR(45),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            
            # Try again after creating the table
            cur.execute("""
                INSERT INTO propintel.audit_log
                (user_id, action_type, table_name, record_id, details, ip_address)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (user_id, action_type, table_name, record_id, details, ip_address))
            conn.commit()
        except Exception as create_e:
            print(f"Error creating audit_log table: {create_e}")
    finally:
        conn.close()
""")
        
        # Create improved before_request function
        login_fix_path = "login_fix.py"
        print(f"Creating login fix file: {login_fix_path}")
        
        with open(login_fix_path, 'w') as f:
            f.write("""#!/usr/bin/env python3

# Improved before_request and login functions to fix session issues
# Copy these into your app.py file

@app.before_request
def before_request():
    """Load logged in user before each request"""
    g.user = None
    
    # Debug session
    print(f"Session contents: {session}")
    
    if 'user_id' in session:
        # Special handling for guest user
        if session['user_id'] == 'guest':
            g.user = {
                'user_id': 'guest',
                'username': 'guest',
                'email': 'guest@example.com',
                'full_name': 'Guest User',
                'role': 'guest'
            }
            return
        
        # Hardcoded admin for fallback
        if session['user_id'] == 1:
            try:
                # Try database first
                conn = get_db_connection()
                try:
                    with conn.cursor(cursor_factory=RealDictCursor) as cur:
                        cur.execute("""
                            SELECT user_id, username, email, full_name, role 
                            FROM propintel.users 
                            WHERE user_id = 1
                        """)
                        admin_user = cur.fetchone()
                        
                        if admin_user:
                            g.user = admin_user
                            return
                except Exception as db_error:
                    print(f"Database error in before_request: {db_error}")
                finally:
                    conn.close()
            except Exception as conn_error:
                print(f"Connection error in before_request: {conn_error}")
            
            # Fallback if database query fails for admin
            g.user = {
                'user_id': 1,
                'username': 'admin',
                'email': 'admin@propintel.com',
                'full_name': 'System Administrator',
                'role': 'admin'
            }
            return
            
        # Fetch user from database for regular users
        try:
            conn = get_db_connection()
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT user_id, username, email, full_name, role 
                        FROM propintel.users 
                        WHERE user_id = %s AND is_active = TRUE
                    """, (session['user_id'],))
                    user = cur.fetchone()
                    
                    if user:
                        g.user = user
                    else:
                        # Clear invalid session
                        print("User not found or inactive, clearing session")
                        session.pop('user_id', None)
                        session.pop('is_guest', None)
            except Exception as db_error:
                print(f"Database error in before_request: {db_error}")
                # Don't clear session on database error, might just be temp issue
            finally:
                conn.close()
        except Exception as conn_error:
            print(f"Connection error in before_request: {conn_error}")
            # Don't clear session on connection error, might just be temp issue

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page"""
    # Redirect if already logged in
    if g.user:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        remember = 'remember' in request.form
        
        # Validate inputs
        if not username:
            flash('Username is required', 'danger')
            return render_template('login.html')
            
        # Guest login (no password needed)
        if username.lower() == 'guest':
            # Set session
            session.clear()
            session['user_id'] = 'guest'
            session['is_guest'] = True
            session.permanent = True  # Make session last longer
            
            flash('Logged in as guest', 'info')
            next_page = request.args.get('next') or url_for('index')
            print(f"Guest login success, redirecting to: {next_page}")
            return redirect(next_page)
            
        # Admin hardcoded login for testing
        if username.lower() == 'admin' and password == 'admin123':
            # Set session
            session.clear()
            session['user_id'] = 1  # Admin user ID should be 1
            session.permanent = remember
            
            flash('Welcome back, System Administrator!', 'success')
            next_page = request.args.get('next') or url_for('index')
            print(f"Admin login success, redirecting to: {next_page}")
            return redirect(next_page)
        
        # Regular login
        try:
            conn = get_db_connection()
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT user_id, username, password_hash, full_name, role, is_active
                        FROM propintel.users 
                        WHERE username = %s
                    """, (username,))
                    user = cur.fetchone()
                    
                    if user:
                        try:
                            # Check if password hash starts with $2b$ (bcrypt format)
                            if check_password_hash(user['password_hash'], password):
                                if not user['is_active']:
                                    flash('Your account is inactive. Please contact an administrator.', 'warning')
                                    return render_template('login.html')
                                    
                                # Set session
                                session.clear()
                                session['user_id'] = user['user_id']
                                session.permanent = remember
                                
                                # Update last login time
                                try:
                                    cur.execute("""
                                        UPDATE propintel.users 
                                        SET last_login = CURRENT_TIMESTAMP 
                                        WHERE user_id = %s
                                    """, (user['user_id'],))
                                    conn.commit()
                                except Exception as e:
                                    print(f"Error updating last login: {e}")
                                
                                flash(f'Welcome back, {user["full_name"]}!', 'success')
                                next_page = request.args.get('next') or url_for('index')
                                print(f"Regular login success for {username}, redirecting to: {next_page}")
                                return redirect(next_page)
                            else:
                                flash('Invalid password', 'danger')
                        except Exception as pw_error:
                            print(f"Password verification error: {pw_error}")
                            flash('Error verifying credentials', 'danger')
                    else:
                        flash('Username not found', 'danger')
            except Exception as db_error:
                print(f"Database error in login: {db_error}")
                flash('Database error during login', 'danger')
            finally:
                conn.close()
        except Exception as conn_error:
            print(f"Connection error in login: {conn_error}")
            flash('Could not connect to database', 'danger')
    
    return render_template('login.html')

# Add this to your imports at the top of app.py
# from datetime import timedelta

# Add this after creating the Flask app but before any routes
@app.before_first_request
def configure_app():
    # Set permanent session lifetime to 30 days
    app.permanent_session_lifetime = timedelta(days=30)
    
    # Ensure secret key is set
    if not app.secret_key or app.secret_key == 'dev':
        secret_key_path = "secret_key.txt"
        if os.path.exists(secret_key_path):
            with open(secret_key_path, "r") as f:
                app.secret_key = f.read().strip()
        else:
            import hashlib
            app.secret_key = hashlib.sha256(os.urandom(32)).hexdigest()
            with open(secret_key_path, "w") as f:
                f.write(app.secret_key)
""")
        
        cur.close()
        conn.close()
        print("\nSession fix and admin dashboard completed successfully!")
        print("\nTo fix login issues:")
        print("1. Copy the functions from login_fix.py into app.py to replace the existing ones")
        print("2. Copy the admin routes from admin_routes.py to add admin dashboard functionality")
        print("\nAdmin dashboard available at: /admin/dashboard")
        print("Admin credentials:")
        print("Username: admin")
        print("Password: admin123")
        
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    fix_session()