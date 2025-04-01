#!/usr/bin/env python3

import os
import sys
from flask import (
    Flask, render_template, request, redirect, url_for, 
    flash, jsonify, session, g, abort
)
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import psycopg2
from psycopg2.extras import RealDictCursor

# About page handler with proper error handling
@app.route('/about')
def about():
    # Initialize stats with default values
    stats = {
        'user_count': 0,
        'property_count': 0,
        'income_total': 0,
        'expense_total': 0,
        'profit_total': 0
    }
    
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get user count - with error handling
            try:
                cur.execute("SELECT COUNT(*) as count FROM propintel.users WHERE is_active = TRUE")
                stats['user_count'] = cur.fetchone()['count']
            except Exception as e:
                print(f"Error counting users: {e}")
                # Create users table if it doesn't exist
                try:
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS propintel.users (
                            user_id SERIAL PRIMARY KEY,
                            username VARCHAR(50) UNIQUE NOT NULL,
                            password_hash VARCHAR(255) NOT NULL,
                            email VARCHAR(100) UNIQUE NOT NULL,
                            full_name VARCHAR(100) NOT NULL,
                            role VARCHAR(20) NOT NULL DEFAULT 'user',
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            last_login TIMESTAMP,
                            is_active BOOLEAN DEFAULT TRUE
                        )
                    """)
                    conn.commit()
                    
                    # Insert admin user if not exists
                    admin_password_hash = generate_password_hash('admin123')
                    cur.execute("""
                        INSERT INTO propintel.users (
                            username, password_hash, email, full_name, role, created_at
                        ) VALUES (
                            'admin', %s, 'admin@propintel.com', 'System Administrator', 'admin', CURRENT_TIMESTAMP
                        ) ON CONFLICT (username) DO NOTHING
                    """, (admin_password_hash,))
                    conn.commit()
                except Exception as create_error:
                    print(f"Error creating users table: {create_error}")
            
            # Get property count - with error handling
            try:
                cur.execute("SELECT COUNT(*) as count FROM propintel.properties")
                stats['property_count'] = cur.fetchone()['count']
            except Exception as e:
                print(f"Error counting properties: {e}")
            
            # Get financial stats - with error handling
            try:
                cur.execute("""
                    SELECT 
                        COALESCE(SUM(total_income), 0) as income_total,
                        COALESCE(SUM(total_expenses), 0) as expense_total,
                        COALESCE(SUM(profit), 0) as profit_total
                    FROM propintel.properties
                """)
                result = cur.fetchone()
                if result:
                    stats['income_total'] = float(result['income_total'])
                    stats['expense_total'] = float(result['expense_total'])
                    stats['profit_total'] = float(result['profit_total'])
            except Exception as e:
                print(f"Error calculating financial stats: {e}")
        
        conn.close()
    except Exception as e:
        print(f"Database error in about page: {e}")
    
    return render_template('about.html', stats=stats)

# Fix for session management in before_request
@app.before_request
def before_request():
    g.user = None
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
            
        # For admin hardcoded login
        if session['user_id'] == 1:
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
                    session.pop('user_id', None)
            conn.close()
        except Exception as e:
            print(f"Error in before_request: {e}")
            # Keep the session but create a fallback user object
            if session.get('user_id') == 1:
                g.user = {
                    'user_id': 1,
                    'username': 'admin',
                    'email': 'admin@propintel.com',
                    'full_name': 'System Administrator',
                    'role': 'admin'
                }
            else:
                # Clear invalid session as a last resort
                session.pop('user_id', None)

# Enhanced login route with better error handling
@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page"""
    # Redirect if already logged in
    if g.user:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = 'remember' in request.form
        
        # Validate inputs
        if not username or not password:
            flash('Username and password are required', 'danger')
            return render_template('login.html')
            
        # Check for guest login
        if username == 'guest':
            session.clear()
            session['user_id'] = 'guest'
            session['is_guest'] = True
            session.permanent = True
            flash('Logged in as guest', 'info')
            return redirect(request.args.get('next') or url_for('index'))
            
        # ADMIN hardcoded login
        if username == 'admin' and password == 'admin123':
            session.clear()
            session['user_id'] = 1  # Admin user ID should be 1
            session.permanent = remember
            flash('Welcome back, System Administrator!', 'success')
            return redirect(request.args.get('next') or url_for('index'))
        
        # Regular login
        try:
            conn = get_db_connection()
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    # Ensure schema exists
                    cur.execute("CREATE SCHEMA IF NOT EXISTS propintel")
                    
                    # Check if users table exists, create if not
                    cur.execute("""
                        SELECT EXISTS (
                            SELECT FROM information_schema.tables 
                            WHERE table_schema = 'propintel' AND table_name = 'users'
                        )
                    """)
                    if not cur.fetchone()[0]:
                        # Create users table
                        cur.execute("""
                            CREATE TABLE propintel.users (
                                user_id SERIAL PRIMARY KEY,
                                username VARCHAR(50) UNIQUE NOT NULL,
                                password_hash VARCHAR(255) NOT NULL,
                                email VARCHAR(100) UNIQUE NOT NULL,
                                full_name VARCHAR(100) NOT NULL,
                                role VARCHAR(20) NOT NULL DEFAULT 'user',
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                last_login TIMESTAMP,
                                is_active BOOLEAN DEFAULT TRUE
                            )
                        """)
                        conn.commit()
                        
                        # Create admin user
                        admin_password_hash = generate_password_hash('admin123')
                        cur.execute("""
                            INSERT INTO propintel.users (
                                username, password_hash, email, full_name, role
                            ) VALUES (
                                'admin', %s, 'admin@propintel.com', 'System Administrator', 'admin'
                            )
                        """, (admin_password_hash,))
                        conn.commit()
                    
                    # Try to get the user
                    cur.execute("""
                        SELECT user_id, username, password_hash, full_name, role, is_active
                        FROM propintel.users 
                        WHERE username = %s
                    """, (username,))
                    user = cur.fetchone()
                    
                    if user:
                        try:
                            # Check password
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
                                return redirect(request.args.get('next') or url_for('index'))
                            else:
                                flash('Invalid password', 'danger')
                        except Exception as pw_error:
                            print(f"Password verification error: {pw_error}")
                            # Hardcoded admin fallback if password check fails
                            if username == 'admin':
                                session.clear()
                                session['user_id'] = 1
                                session.permanent = remember
                                flash('Welcome back, System Administrator! (Backup login)', 'success')
                                return redirect(request.args.get('next') or url_for('index'))
                            flash('Error verifying credentials', 'danger')
                    else:
                        flash('Username not found', 'danger')
            except Exception as e:
                flash(f"Database error: {str(e)}", 'danger')
            finally:
                conn.close()
        except Exception as conn_err:
            flash(f"Connection error: {str(conn_err)}", 'danger')
            # Fallback admin login if database is unreachable
            if username == 'admin' and password == 'admin123':
                session.clear()
                session['user_id'] = 1
                session.permanent = remember
                flash('Welcome back, System Administrator! (Fallback mode)', 'success')
                return redirect(request.args.get('next') or url_for('index'))
    
    return render_template('login.html')