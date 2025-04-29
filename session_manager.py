#!/usr/bin/env python3

'''
Server-side session manager for PropIntel
This is an alternative to Flask's cookie-based sessions, which can be unreliable
'''

import os
import json
import uuid
from datetime import datetime, timedelta
import psycopg2
from psycopg2.extras import RealDictCursor

class DatabaseSessionManager:
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        self.app = app
        
        # Override Flask's session interface
        app.session_interface = DatabaseSessionInterface()
        
        # Cleanup expired sessions periodically
        @app.before_first_request
        def cleanup_sessions():
            try:
                conn = self.get_db_connection()
                with conn.cursor() as cur:
                    cur.execute('''
                        DELETE FROM propintel.sessions 
                        WHERE expires_at < NOW()
                    ''')
                conn.commit()
                conn.close()
            except Exception as e:
                app.logger.error(f"Error cleaning up sessions: {e}")
    
    def get_db_connection(self):
        '''Get a connection to the PostgreSQL database'''
        from db_connect import get_db_config
        
        # Get database connection parameters
        params = get_db_config()
        conn = psycopg2.connect(**params)
        return conn

class ServerSideSession(dict):
    '''Server-side session stored in the database'''
    def __init__(self, session_id=None, user_id=None):
        super().__init__()
        self.session_id = session_id or str(uuid.uuid4())
        self.user_id = user_id
        self.modified = False
        
    def __setitem__(self, key, value):
        self.modified = True
        super().__setitem__(key, value)
    
    def __delitem__(self, key):
        self.modified = True
        super().__delitem__(key)
    
    def clear(self):
        self.modified = True
        super().clear()

class DatabaseSessionInterface:
    '''Session interface that stores sessions in the database'''
    def open_session(self, app, request):
        # Get session ID from cookie
        session_id = request.cookies.get(app.session_cookie_name)
        
        if session_id:
            # Try to load session from database
            try:
                conn = self.get_db_connection()
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute('''
                        SELECT session_id, user_id, data 
                        FROM propintel.sessions 
                        WHERE session_id = %s AND expires_at > NOW()
                    ''', (session_id,))
                    
                    session_data = cur.fetchone()
                    
                    if session_data:
                        # Load session from database
                        session = ServerSideSession(
                            session_id=session_data['session_id'],
                            user_id=session_data['user_id']
                        )
                        
                        # Load data from JSON
                        if session_data['data']:
                            session.update(session_data['data'])
                        
                        # Update last access time
                        cur.execute('''
                            UPDATE propintel.sessions
                            SET updated_at = NOW(),
                                expires_at = NOW() + INTERVAL '30 days'
                            WHERE session_id = %s
                        ''', (session_id,))
                        
                        conn.commit()
                        conn.close()
                        return session
            except Exception as e:
                app.logger.error(f"Error loading session: {e}")
            
        # Create new session if none exists or loading failed
        return ServerSideSession()
    
    def save_session(self, app, session, response):
        domain = self.get_cookie_domain(app)
        
        # Delete session if empty
        if not session:
            try:
                conn = self.get_db_connection()
                with conn.cursor() as cur:
                    cur.execute('''
                        DELETE FROM propintel.sessions 
                        WHERE session_id = %s
                    ''', (session.session_id,))
                conn.commit()
                conn.close()
            except Exception as e:
                app.logger.error(f"Error deleting session: {e}")
            
            if session.session_id and app.session_cookie_name in request.cookies:
                response.delete_cookie(app.session_cookie_name, domain=domain)
            
            return
        
        # Don't save if not modified and already exists
        if not session.modified:
            return
        
        # Save session to database
        try:
            conn = self.get_db_connection()
            with conn.cursor() as cur:
                # Convert session to JSON
                session_data = dict(session)
                
                # Make sure user_id is set
                if 'user_id' in session:
                    session.user_id = session['user_id']
                
                # Use UPSERT to create or update session
                cur.execute('''
                    INSERT INTO propintel.sessions 
                    (session_id, user_id, data, updated_at, expires_at)
                    VALUES (%s, %s, %s, NOW(), NOW() + INTERVAL '30 days')
                    ON CONFLICT (session_id) 
                    DO UPDATE SET
                        user_id = EXCLUDED.user_id,
                        data = EXCLUDED.data,
                        updated_at = EXCLUDED.updated_at,
                        expires_at = EXCLUDED.expires_at
                ''', (
                    session.session_id,
                    session.user_id or 'guest',
                    json.dumps(session_data)
                ))
                
            conn.commit()
            conn.close()
        except Exception as e:
            app.logger.error(f"Error saving session: {e}")
        
        # Set session cookie
        httponly = self.get_cookie_httponly(app)
        secure = self.get_cookie_secure(app)
        expires = self.get_expiration_time(app, session)
        
        response.set_cookie(
            app.session_cookie_name,
            session.session_id,
            expires=expires,
            httponly=httponly,
            domain=domain,
            secure=secure
        )
    
    def get_cookie_domain(self, app):
        return app.config.get('SESSION_COOKIE_DOMAIN')
    
    def get_cookie_httponly(self, app):
        return app.config.get('SESSION_COOKIE_HTTPONLY', True)
    
    def get_cookie_secure(self, app):
        return app.config.get('SESSION_COOKIE_SECURE', False)
    
    def get_expiration_time(self, app, session):
        # 30 days expiration
        return datetime.now() + timedelta(days=30)
    
    def get_db_connection(self):
        '''Get a connection to the PostgreSQL database'''
        from db_connect import get_db_config
        
        # Get database connection parameters
        params = get_db_config()
        conn = psycopg2.connect(**params)
        return conn

# Create an instance of the session manager
session_manager = DatabaseSessionManager()
