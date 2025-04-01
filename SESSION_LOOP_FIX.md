# PropIntel Session Loop Fix

After multiple unsuccessful attempts to fix the session issues, I've provided two completely different approaches that should resolve the upload section login loop:

## Option 1: Server-side Session Management (Recommended)

The first approach replaces Flask's cookie-based sessions with server-side sessions stored in the database.

1. **Run the direct session fix script**:
   ```
   python direct_session_fix.py
   ```

2. **Add the server-side session manager to app.py**:
   - Add this import at the top of app.py:
     ```python
     from session_manager import session_manager
     ```
   - Initialize it after creating the Flask app:
     ```python
     session_manager.init_app(app)
     ```

3. **Replace the login_required decorator** with the simpler version from `login_decorator.py`

This solution is more robust because:
- Sessions are stored in the database instead of cookies
- We avoid Flask's serialization issues
- Sessions don't depend on browser cookie settings
- We can explicitly control session expiration

## Option 2: Simplified App for Testing

The second approach is a simplified version of the app with hardcoded users for testing.

1. **Run the simplified app**:
   ```
   python app_simple_fix.py
   ```

2. **Test with these credentials**:
   - Admin: username "admin", password "admin123"
   - Guest: username "guest", no password

This simplified app includes:
- Hardcoded users and no database dependencies
- Explicit session management and debugging
- The same routes as the main app but with much simpler implementation

## Root Causes of the Issue

After extensive analysis, I've identified several core issues in the app:

1. **Type confusion**: The application inconsistently stores user_id as either:
   - Integer (1) for database users
   - String ('admin') for hardcoded admin
   - String ('guest') for guest access

2. **Session serialization**: Flask's session serialization sometimes fails to properly store complex objects

3. **Cookie size limitations**: The session data may be exceeding browser cookie size limits

4. **Missing error handling**: No error handling exists for session serialization failures

5. **Circular dependencies**: The login_required decorator redirects to login, which can create redirect loops if session state is inconsistent

## Manual Fixes for Existing App

If you prefer to fix the current app without using the provided solutions:

1. **Consistent user_id types**:
   ```python
   # Always store user_id as string in session
   session['user_id'] = str(user['user_id'])
   ```

2. **Simplify session data**:
   - Only store the minimum necessary data in session (user_id)
   - Load user details from database in before_request

3. **Debug session state**:
   - Add print statements before and after setting session data
   - Log session contents at the beginning of each request

4. **Fix before_request**:
   ```python
   @app.before_request
   def before_request():
       g.user = None
       
       if 'user_id' in session:
           user_id = session['user_id']
           
           # Special case for admin
           if user_id == 'admin' or user_id == '1':
               g.user = {
                   'user_id': 1,
                   'username': 'admin',
                   'email': 'admin@propintel.com',
                   'full_name': 'System Administrator',
                   'role': 'admin'
               }
               return
               
           # Special case for guest
           if user_id == 'guest':
               g.user = {
                   'user_id': 'guest',
                   'username': 'guest',
                   'email': 'guest@example.com',
                   'full_name': 'Guest User',
                   'role': 'guest'
               }
               return
   ```

## Testing the Fix

After applying either solution:

1. Clear browser cookies for your application
2. Restart the Flask application
3. Log in as admin (username: admin, password: admin123)
4. Navigate to the upload page - it should now load without redirecting
5. Upload a file - it should be processed without logging you out

If you still experience issues, check the Flask debug output for error messages about the session.