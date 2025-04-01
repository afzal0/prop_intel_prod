#!/usr/bin/env python3

'''
Simple login_required decorator for PropIntel
'''

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            session['next_url'] = request.url
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Simple access control decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.user or g.user.get('role') != 'admin':
            flash('You do not have permission to access this page', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function
