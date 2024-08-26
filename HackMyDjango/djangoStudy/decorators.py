from django.shortcuts import redirect
from functools import wraps
# import mysqlclient.connector

def login_required(f):
    @wraps(f)
    def decorated_function(request, *args, **kwargs):
        if not request.COOKIES.get('session_id'):
            return redirect('/login')
        return f(request, *args, **kwargs)
    return decorated_function

