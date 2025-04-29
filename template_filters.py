#!/usr/bin/env python3

'''
Template filters for PropIntel
Add these to your app.py file after creating the Flask app
'''

import datetime
import locale
from flask import current_app as app

# Set locale for currency formatting
try:
    locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
except:
    try:
        locale.setlocale(locale.LC_ALL, 'en_US')
    except:
        # Fallback if locale not available
        pass

# Format currency filter
@app.template_filter('format_currency')
def format_currency_filter(value):
    '''Format a number as currency ($X,XXX.XX)'''
    if value is None:
        return "$0.00"
    try:
        value = float(value)
        return "${:,.2f}".format(value)
    except (ValueError, TypeError):
        return "$0.00"

# Format date filter
@app.template_filter('format_date')
def format_date_filter(value):
    '''Format a date as Month DD, YYYY'''
    if not value:
        return ""
    if isinstance(value, str):
        try:
            value = datetime.datetime.strptime(value, '%Y-%m-%d')
        except ValueError:
            try:
                value = datetime.datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                return value
    
    if isinstance(value, datetime.datetime):
        return value.strftime('%b %d, %Y')
    return str(value)

# Format percent filter
@app.template_filter('format_percent')
def format_percent_filter(value):
    '''Format a number as percentage (X.XX%)'''
    if value is None:
        return "0.00%"
    try:
        value = float(value) * 100  # Convert decimal to percentage
        return "{:.2f}%".format(value)
    except (ValueError, TypeError):
        return "0.00%"

# Safe division filter (avoid divide by zero)
@app.template_filter('safe_divide')
def safe_divide_filter(numerator, denominator):
    '''Safely divide two numbers, avoiding divide by zero'''
    try:
        if denominator == 0:
            return 0
        return numerator / denominator
    except (ValueError, TypeError):
        return 0
