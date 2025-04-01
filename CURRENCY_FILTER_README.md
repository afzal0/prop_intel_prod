# PropIntel Format Currency Filter Fix

This guide explains how to fix the `jinja2.exceptions.TemplateAssertionError: No filter named 'format_currency'` error in PropIntel.

## Problem

The error occurs because a template is using the `format_currency` filter, but this filter is not defined in the Flask application. This filter is commonly used to format numbers as currency (e.g., $1,234.56).

## Quick Fix

You can use one of these methods to fix the issue:

### Option 1: Automatic Patch

1. Run the automatic patch script:
   ```
   python app_filter_patch.py
   ```

2. This script will:
   - Create a backup of your app.py file
   - Add the necessary import for datetime if missing
   - Add the format_currency and format_date filter functions
   - Preserve all other code in your app.py

3. Restart your Flask application for the changes to take effect

### Option 2: Manual Addition

1. Open your `app.py` file

2. Add this import if not already present:
   ```python
   import datetime
   ```

3. Add these filter functions after creating the Flask app (after `app = Flask(__name__)`):
   ```python
   # Format currency filter
   @app.template_filter('format_currency')
   def format_currency_filter(value):
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
   ```

4. Save the file and restart your Flask application

## Using the Filters in Templates

After adding these filters, you can use them in your Jinja2 templates like this:

### Format Currency
```html
<p>Price: {{ item.price|format_currency }}</p>
```

### Format Date
```html
<p>Date: {{ item.date|format_date }}</p>
```

## Troubleshooting

If you still encounter issues after adding the filters:

1. **Check for typos** in the filter names in your templates
2. **Verify** that app.py was properly saved and that Flask was restarted
3. **Look for error messages** in the Flask console output
4. **Check other templates** for similar filter usage

## Additional Information

The `format_currency` filter formats numbers as currency with:
- Dollar sign ($)
- Thousands separators (commas)
- Two decimal places
- Proper handling of None values and conversion errors

The `format_date` filter formats dates in a user-friendly format:
- Converts string dates to datetime objects
- Formats as "Month DD, YYYY" (e.g., "Apr 01, 2025")
- Handles various date input formats