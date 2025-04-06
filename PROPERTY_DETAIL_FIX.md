# Property Detail Page Fix

This document provides instructions for fixing the "tuple index out of range" error on the property detail page.

## Diagnosis

The error appears to be in the `property_detail` function in `app.py`. The issue is likely due to one of the following:

1. Accessing a non-existent property in `expense_categories` when the database query doesn't return expected columns
2. Issues with the chart data serialization (trend_labels, income_data, expense_data)
3. Duplicate template filters with the same name (`format_currency`)
4. Missing values being passed to the template

## Fix Options

### Option 1: Replace the property_detail function in app.py

1. Open `app.py` in your editor
2. Find the `property_detail` function
3. Replace it with the more robust version from `property_detail_fix.py`

This is the most direct way to fix the issue.

### Option 2: Use the test application

Run the standalone test application to verify the fix works:

```bash
python test_property_fix.py
```

Then navigate to http://localhost:5001/property/27 to see if the fixed version works.

### Option 3: Apply targeted fixes to app.py

If you prefer to make minimal changes to app.py, apply these key fixes:

1. Fix the expense_categories access:
```python
# Change this:
wage_expense_total=expense_categories['wage_total']

# To this:
wage_expense_total=expense_categories.get('wage_total', 0) or 0
```

2. Fix chart data serialization:
```python
# Add this near the end of the function:
import json
trend_labels_json = json.dumps(trend_labels)
income_data_json = json.dumps(income_data)
expense_data_json = json.dumps(expense_data)

# Then use these in the render_template call:
trend_labels=trend_labels_json,
income_data=income_data_json,
expense_data=expense_data_json,
```

3. Fix the duplicate template filter by removing one of them:
```python
# Keep only one of these in app.py:
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
```

## Testing

After applying the fix, test the property detail page by:

1. Visiting a property detail page directly (/property/27)
2. Navigating to a property from the properties list
3. Testing with various properties to ensure the fix works for all cases

## Debugging

If you need to debug further, use the `debug_property_detail.py` script:

```bash
python debug_property_detail.py 27
```

This will print detailed debug information about each step of the property detail function to help identify where errors occur.