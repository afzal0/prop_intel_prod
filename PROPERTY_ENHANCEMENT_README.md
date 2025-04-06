# PropIntel Property Management Enhancements

This update adds several enhancements to the PropIntel property management application:

1. **Property Images**: Add images to property listings
2. **Work Record Images**: Upload images for work records
3. **Expense Images**: Upload receipt images for expense records 
4. **Property Manager**: Add property manager for each property
5. **Expense Categorization**: Auto-categorize expenses as:
   - Wage
   - Project Manager Cost
   - Material
   - Miscellaneous
6. **Automatic Expense Tracking**: Work records automatically create expense records
7. **Modern UI Enhancements**:
   - Fixed navigation bar
   - Modern aesthetic color scheme
   - Improved mobile compatibility
   - Better card design and animations

## Installation Instructions

Follow these steps to implement the enhancements:

### 1. Database Configuration

The scripts are configured to use the following database connection:

```
user = postgres
password = 1234
host = localhost
port = 5432
database = postgres
```

If your database configuration is different, update the DB_CONFIG dictionary in `apply_updates.py` and `app_update.py`.

### 2. Apply Schema Updates

Run the `apply_updates.py` script to create new database fields and image directories:

```bash
python apply_updates.py
```

This will:
- Add necessary fields to the database
- Create required directories for image storage
- Apply categorization to existing expense records

### 3. Update Route Handlers

The file `app_update.py` contains updated route handlers for:
- `new_property`: Add property with image upload
- `new_work`: Add work record with image upload and expense categorization
- `new_expense`: Add expense with receipt upload and categorization
- `property_detail`: View property with images and expense breakdowns

Copy these updated functions into your main `app.py` file.

### 4. Templates

The following templates have been updated:
- `layout.html`: Updated for modern design and mobile compatibility
- `property_form.html`: Added property manager and image upload
- `work_form.html`: Added expense type and image upload
- `expense_form.html`: Added expense category and receipt upload
- `property_detail.html`: Updated to display images and expense categories

### 5. Testing

After implementing all changes:
1. Test adding a new property with an image
2. Test adding work records with expense categories
3. Test adding expense records with receipt images
4. Verify that expense categorization works correctly
5. Check the improved UI on both desktop and mobile devices

## Features Usage

### Property Images
When adding a new property, you can upload an image that will be displayed on the property detail page.

### Work Images
When adding work records, you can upload images of the work performed. These will be displayed in the work tab of the property detail page.

### Expense Categorization
Expenses are automatically categorized based on their description:
- **Wage**: Any expense containing "wage", "salary", or "payment"
- **Project Manager**: Any expense containing "project manager" or "pm"
- **Material**: Any expense containing "material" or "supplies"
- **Miscellaneous**: All other expenses

The expense breakdown chart on the property detail page shows the distribution of expenses across these categories.

### Expense from Work
When a work record is added, a corresponding expense record is automatically created in the appropriate category.

## Technical Details

### New Database Fields
- `propintel.money_out.expense_category`: Categorization of expenses
- `propintel.work.expense_type`: Type of expense for work records
- `propintel.properties.project_manager`: Property manager name

### New Image Storage
Images are stored in the following directories:
- `static/images/properties/`: Property images
- `static/images/work/`: Work record images
- `static/images/receipts/`: Expense receipt images

### New Database Table
- `propintel.property_images`: Stores metadata for all image uploads