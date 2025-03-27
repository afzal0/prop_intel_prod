import json
import decimal
from flask import Flask

# Get the original Flask class
original_jsonify = Flask.jsonify

# Create a custom JSON encoder that can handle Decimal objects
class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, decimal.Decimal):
            return float(obj)
        return super(CustomJSONEncoder, self).default(obj)

# Monkey patch the Flask app
def patch_app(app):
    app.json_encoder = CustomJSONEncoder

# Patch the app when imported
import app
patch_app(app.app)