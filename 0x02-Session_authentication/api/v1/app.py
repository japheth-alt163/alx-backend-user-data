#!/usr/bin/env python3
"""
Route module for the API
"""
from os import getenv
from api.v1.views import app_views
from flask import Flask, jsonify, abort, request
from flask_cors import CORS

# Initialize Flask app
app = Flask(__name__)

# Register blueprints for API routes
app.register_blueprint(app_views)

# Enable Cross-Origin Resource Sharing (CORS)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})

# Determine authentication type
auth = None
AUTH_TYPE = getenv("AUTH_TYPE")
if AUTH_TYPE == "auth":
    from api.v1.auth.auth import Auth
    auth = Auth()
elif AUTH_TYPE == "basic_auth":
    from api.v1.auth.basic_auth import BasicAuth
    auth = BasicAuth()

# Before Request Filter
@app.before_request
def bef_req():
    """
    Filter each request before it's handled by the proper route
    """
    if auth is None:
        pass
    else:
        excluded = [
            '/api/v1/status/',
            '/api/v1/unauthorized/',
            '/api/v1/forbidden/'
        ]
        if auth.require_auth(request.path, excluded):
            if auth.authorization_header(request) is None:
                abort(401, description="Unauthorized")
            if auth.current_user(request) is None:
                abort(403, description="Forbidden")

# Error Handlers
@app.errorhandler(404)
def not_found(error) -> str:
    """ Not found handler
    """
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(401)
def unauthorized(error) -> str:
    """ Request unauthorized handler
    """
    return jsonify({"error": "Unauthorized"}), 401

@app.errorhandler(403)
def forbidden(error) -> str:
    """ Request unauthorized handler
    """
    return jsonify({"error": "Forbidden"}), 403

# Run the Application
if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)
