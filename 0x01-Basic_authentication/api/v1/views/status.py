#!/usr/bin/env python3

from api.v1.views import app_views
from flask import jsonify

@app_views.route('/api/v1/status', methods=['GET'])
def status():
    return jsonify({"status": "OK"})
