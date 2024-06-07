from flask import Blueprint

app_views = Blueprint("app_views", __name__)

# Import all the view modules here
from api.v1.views.status import *
