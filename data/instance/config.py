#
#   Any settings you put here will override the default ones from __init__.py
#   Make sure this file is in the ./instance folder.
#
import os

current_path = basedir = os.path.abspath(os.path.dirname(__file__))

SECRET_KEY = "jl8n6#-%l7c7y^%beg6b*4l!0ebzz#7e9*+qx18+r7=#ltklxz"
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(current_path, 'pwcrack.sqlite3')
SQLALCHEMY_TRACK_MODIFICATIONS = False
