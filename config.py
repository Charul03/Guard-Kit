import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-change-me')
SQLALCHEMY_DATABASE_URI = f"sqlite:///{BASE_DIR / 'instance' / 'guardkit.sqlite'}"
SQLALCHEMY_TRACK_MODIFICATIONS = False
