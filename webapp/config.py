"""
Configuration settings for BAS Reviewer SaaS
"""
import os
from datetime import timedelta


class Config:
    """Base configuration"""
    # Secret key for session management
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        raise RuntimeError("SECRET_KEY environment variable must be set")

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///bas_reviewer.db')
    # Fix for Railway PostgreSQL URL format
    if SQLALCHEMY_DATABASE_URI.startswith('postgres://'):
        SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI.replace('postgres://', 'postgresql://', 1)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }

    # Session configuration
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)

    # File upload
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB

    # Xero OAuth
    XERO_CLIENT_ID = os.environ.get('XERO_CLIENT_ID')
    XERO_CLIENT_SECRET = os.environ.get('XERO_CLIENT_SECRET')
    XERO_REDIRECT_URI = os.environ.get('XERO_REDIRECT_URI', 'https://bas-reviewer.up.railway.app/callback')
    XERO_SCOPES = 'openid profile email accounting.transactions.read accounting.settings.read offline_access'

    # DeepSeek AI
    DEEPSEEK_API_KEY = os.environ.get('DEEPSEEK_API_KEY')

    # Cloudflare R2
    R2_ACCOUNT_ID = os.environ.get('R2_ACCOUNT_ID')
    R2_ACCESS_KEY_ID = os.environ.get('R2_ACCESS_KEY_ID')
    R2_SECRET_ACCESS_KEY = os.environ.get('R2_SECRET_ACCESS_KEY')
    R2_BUCKET_NAME = os.environ.get('R2_BUCKET_NAME', 'bas-reviewer-uploads')


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    SESSION_COOKIE_SECURE = False  # Allow HTTP in development


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False


# Select config based on environment
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': ProductionConfig
}

def get_config():
    """Get configuration based on FLASK_ENV"""
    env = os.environ.get('FLASK_ENV', 'production')
    return config.get(env, config['default'])
