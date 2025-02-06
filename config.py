import os
from decouple import config

# Define the base directory
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Environment-specific setting
FLASK_ENV = config('FLASK_ENV', default='production')


class Config:
    """Base configuration class with default settings."""
    # General application settings
    BASE_VERIFICATION_URL = config('BASE_VERIFICATION_URL', default='http://localhost:5000')

    SECRET_KEY = os.urandom(32)
    GEMINI_API_KEY = config('GEMINI_API_KEY', default='abcdefghijkl123')
    DEEPSK_API_KEY = config('DEEPSK_API_KEY', default='abcdefghijkl123')

    XRapidAPIKey = config('XRapidAPIKey')
    XRapidAPIHost = config('XRapidAPIHost')

    # Database configuration
    SQLALCHEMY_DATABASE_URI = config('DATABASE_URI', default='sqlite:///imdata.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    BCRYPT_LOG_ROUNDS = 13

    # Mail settings
    MAIL_SERVER = config('MAIL_SERVER', default='smtp.gmail.com')
    MAIL_PORT = 465  # Use 587 for TLS or 465 for SSL
    MAIL_DEFAULT_SENDER = config('MAIL_DEFAULT_SENDER', default='noreply@imhoweb.net')
    MAIL_USERNAME = config('MAIL_USERNAME', default='initas.info@gmail.com')
    MAIL_PASSWORD = config('MAIL_PASSWORD')
    #MAIL_DEFAULT_SENDER = 'noreply@imhoweb.net'
    MAIL_USE_TLS = False  # Set to True if your SMTP server requires TLS
    MAIL_USE_SSL = True  # Set to True if your SMTP server requires SSL

    # Flask Sessions
    SESSION_TYPE = 'filesystem'  # Or 'redis', 'memcached', etc.
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour in seconds
    SESSION_COOKIE_SECURE = True  # Only sent over HTTPS
    SESSION_COOKIE_HTTPONLY = True  # JS cannot access the cookie
    SESSION_COOKIE_SAMESITE = 'Lax'  # Mitigate CSRF risks


    # File upload settings
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
    USER_FOLDER = os.path.join(UPLOAD_FOLDER, 'users')  # User profile uploads
    BOOK_FOLDER = os.path.join(UPLOAD_FOLDER, 'books')  # Book-related uploads
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB max file size
    ALLOWED_EXTENSIONS = {'txt', 'png', 'jpg', 'jpeg', 'gif'}

    # Define the logs directory
    LOG_DIR = os.path.join(BASE_DIR, 'logs')
    # Paths for the log files
    TRAFFIC_LOG = os.path.join(LOG_DIR, 'traffic.log')
    ERROR_LOG = os.path.join(LOG_DIR, 'error.log')

    # Ensure the all folders exist
    folders = [UPLOAD_FOLDER, USER_FOLDER, BOOK_FOLDER, LOG_DIR]
    for folder in folders:
        os.makedirs(folder, exist_ok=True)

class DevelopmentConfig(Config):
    """Development-specific settings."""
    DEBUG = True

class ProductionConfig(Config):
    """Production-specific settings."""
    DEBUG = False

# Factory function to return the appropriate configuration
def get_config():
    """Retrieve the configuration class based on the environment."""
    if FLASK_ENV == "development":
        return DevelopmentConfig
    return ProductionConfig