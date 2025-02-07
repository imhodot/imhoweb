import random
import hashlib
from datetime import datetime, timedelta
from flask import current_app, render_template
from flask_mail import Message
from threading import Thread

# In-memory store for verification codes
verification_store = {}

def generate_and_store_code(email, expiry_minutes=1440, purpose=None):
    """Generate and store a 6-digit verification code with expiration and correct purpose."""

    verification_code = f"{random.randint(100000, 999999)}"
    expiration_time = datetime.utcnow() + timedelta(minutes=expiry_minutes)
    verification_store[email] = {
        "code": verification_code,
        "expires_at": expiration_time,
        "purpose": purpose  # Ensure the correct purpose is stored
    }
    #print(f"Code Generated for {purpose}: {verification_code}")
    return verification_code, expiration_time

# Generalized helper to validate verification codes and tokens
def validate_verification(email, code_token, is_token=False, purpose=None):
    if email not in verification_store:
        #print(f"Email {email} not found in verification_store.")
        return False

    stored_data = verification_store[email]

    # Ensure purpose matches before continuing
    if purpose is None or stored_data["purpose"] != purpose:
        print("Purpose mismatch.")
        return False  # Reject mismatched purposes

    # Check expiration
    if datetime.utcnow() > stored_data["expires_at"]:
        print("Code has expired.")
        del verification_store[email]  # Remove expired entry
        return False

    if is_token:
        generated_token = generate_hash(email, stored_data["code"], purpose=purpose)
        if generated_token == code_token:
            del verification_store[email]  # Invalidate token after successful verification
            return True
    else:
        if stored_data["code"] == code_token:
            del verification_store[email]  # Invalidate code after successful verification
            return True

    print("Code/Token mismatch.")
    return False

# Helper to generate a hash for URL verification
def generate_hash(email, code, purpose=None):
    """Generate a hash using email, code, and purpose."""
    secret_key = current_app.config['SECRET_KEY'] # SECRET_KEY from current_app.config
    combined_string = f"{email}{code}{purpose}{secret_key}"  # Include purpose
    hash_object = hashlib.sha256(combined_string.encode())
    return hash_object.hexdigest()


# Helper to create a verification URL
def create_verification_url(email, verification_code, purpose=None):
    verification_hash = generate_hash(email, verification_code, purpose=purpose)
    base_url = current_app.config.get('BASE_VERIFICATION_URL')
    verify_path = "/verify"
    return f"{base_url}{verify_path}?email={email}&verification={verification_hash}&purpose={purpose}"

# Helper to send emails asynchronously
def send_email_async(app_context, message):
    with app_context:  # Use the explicitly passed app context as a context manager
        mail = current_app.extensions['mail']
        mail.send(message)

def send_email(subject, recipients, template_name=None, context=None, sender=None, body=None, html_body=None, cc=None, bcc=None, attachments=None):
    """
    Generic function to send emails asynchronously using templates.

    :param subject: Email subject
    :param recipients: List of recipient email addresses
    :param template_name: Name of the template file (e.g., 'email/verification_email.txt')
    :param context: Dictionary of variables to render in the template
    :param sender: Email sender (defaults to app's default sender)
    :param body: Plain text body of the email (optional, overrides template)
    :param html_body: HTML body of the email (optional, overrides template)
    :param cc: List of CC email addresses (optional)
    :param bcc: List of BCC email addresses (optional)
    :param attachments: List of attachments (optional)
    """
    app_context = current_app.app_context()  # Get the current app context

    # Set the sender if not provided
    if sender is None:
        sender = ('Novela', current_app.config['MAIL_DEFAULT_SENDER'])

    # Assuming the email directory is named 'email'
    EMAIL_DIRECTORY = 'email/'

    # Render the template if provided
    if template_name:
        # Append the email directory to the template name
        template_path = f"{EMAIL_DIRECTORY}{template_name}"
        
        if template_name.endswith(".html"):
            html_body = render_template(template_path, **context) if context else render_template(template_path)
        else:
            body = render_template(template_path, **context) if context else render_template(template_path)

    # Create the email message
    message = Message(
        subject=subject,
        sender=sender,
        recipients=recipients,
        body=body,
        html=html_body,
        cc=cc,
        bcc=bcc
    )

    # Add attachments if provided
    if attachments:
        for attachment in attachments:
            message.attach(*attachment)

    # Send the email asynchronously
    thread = Thread(target=send_email_async, args=(app_context, message))
    thread.start()