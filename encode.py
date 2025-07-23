import json
import base64
import hmac
import hashlib
from datetime import datetime, timedelta

def base64_url_encode(data):
    """Base64 URL-safe encoding without padding"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    elif isinstance(data, dict):
        data = json.dumps(data, separators=(',', ':')).encode('utf-8')
    
    encoded = base64.urlsafe_b64encode(data).decode('utf-8')
    return encoded.rstrip('=')

def create_signature(header_payload, secret, algorithm='HS256'):
    """Create JWT signature"""
    if algorithm == 'HS256':
        signature = hmac.new(
            secret.encode('utf-8'),
            header_payload.encode('utf-8'),
            hashlib.sha256
        ).digest()
        return base64_url_encode(signature)
    elif algorithm == 'none':
        return ''
    else:
        raise ValueError(f"Algorithm {algorithm} not supported")

def encode_jwt(payload, secret='', algorithm='HS256', extra_headers=None):
    """
    Encode a JWT token
    
    Args:
        payload (dict): JWT payload claims
        secret (str): Secret key for signing
        algorithm (str): Signing algorithm (HS256, none)
        extra_headers (dict): Additional headers to include
    
    Returns:
        str: Complete JWT token
    """
    # Default header
    header = {
        'typ': 'JWT',
        'alg': algorithm
    }
    
    # Add extra headers if provided
    if extra_headers:
        header.update(extra_headers)
    
    # Encode header and payload
    encoded_header = base64_url_encode(header)
    encoded_payload = base64_url_encode(payload)
    
    # Create header.payload string
    header_payload = f"{encoded_header}.{encoded_payload}"
    
    # Create signature
    if algorithm == 'none':
        signature = ''
    else:
        signature = create_signature(header_payload, secret, algorithm)
    
    # Return complete JWT
    if signature:
        return f"{header_payload}.{signature}"
    else:
        return f"{header_payload}."

def create_default_payload(subject='user', issuer='cyberjwt', audience='api', 
                          expiration_hours=24, not_before_minutes=0):
    """Create a default JWT payload with common claims"""
    now = datetime.utcnow()
    
    payload = {
        'iss': issuer,  # Issuer
        'sub': subject,  # Subject
        'aud': audience,  # Audience
        'exp': int((now + timedelta(hours=expiration_hours)).timestamp()),  # Expiration
        'nbf': int((now + timedelta(minutes=not_before_minutes)).timestamp()),  # Not Before
        'iat': int(now.timestamp()),  # Issued At
        'jti': f"jwt-{int(now.timestamp())}"  # JWT ID
    }
    
    return payload

def validate_payload(payload):
    """Basic validation of JWT payload"""
    if not isinstance(payload, dict):
        return False, "Payload must be a dictionary"
    
    # Check for valid JSON serializable content
    try:
        json.dumps(payload)
    except (TypeError, ValueError) as e:
        return False, f"Payload contains non-serializable data: {str(e)}"
    
    return True, "Valid payload"

# Common algorithm options
SUPPORTED_ALGORITHMS = ['HS256', 'none']

# Common header options
COMMON_HEADERS = {
    'typ': 'JWT',
    'cty': 'application/json'
}