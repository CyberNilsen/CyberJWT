import json
import base64
import hmac
import hashlib
from datetime import datetime
import re

def base64_url_decode(data):
    """Base64 URL-safe decoding with padding correction"""
    
    missing_padding = len(data) % 4
    if missing_padding:
        data += '=' * (4 - missing_padding)
    
    try:
        decoded = base64.urlsafe_b64decode(data)
        return decoded
    except Exception as e:
        raise ValueError(f"Invalid base64 encoding: {str(e)}")

def parse_jwt_structure(token):
    """
    Parse JWT token structure and return components
    
    Args:
        token (str): JWT token
        
    Returns:
        dict: Dictionary containing parsed components
    """
    if not token or not isinstance(token, str):
        raise ValueError("Token must be a non-empty string")
    
    token = token.strip()
    
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT format. Expected 3 parts, got {len(parts)}")
    
    header_b64, payload_b64, signature_b64 = parts
    
    result = {
        'raw_token': token,
        'header_b64': header_b64,
        'payload_b64': payload_b64,
        'signature_b64': signature_b64,
        'header': None,
        'payload': None,
        'signature': None,
        'valid_structure': True,
        'errors': []
    }
    
    try:
        header_decoded = base64_url_decode(header_b64)
        result['header'] = json.loads(header_decoded.decode('utf-8'))
    except Exception as e:
        result['errors'].append(f"Header decode error: {str(e)}")
        result['valid_structure'] = False
    
    try:
        payload_decoded = base64_url_decode(payload_b64)
        result['payload'] = json.loads(payload_decoded.decode('utf-8'))
    except Exception as e:
        result['errors'].append(f"Payload decode error: {str(e)}")
        result['valid_structure'] = False
    
    if signature_b64:
        try:
            result['signature'] = base64_url_decode(signature_b64)
        except Exception as e:
            result['errors'].append(f"Signature decode error: {str(e)}")
    else:
        result['signature'] = b''  
    
    return result

def verify_jwt_signature(token, secret, algorithm=None):
    """
    Verify JWT signature
    
    Args:
        token (str): JWT token
        secret (str): Secret key for verification
        algorithm (str): Expected algorithm (if None, use algorithm from header)
        
    Returns:
        dict: Verification result
    """
    try:
        parsed = parse_jwt_structure(token)
        
        if not parsed['valid_structure']:
            return {
                'valid': False,
                'error': 'Invalid token structure',
                'details': parsed['errors']
            }
        
        header = parsed['header']
        payload = parsed['payload']
        
        token_algorithm = header.get('alg', 'unknown')
        
        if algorithm and algorithm != token_algorithm:
            return {
                'valid': False,
                'error': f"Algorithm mismatch. Expected {algorithm}, got {token_algorithm}"
            }
        
        if token_algorithm == 'none':
            if parsed['signature_b64']:
                return {
                    'valid': False,
                    'error': "Token uses 'none' algorithm but has signature"
                }
            return {
                'valid': True,
                'algorithm': 'none',
                'note': "Token is unsigned (algorithm: none)"
            }
        
        if token_algorithm == 'HS256':
            if not secret:
                return {
                    'valid': False,
                    'error': "Secret key required for HS256 verification"
                }
            
            header_payload = f"{parsed['header_b64']}.{parsed['payload_b64']}"
            expected_signature = hmac.new(
                secret.encode('utf-8'),
                header_payload.encode('utf-8'),
                hashlib.sha256
            ).digest()
            
            if hmac.compare_digest(expected_signature, parsed['signature']):
                return {
                    'valid': True,
                    'algorithm': token_algorithm
                }
            else:
                return {
                    'valid': False,
                    'error': "Signature verification failed"
                }
        
        else:
            return {
                'valid': False,
                'error': f"Unsupported algorithm: {token_algorithm}"
            }
            
    except Exception as e:
        return {
            'valid': False,
            'error': f"Verification error: {str(e)}"
        }

def decode_jwt(token, secret='', verify_signature=True, verify_expiration=True):
    """
    Decode and optionally verify a JWT token
    
    Args:
        token (str): JWT token to decode
        secret (str): Secret key for signature verification
        verify_signature (bool): Whether to verify signature
        verify_expiration (bool): Whether to check expiration
        
    Returns:
        dict: Complete decode result
    """
    try:
        parsed = parse_jwt_structure(token)
        
        result = {
            'token': token,
            'header': parsed['header'],
            'payload': parsed['payload'],
            'signature_b64': parsed['signature_b64'],
            'valid_structure': parsed['valid_structure'],
            'signature_valid': None,
            'expired': None,
            'not_yet_valid': None,
            'errors': parsed['errors'].copy(),
            'warnings': [],
            'claims': {}
        }
        
        if not parsed['valid_structure']:
            return result
        
        if parsed['payload']:
            result['claims'] = analyze_claims(parsed['payload'])
        
        if verify_signature:
            signature_result = verify_jwt_signature(token, secret)
            result['signature_valid'] = signature_result['valid']
            
            if not signature_result['valid']:
                result['errors'].append(signature_result['error'])
            elif 'note' in signature_result:
                result['warnings'].append(signature_result['note'])
        
        if verify_expiration and parsed['payload']:
            expiration_check = check_token_timing(parsed['payload'])
            result.update(expiration_check)
        
        return result
        
    except Exception as e:
        return {
            'token': token,
            'header': None,
            'payload': None,
            'signature_b64': None,
            'valid_structure': False,
            'signature_valid': None,
            'expired': None,
            'not_yet_valid': None,
            'errors': [f"Decode error: {str(e)}"],
            'warnings': [],
            'claims': {}
        }

def analyze_claims(payload):
    """
    Analyze JWT payload claims and provide human-readable information
    
    Args:
        payload (dict): JWT payload
        
    Returns:
        dict: Analyzed claims with descriptions
    """
    standard_claims = {
        'iss': 'Issuer',
        'sub': 'Subject',
        'aud': 'Audience', 
        'exp': 'Expiration Time',
        'nbf': 'Not Before',
        'iat': 'Issued At',
        'jti': 'JWT ID'
    }
    
    claims = {
        'standard': {},
        'custom': {},
        'timestamps': {}
    }
    
    for key, value in payload.items():
        if key in standard_claims:
            claims['standard'][key] = {
                'name': standard_claims[key],
                'value': value,
                'readable': format_claim_value(key, value)
            }
            
            if key in ['exp', 'nbf', 'iat'] and isinstance(value, (int, float)):
                claims['timestamps'][key] = {
                    'timestamp': value,
                    'datetime': datetime.fromtimestamp(value).strftime('%Y-%m-%d %H:%M:%S UTC'),
                    'readable': format_timestamp_relative(value)
                }
        else:
            claims['custom'][key] = value
    
    return claims

def format_claim_value(claim_name, value):
    """Format claim values for human reading"""
    if claim_name in ['exp', 'nbf', 'iat'] and isinstance(value, (int, float)):
        try:
            dt = datetime.fromtimestamp(value)
            return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        except:
            return str(value)
    
    return str(value)

def format_timestamp_relative(timestamp):
    """Format timestamp relative to current time"""
    try:
        now = datetime.utcnow()
        token_time = datetime.fromtimestamp(timestamp)
        diff = token_time - now
        
        if diff.total_seconds() > 0:
            if diff.days > 0:
                return f"in {diff.days} days"
            elif diff.seconds > 3600:
                hours = diff.seconds // 3600
                return f"in {hours} hours"
            elif diff.seconds > 60:
                minutes = diff.seconds // 60
                return f"in {minutes} minutes"
            else:
                return "in less than a minute"
        else:
            diff = now - token_time
            if diff.days > 0:
                return f"{diff.days} days ago"
            elif diff.seconds > 3600:
                hours = diff.seconds // 3600
                return f"{hours} hours ago"
            elif diff.seconds > 60:
                minutes = diff.seconds // 60
                return f"{minutes} minutes ago"
            else:
                return "less than a minute ago"
                
    except Exception:
        return "unknown"

def check_token_timing(payload):
    """
    Check token timing (expiration, not before)
    
    Args:
        payload (dict): JWT payload
        
    Returns:
        dict: Timing check results
    """
    now = datetime.utcnow().timestamp()
    
    result = {
        'expired': False,
        'not_yet_valid': False,
        'timing_errors': []
    }
    
    if 'exp' in payload:
        try:
            exp_time = float(payload['exp'])
            if now > exp_time:
                result['expired'] = True
                result['timing_errors'].append("Token has expired")
        except (ValueError, TypeError):
            result['timing_errors'].append("Invalid expiration time format")
    
    if 'nbf' in payload:
        try:
            nbf_time = float(payload['nbf'])
            if now < nbf_time:
                result['not_yet_valid'] = True
                result['timing_errors'].append("Token is not yet valid")
        except (ValueError, TypeError):
            result['timing_errors'].append("Invalid 'not before' time format")
    
    return result

def format_decode_output(decode_result):
    """
    Format decode result for display in GUI
    
    Args:
        decode_result (dict): Result from decode_jwt function
        
    Returns:
        str: Formatted output string
    """
    output = []
    
    output.append("=== JWT HEADER ===")
    if decode_result['header']:
        output.append(json.dumps(decode_result['header'], indent=2))
    else:
        output.append("Failed to decode header")
    
    output.append("\n=== JWT PAYLOAD ===")
    if decode_result['payload']:
        output.append(json.dumps(decode_result['payload'], indent=2))
    else:
        output.append("Failed to decode payload")
    
    if decode_result['claims']:
        output.append("\n=== CLAIMS ANALYSIS ===")
        
        claims = decode_result['claims']
        
        if claims['standard']:
            output.append("\nStandard Claims:")
            for claim_key, claim_info in claims['standard'].items():
                output.append(f"  {claim_info['name']} ({claim_key}): {claim_info['readable']}")
        
        if claims['custom']:
            output.append("\nCustom Claims:")
            for key, value in claims['custom'].items():
                output.append(f"  {key}: {value}")
        
        if claims['timestamps']:
            output.append("\nTimestamp Details:")
            for ts_key, ts_info in claims['timestamps'].items():
                output.append(f"  {ts_key}: {ts_info['datetime']} ({ts_info['readable']})")
    
    output.append("\n=== VERIFICATION ===")
    
    if decode_result['signature_valid'] is not None:
        if decode_result['signature_valid']:
            output.append("✅ Signature: VALID")
        else:
            output.append("❌ Signature: INVALID")
    else:
        output.append("⚠️  Signature: NOT VERIFIED")
    
    if decode_result['expired'] is not None:
        if decode_result['expired']:
            output.append("❌ Token: EXPIRED")
        else:
            output.append("✅ Token: NOT EXPIRED")
    
    if decode_result['not_yet_valid'] is not None:
        if decode_result['not_yet_valid']:
            output.append("❌ Token: NOT YET VALID")
        else:
            output.append("✅ Token: CURRENTLY VALID")
    
    if decode_result['errors']:
        output.append("\n=== ERRORS ===")
        for error in decode_result['errors']:
            output.append(f"❌ {error}")
    
    if decode_result['warnings']:
        output.append("\n=== WARNINGS ===")
        for warning in decode_result['warnings']:
            output.append(f"⚠️  {warning}")
    
    return "\n".join(output)