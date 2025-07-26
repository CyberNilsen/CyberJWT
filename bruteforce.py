import json
import base64
import hmac
import hashlib
import threading
import time
from datetime import datetime
from decode import parse_jwt_structure, verify_jwt_signature

class JWTBruteforcer:
    def __init__(self):
        self.is_running = False
        self.found_secret = None
        self.attempts = 0
        self.start_time = None
        self.stop_event = threading.Event()
        
    def base64_url_decode(self, data):
        """Base64 URL-safe decoding with padding correction"""
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        
        try:
            decoded = base64.urlsafe_b64decode(data)
            return decoded
        except Exception:
            return None
    
    def verify_secret(self, token, secret):
        """Verify if a secret is correct for the given JWT token"""
        try:
            result = verify_jwt_signature(token, secret)
            return result['valid']
        except Exception:
            return False
    
    def bruteforce_from_wordlist(self, token, wordlist_path, progress_callback=None, result_callback=None):
        """
        Bruteforce JWT secret using a wordlist file
        
        Args:
            token (str): JWT token to crack
            wordlist_path (str): Path to wordlist file
            progress_callback (function): Callback for progress updates
            result_callback (function): Callback for results
        """
        self.is_running = True
        self.found_secret = None
        self.attempts = 0
        self.start_time = time.time()
        self.stop_event.clear()
        
        try:
            parsed = parse_jwt_structure(token)
            if not parsed['valid_structure']:
                if result_callback:
                    result_callback({
                        'success': False,
                        'error': 'Invalid JWT token structure',
                        'details': parsed['errors']
                    })
                return
            
            if parsed['header'] and parsed['header'].get('alg') == 'none':
                if result_callback:
                    result_callback({
                        'success': False,
                        'error': 'Token uses "none" algorithm - no secret to crack'
                    })
                return
            
            if not parsed['signature_b64']:
                if result_callback:
                    result_callback({
                        'success': False,
                        'error': 'Token has no signature to verify'
                    })
                return
            
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if self.stop_event.is_set():
                        break
                    
                    secret = line.strip()
                    if not secret: 
                        continue
                    
                    self.attempts += 1
                    
                    if progress_callback and self.attempts % 100 == 0:
                        elapsed_time = time.time() - self.start_time
                        rate = self.attempts / elapsed_time if elapsed_time > 0 else 0
                        progress_callback({
                            'attempts': self.attempts,
                            'current_secret': secret,
                            'elapsed_time': elapsed_time,
                            'rate': rate,
                            'found': False
                        })
                    
                    if self.verify_secret(token, secret):
                        self.found_secret = secret
                        elapsed_time = time.time() - self.start_time
                        
                        if result_callback:
                            result_callback({
                                'success': True,
                                'secret': secret,
                                'attempts': self.attempts,
                                'elapsed_time': elapsed_time,
                                'rate': self.attempts / elapsed_time if elapsed_time > 0 else 0
                            })
                        
                        self.is_running = False
                        return
            
            elapsed_time = time.time() - self.start_time
            if result_callback:
                result_callback({
                    'success': False,
                    'error': 'Secret not found in wordlist',
                    'attempts': self.attempts,
                    'elapsed_time': elapsed_time,
                    'rate': self.attempts / elapsed_time if elapsed_time > 0 else 0
                })
        
        except FileNotFoundError:
            if result_callback:
                result_callback({
                    'success': False,
                    'error': f'Wordlist file not found: {wordlist_path}'
                })
        except PermissionError:
            if result_callback:
                result_callback({
                    'success': False,
                    'error': f'Permission denied accessing: {wordlist_path}'
                })
        except Exception as e:
            if result_callback:
                result_callback({
                    'success': False,
                    'error': f'Unexpected error: {str(e)}'
                })
        finally:
            self.is_running = False
    
    def bruteforce_common_secrets(self, token, progress_callback=None, result_callback=None):
        """
        Try common/weak secrets first
        
        Args:
            token (str): JWT token to crack
            progress_callback (function): Callback for progress updates
            result_callback (function): Callback for results
        """
        common_secrets = [
            '', 
            'secret',
            'password',
            '123456',
            'admin',
            'test',
            'key',
            'jwt',
            'token',
            'secret123',
            'password123',
            'admin123',
            'qwerty',
            '12345678',
            'abc123',
            'default',
            'changeme',
            'letmein',
            'welcome',
            'guest',
            'root',
            'user',
            'pass',
            'temp',
            'demo',
            'public',
            'private',
            'null',
            'none',
            'empty',
            'blank',
            'your-256-bit-secret',
            'your-secret-key',
            'supersecret',
            'topsecret',
            'confidential',
            'classified',
            'restricted'
        ]
        
        self.is_running = True
        self.found_secret = None
        self.attempts = 0
        self.start_time = time.time()
        self.stop_event.clear()
        
        try:
            parsed = parse_jwt_structure(token)
            if not parsed['valid_structure']:
                if result_callback:
                    result_callback({
                        'success': False,
                        'error': 'Invalid JWT token structure',
                        'details': parsed['errors']
                    })
                return
            
            for secret in common_secrets:
                if self.stop_event.is_set():
                    break
                
                self.attempts += 1
                
                if progress_callback:
                    elapsed_time = time.time() - self.start_time
                    rate = self.attempts / elapsed_time if elapsed_time > 0 else 0
                    progress_callback({
                        'attempts': self.attempts,
                        'current_secret': secret if secret else '(empty)',
                        'elapsed_time': elapsed_time,
                        'rate': rate,
                        'found': False
                    })
                
                if self.verify_secret(token, secret):
                    self.found_secret = secret
                    elapsed_time = time.time() - self.start_time
                    
                    if result_callback:
                        result_callback({
                            'success': True,
                            'secret': secret if secret else '(empty secret)',
                            'attempts': self.attempts,
                            'elapsed_time': elapsed_time,
                            'rate': self.attempts / elapsed_time if elapsed_time > 0 else 0
                        })
                    
                    self.is_running = False
                    return
            
            elapsed_time = time.time() - self.start_time
            if result_callback:
                result_callback({
                    'success': False,
                    'error': 'Secret not found in common secrets list',
                    'attempts': self.attempts,
                    'elapsed_time': elapsed_time,
                    'rate': self.attempts / elapsed_time if elapsed_time > 0 else 0
                })
        
        except Exception as e:
            if result_callback:
                result_callback({
                    'success': False,
                    'error': f'Unexpected error: {str(e)}'
                })
        finally:
            self.is_running = False
    
    def stop_bruteforce(self):
        """Stop the bruteforce attack"""
        self.stop_event.set()
        self.is_running = False
    
    def get_stats(self):
        """Get current bruteforce statistics"""
        if not self.start_time:
            return {
                'attempts': 0,
                'elapsed_time': 0,
                'rate': 0,
                'is_running': self.is_running
            }
        
        elapsed_time = time.time() - self.start_time
        rate = self.attempts / elapsed_time if elapsed_time > 0 else 0
        
        return {
            'attempts': self.attempts,
            'elapsed_time': elapsed_time,
            'rate': rate,
            'is_running': self.is_running,
            'found_secret': self.found_secret
        }

def format_time(seconds):
    """Format seconds into human readable time"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"

def estimate_wordlist_size(wordlist_path, sample_lines=1000):
    """Estimate wordlist size by sampling"""
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            line_count = 0
            char_count = 0
            for i, line in enumerate(f):
                if i >= sample_lines:
                    break
                line_count += 1
                char_count += len(line)
            
            if line_count == 0:
                return 0
            
            f.seek(0, 2)  
            file_size = f.tell()
            
            avg_line_length = char_count / line_count
            estimated_lines = int(file_size / avg_line_length)
            
            return estimated_lines
    except Exception:
        return 0