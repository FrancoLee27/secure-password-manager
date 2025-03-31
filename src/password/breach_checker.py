"""
Password breach checker.
Checks if passwords have been exposed in data breaches.
Uses a zero-knowledge approach to maintain privacy.
"""

import hashlib
import requests
import sys
import os

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from config.config import HIBP_API_URL, HIBP_USER_AGENT


class BreachChecker:
    """Checks passwords against known data breaches securely"""
    
    def __init__(self):
        """Initialize breach checker"""
        self.api_url = HIBP_API_URL
        self.user_agent = HIBP_USER_AGENT
        self.cache = {}  # Simple in-memory cache
    
    def check_password(self, password, use_cache=True):
        """
        Check if a password has been exposed in known data breaches
        Uses the k-anonymity model from Have I Been Pwned
        
        Args:
            password (str): Password to check
            use_cache (bool): Whether to use the cache
            
        Returns:
            dict: Result of the check
        """
        try:
            # Convert empty passwords to a string to avoid errors
            if not password:
                return {
                    'compromised': False,
                    'count': 0,
                    'message': 'Empty password not checked'
                }
            
            # Create a SHA-1 hash of the password
            password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            
            # Check cache first if enabled
            if use_cache and password_hash in self.cache:
                return self.cache[password_hash]
            
            # Use the first 5 characters as the prefix
            prefix = password_hash[:5]
            suffix = password_hash[5:]
            
            # Make API request
            response = self._make_api_request(prefix)
            
            # Parse response
            result = self._parse_response(response, suffix)
            
            # Cache result
            if use_cache:
                self.cache[password_hash] = result
            
            return result
        except Exception as e:
            # Fail gracefully - always assume password is safe if service fails
            return {
                'compromised': False,
                'count': 0,
                'message': f'Error checking password: {str(e)}'
            }
    
    def generate_breach_notification(self, result):
        """
        Generate a human-readable notification about the breach check result
        
        Args:
            result (dict): Result from check_password
            
        Returns:
            str: Human-readable notification
        """
        if 'status' in result and result['status'] == 'error':
            return f"Unable to check breach status: {result.get('message', 'Unknown error')}"
        
        if result.get('compromised'):
            count = result.get('count', 0)
            if count == 1:
                return "⚠️ WARNING: This password has been exposed in a data breach!"
            else:
                return f"⚠️ WARNING: This password has been found in {count} data breaches!"
        else:
            return "✅ Not found in known data breaches."
    
    def _make_api_request(self, prefix):
        """
        Make an API request to the breach checking service
        
        Args:
            prefix (str): The hash prefix to check
            
        Returns:
            str: The API response
        """
        headers = {
            'User-Agent': self.user_agent
        }
        
        url = f"{self.api_url}/{prefix}"
        
        try:
            response = requests.get(url, headers=headers, timeout=5)
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            raise Exception(f"API request failed: {str(e)}")
    
    def _parse_response(self, response, suffix):
        """
        Parse the API response to check if the password suffix is present
        
        Args:
            response (str): The API response
            suffix (str): The hash suffix to look for
            
        Returns:
            dict: The result of the check
        """
        lines = response.splitlines()
        
        for line in lines:
            parts = line.split(':')
            if len(parts) == 2:
                found_suffix = parts[0].strip()
                count = int(parts[1].strip())
                
                if found_suffix == suffix:
                    return {
                        'compromised': True,
                        'count': count,
                        'message': f'This password has been exposed in {count} data breaches'
                    }
        
        return {
            'compromised': False,
            'count': 0,
            'message': 'This password was not found in known data breaches'
        }


# Singleton instance
breach_checker = BreachChecker() 