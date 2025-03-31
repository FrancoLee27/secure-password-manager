"""
Two-factor authentication module.
"""

from src.auth.twofa.totp import totp_service
from src.auth.twofa.webauthn import webauthn_service


class TwoFactorAuth:
    """
    Two-factor authentication manager.
    Combines TOTP and WebAuthn services.
    """
    
    def __init__(self):
        """Initialize the two-factor authentication manager"""
        self.totp_service = totp_service
        self.webauthn_service = webauthn_service
    
    def get_available_methods(self, username):
        """
        Get available 2FA methods for a user
        
        Args:
            username (str): The username
            
        Returns:
            list: List of available 2FA methods (totp, webauthn)
        """
        methods = []
        
        # Check TOTP availability
        # This would typically involve checking if the user has set up TOTP
        # For now, we'll always offer TOTP as an option
        methods.append('totp')
        
        # Check WebAuthn availability
        # This involves checking if the user has registered security keys
        credentials = self.webauthn_service._load_credentials(username)
        if credentials and len(credentials) > 0:
            methods.append('webauthn')
        
        return methods


# Singleton instance
twofa_service = TwoFactorAuth() 