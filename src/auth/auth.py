"""
Authentication service for secure user authentication.
Uses Argon2id for password hashing and provides recovery mechanisms.
"""

import os
import base64
import sys
import json
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Import configuration and encryption service
from config import config
from src.crypto.encryption import encryption_service

# Import twofa service
from src.auth.twofa import twofa_service


class AuthService:
    """Authentication service for secure user authentication"""
    
    def __init__(self):
        """Initialize the password hasher with Argon2id parameters"""
        self.password_hasher = PasswordHasher(
            time_cost=config.ARGON2_TIME_COST,
            memory_cost=config.ARGON2_MEMORY_COST,
            parallelism=config.ARGON2_PARALLELISM,
            hash_len=config.ARGON2_HASH_LENGTH,
            type=config.ARGON2_TYPE
        )
        self.twofa_service = twofa_service
    
    def hash_master_password(self, master_password):
        """
        Hash the master password using Argon2id
        
        Args:
            master_password (str): The master password to hash
            
        Returns:
            str: The hashed password
        """
        return self.password_hasher.hash(master_password)
    
    def verify_master_password(self, hash_str, master_password):
        """
        Verify the master password against a hash
        
        Args:
            hash_str (str): The stored password hash
            master_password (str): The password to verify
            
        Returns:
            bool: True if password matches
        """
        try:
            self.password_hasher.verify(hash_str, master_password)
            return True
        except VerifyMismatchError:
            return False
        except Exception as e:
            print(f"Error verifying password: {e}")
            return False
    
    def generate_recovery_key(self):
        """
        Generate a random recovery key
        
        Returns:
            str: Base64 encoded recovery key
        """
        recovery_key_bytes = os.urandom(32)
        return base64.b64encode(recovery_key_bytes).decode('utf-8')
    
    def backup_vault_key(self, vault_key, recovery_key):
        """
        Create backup of vault key using recovery key
        
        Args:
            vault_key (bytes): The vault encryption key
            recovery_key (str): The recovery key
            
        Returns:
            dict: Encrypted vault key backup
        """
        # Convert recovery key from base64 to buffer
        recovery_key_buffer = base64.b64decode(recovery_key)
        
        # Encrypt vault key with recovery key
        vault_key_hex = vault_key.hex()
        encrypted, iv, auth_tag = encryption_service.encrypt(recovery_key_buffer, vault_key_hex)
        
        return {
            'encrypted': base64.b64encode(encrypted).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'auth_tag': base64.b64encode(auth_tag).decode('utf-8')
        }
    
    def recover_vault_key(self, encrypted_backup, recovery_key):
        """
        Recover vault key using recovery key
        
        Args:
            encrypted_backup (dict): The encrypted vault key backup
            recovery_key (str): The recovery key
            
        Returns:
            bytes: The recovered vault key
        """
        # Convert recovery key from base64 to buffer
        recovery_key_buffer = base64.b64decode(recovery_key)
        
        # Decode encrypted data from base64
        encrypted = base64.b64decode(encrypted_backup['encrypted'])
        iv = base64.b64decode(encrypted_backup['iv'])
        auth_tag = base64.b64decode(encrypted_backup['auth_tag'])
        
        # Decrypt vault key with recovery key
        decrypted_hex = encryption_service.decrypt(recovery_key_buffer, encrypted, iv, auth_tag)
        return bytes.fromhex(decrypted_hex)
    
    def hash_security_answer(self, answer):
        """
        Generate secure security question answers
        
        Args:
            answer (str): The user's answer
            
        Returns:
            str: Hashed answer
        """
        # Normalize answer (lowercase, trim whitespace)
        normalized_answer = answer.lower().strip()
        return self.hash_master_password(normalized_answer)
    
    def verify_security_answer(self, hashed_answer, provided_answer):
        """
        Verify security question answer
        
        Args:
            hashed_answer (str): The stored hashed answer
            provided_answer (str): The answer to verify
            
        Returns:
            bool: True if answer matches
        """
        # Normalize answer (lowercase, trim whitespace)
        normalized_answer = provided_answer.lower().strip()
        return self.verify_master_password(hashed_answer, normalized_answer)
    
    def setup_totp(self, username, vault_key):
        """
        Set up TOTP two-factor authentication for a user
        
        Args:
            username (str): The username
            vault_key (bytes): The vault encryption key
            
        Returns:
            dict: Setup information including the secret and provisioning URI
        """
        # Generate a new TOTP secret
        secret = self.twofa_service.totp_service.generate_secret()
        
        # Get the provisioning URI for QR code
        uri = self.twofa_service.totp_service.get_provisioning_uri(secret, username)
        
        # Generate QR code
        qr_code = self.twofa_service.totp_service.generate_qr_code(uri)
        
        # Generate backup codes
        backup_codes = self.twofa_service.totp_service.generate_backup_codes()
        
        # Save backup codes
        self.twofa_service.totp_service.save_backup_codes(username, vault_key, backup_codes)
        
        # Return setup information
        return {
            'secret': secret,
            'uri': uri,
            'qr_code': base64.b64encode(qr_code).decode('utf-8'),
            'backup_codes': backup_codes
        }
    
    def verify_totp(self, username, secret, code):
        """
        Verify a TOTP code
        
        Args:
            username (str): The username
            secret (str): The TOTP secret
            code (str): The code to verify
            
        Returns:
            bool: True if code is valid
        """
        return self.twofa_service.totp_service.verify_code(secret, code)
    
    def verify_backup_code(self, username, vault_key, code):
        """
        Verify a backup code
        
        Args:
            username (str): The username
            vault_key (bytes): The vault encryption key
            code (str): The backup code to verify
            
        Returns:
            bool: True if code is valid
        """
        return self.twofa_service.totp_service.verify_backup_code(username, vault_key, code)
    
    def start_webauthn_registration(self, username):
        """
        Start WebAuthn registration process
        
        Args:
            username (str): The username
            
        Returns:
            dict: Registration options for the client
        """
        return self.twofa_service.webauthn_service.start_registration(username)
    
    def verify_webauthn_registration(self, username, credential, client_data):
        """
        Verify WebAuthn registration response
        
        Args:
            username (str): The username
            credential (dict): The credential response from client
            client_data (dict): The client data from response
            
        Returns:
            bool: True if registration is verified
        """
        return self.twofa_service.webauthn_service.verify_registration(username, credential, client_data)
    
    def start_webauthn_authentication(self, username):
        """
        Start WebAuthn authentication process
        
        Args:
            username (str): The username
            
        Returns:
            dict: Authentication options for the client
        """
        return self.twofa_service.webauthn_service.start_authentication(username)
    
    def verify_webauthn_authentication(self, username, credential, client_data):
        """
        Verify WebAuthn authentication response
        
        Args:
            username (str): The username
            credential (dict): The credential response from client
            client_data (dict): The client data from response
            
        Returns:
            bool: True if authentication is verified
        """
        return self.twofa_service.webauthn_service.verify_authentication(username, credential, client_data)
    
    def get_available_twofa_methods(self, username):
        """
        Get available two-factor authentication methods for a user
        
        Args:
            username (str): The username
            
        Returns:
            list: List of available 2FA methods
        """
        return self.twofa_service.get_available_methods(username)


# Singleton instance
auth_service = AuthService() 