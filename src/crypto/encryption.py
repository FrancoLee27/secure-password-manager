"""
Core encryption service.
Implements AES-256-GCM encryption with zero-knowledge design.
"""

import os
import hashlib
import base64
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from config.config import (
    AES_KEY_LENGTH, 
    AES_IV_LENGTH, 
    AES_AUTH_TAG_LENGTH,
    PBKDF2_ITERATIONS,
    PBKDF2_HASH_TYPE,
    PBKDF2_SALT_LENGTH
)


class EncryptionService:
    """Core encryption service using AES-256-GCM"""
    
    def derive_key(self, password, salt=None, purpose='encryption'):
        """
        Derive a key from a password using PBKDF2
        
        Args:
            password (str): The password to derive key from
            salt (str or bytes, optional): The salt for key derivation, generated if None
            purpose (str): Purpose identifier for the key
            
        Returns:
            bytes or tuple: The derived key, or tuple of (key, salt) if new salt was generated
        """
        # Ensure password is bytes
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        # Generate salt if not provided
        if salt is None:
            salt = os.urandom(PBKDF2_SALT_LENGTH)
            new_salt = True
        else:
            # If salt is provided as base64, decode it
            if isinstance(salt, str):
                try:
                    salt = base64.b64decode(salt)
                except:
                    # If decoding fails, use the bytes directly
                    salt = salt.encode('utf-8')
            new_salt = False
        
        # Add purpose to prevent key reuse for different functions
        if isinstance(purpose, str):
            purpose = purpose.encode('utf-8')
        
        # Derive key using PBKDF2
        key = hashlib.pbkdf2_hmac(
            PBKDF2_HASH_TYPE,
            password + purpose,  # Add purpose to the password
            salt,
            PBKDF2_ITERATIONS,
            AES_KEY_LENGTH
        )
        
        # Return key and salt if new salt was generated
        if new_salt:
            return key, base64.b64encode(salt).decode('utf-8')
        return key
    
    def encrypt(self, key, data):
        """
        Encrypt data using AES-256-GCM
        
        Args:
            key (bytes): Encryption key (must be 32 bytes for AES-256)
            data (str or bytes): Data to encrypt
            
        Returns:
            tuple: (encrypted_data, iv, auth_tag)
        """
        # Check key length
        if len(key) != AES_KEY_LENGTH:
            raise ValueError(f"Key must be {AES_KEY_LENGTH} bytes for AES-256")
        
        # Convert data to bytes if it's a string
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Generate a random initialization vector (IV)
        iv = os.urandom(AES_IV_LENGTH)
        
        # Create AESGCM cipher with the key
        cipher = AESGCM(key)
        
        # Encrypt the data
        # In GCM mode, the auth tag is appended to the ciphertext
        ciphertext_with_tag = cipher.encrypt(iv, data, None)
        
        # Split the ciphertext and authentication tag
        ciphertext = ciphertext_with_tag[:-AES_AUTH_TAG_LENGTH]
        auth_tag = ciphertext_with_tag[-AES_AUTH_TAG_LENGTH:]
        
        return ciphertext, iv, auth_tag
    
    def decrypt(self, key, ciphertext, iv, auth_tag):
        """
        Decrypt data using AES-256-GCM
        
        Args:
            key (bytes): Decryption key
            ciphertext (bytes): Encrypted data
            iv (bytes): Initialization vector
            auth_tag (bytes): Authentication tag
            
        Returns:
            str: Decrypted data as a string
        """
        # Check key length
        if len(key) != AES_KEY_LENGTH:
            raise ValueError(f"Key must be {AES_KEY_LENGTH} bytes for AES-256")
        
        # Ensure all inputs are bytes
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode('utf-8')
        if isinstance(iv, str):
            iv = iv.encode('utf-8')
        if isinstance(auth_tag, str):
            auth_tag = auth_tag.encode('utf-8')
        
        # Reconstruct the full ciphertext with auth tag
        full_ciphertext = ciphertext + auth_tag
        
        # Create AESGCM cipher with the key
        cipher = AESGCM(key)
        
        # Decrypt the data
        # This will also verify the authentication tag
        plaintext = cipher.decrypt(iv, full_ciphertext, None)
        
        # Return the plaintext as a string
        return plaintext.decode('utf-8')
    
    def secure_wipe(self, buffer):
        """
        Securely wipe a buffer from memory by overwriting it
        
        Args:
            buffer (bytearray): The buffer to wipe
            
        Returns:
            None
        """
        # Check if the buffer is a bytearray or bytes object
        if isinstance(buffer, (bytearray, bytes)):
            # If it's bytes, we need to convert to bytearray
            if isinstance(buffer, bytes):
                buffer = bytearray(buffer)
            
            # Overwrite with random data
            for i in range(len(buffer)):
                buffer[i] = 0
        else:
            raise TypeError("Buffer must be a bytearray or bytes object")
    
    def create_vault_key(self, master_password):
        """
        Create a vault key from a master password
        
        Args:
            master_password (str): The master password
            
        Returns:
            tuple: (vault_key, salt)
        """
        return self.derive_key(master_password, purpose='vault_key')


# Singleton instance
encryption_service = EncryptionService() 