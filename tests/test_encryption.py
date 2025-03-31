"""
Tests for the encryption module.
"""

import unittest
import sys
import os
import base64
import json

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.crypto.encryption import encryption_service


class TestEncryption(unittest.TestCase):
    """Test cases for the encryption service"""
    
    def test_key_derivation(self):
        """Test that keys are correctly derived from passwords with custom salt"""
        # Test with custom salt
        password = "test_password"
        salt = base64.b64encode(os.urandom(16)).decode('utf-8')
        
        # Derive key with custom salt
        key1 = encryption_service.derive_key(password, salt)
        key2 = encryption_service.derive_key(password, salt)
        
        # Keys should be identical when using the same salt
        self.assertEqual(key1, key2)
        
        # Keys should be 32 bytes (256 bits) for AES-256
        self.assertEqual(len(key1), 32)
    
    def test_key_derivation_with_purpose(self):
        """Test that keys derived for different purposes are unique"""
        password = "test_password"
        salt = base64.b64encode(os.urandom(16)).decode('utf-8')
        
        # Derive keys with different purposes
        vault_key = encryption_service.derive_key(password, salt, purpose="vault_key")
        auth_key = encryption_service.derive_key(password, salt, purpose="auth")
        
        # Keys should be different for different purposes
        self.assertNotEqual(vault_key, auth_key)
    
    def test_key_derivation_autosalt(self):
        """Test that keys are correctly derived with auto-generated salt"""
        password = "test_password"
        
        # Derive key with auto-generated salt
        key, salt = encryption_service.derive_key(password, generate_salt=True)
        
        # Salt should not be None
        self.assertIsNotNone(salt)
        
        # Key should be 32 bytes (256 bits) for AES-256
        self.assertEqual(len(key), 32)
    
    def test_encryption_decryption(self):
        """Test encryption and decryption of data"""
        # Test data
        plaintext = "This is a secret message."
        
        # Generate a random key
        key = os.urandom(32)  # 32 bytes = 256 bits
        
        # Encrypt the data
        encrypted, iv, auth_tag = encryption_service.encrypt(key, plaintext)
        
        # Decrypt the data
        decrypted = encryption_service.decrypt(key, encrypted, iv, auth_tag)
        
        # The decrypted data should match the original plaintext
        self.assertEqual(plaintext, decrypted)
    
    def test_json_encryption_decryption(self):
        """Test encryption and decryption of JSON data"""
        # Test data (complex JSON object)
        data = {
            "username": "testuser",
            "password": "p@ssw0rd!",
            "websites": ["example.com", "test.org"],
            "details": {
                "email": "test@example.com",
                "age": 30,
                "active": True
            }
        }
        
        # Convert to JSON string
        plaintext = json.dumps(data)
        
        # Generate a random key
        key = os.urandom(32)  # 32 bytes = 256 bits
        
        # Encrypt the data
        encrypted, iv, auth_tag = encryption_service.encrypt(key, plaintext)
        
        # Decrypt the data
        decrypted = encryption_service.decrypt(key, encrypted, iv, auth_tag)
        
        # Parse the JSON to verify it's valid
        decrypted_data = json.loads(decrypted)
        
        # The decrypted data should match the original data
        self.assertEqual(data, decrypted_data)
    
    def test_vault_key_creation(self):
        """Test creation of vault key from master password"""
        # Create vault key
        master_password = "my_secure_master_password"
        vault_key, salt = encryption_service.create_vault_key(master_password)
        
        # Salt should not be None
        self.assertIsNotNone(salt)
        
        # Vault key should be 32 bytes (256 bits)
        self.assertEqual(len(vault_key), 32)
        
        # Test recreation with the same salt
        recreated_key = encryption_service.derive_key(
            master_password, 
            salt, 
            purpose="vault_key"
        )
        
        # Recreated key should match the original vault key
        self.assertEqual(vault_key, recreated_key)
    
    def test_tamper_detection(self):
        """Test detection of tampered data"""
        # Test data
        plaintext = "This is a secret message."
        
        # Generate a random key
        key = os.urandom(32)  # 32 bytes = 256 bits
        
        # Encrypt the data
        encrypted, iv, auth_tag = encryption_service.encrypt(key, plaintext)
        
        # Tamper with the encrypted data
        tampered = bytearray(encrypted)
        tampered[5] ^= 0xFF  # Flip bits in a byte
        
        # Attempt to decrypt the tampered data
        with self.assertRaises(Exception):
            encryption_service.decrypt(key, bytes(tampered), iv, auth_tag)
    
    def test_tamper_detection_auth_tag(self):
        """Test detection of tampered authentication tag"""
        # Test data
        plaintext = "This is a secret message."
        
        # Generate a random key
        key = os.urandom(32)  # 32 bytes = 256 bits
        
        # Encrypt the data
        encrypted, iv, auth_tag = encryption_service.encrypt(key, plaintext)
        
        # Tamper with the authentication tag
        tampered_tag = bytearray(auth_tag)
        tampered_tag[0] ^= 0xFF  # Flip bits in a byte
        
        # Attempt to decrypt with the tampered tag
        with self.assertRaises(Exception):
            encryption_service.decrypt(key, encrypted, iv, bytes(tampered_tag))
    
    def test_wrong_key(self):
        """Test decryption with wrong key"""
        # Test data
        plaintext = "This is a secret message."
        
        # Generate a random key
        key = os.urandom(32)  # 32 bytes = 256 bits
        
        # Encrypt the data
        encrypted, iv, auth_tag = encryption_service.encrypt(key, plaintext)
        
        # Generate a different key
        wrong_key = os.urandom(32)  # 32 bytes = 256 bits
        
        # Attempt to decrypt with the wrong key
        with self.assertRaises(Exception):
            encryption_service.decrypt(wrong_key, encrypted, iv, auth_tag)


if __name__ == "__main__":
    unittest.main() 