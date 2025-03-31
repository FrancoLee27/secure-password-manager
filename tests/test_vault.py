"""
Tests for the vault manager.
"""

import unittest
import sys
import os
import time
import shutil
from pathlib import Path

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.password.vault import VaultManager
from config.config import DB_DIRECTORY


class TestVaultManager(unittest.TestCase):
    """Test cases for the vault manager"""
    
    def setUp(self):
        """Set up test environment"""
        # Clean up any existing test database
        self.data_dir = Path(DB_DIRECTORY)
        if self.data_dir.exists():
            shutil.rmtree(self.data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Create a fresh vault manager for each test
        self.vault = VaultManager()
    
    def tearDown(self):
        """Clean up after tests"""
        # Close vault manager
        self.vault.close()
        
        # Optional: Clean up database files
        if self.data_dir.exists() and "test" in str(self.data_dir):
            shutil.rmtree(self.data_dir)
    
    def test_create_user(self):
        """Test creating a new user"""
        # Create a user
        result = self.vault.create_user("testuser", "Test@Password123")
        
        # Check result
        self.assertTrue(result['success'])
        self.assertTrue(self.vault.check_lock_status())  # Vault should be unlocked
    
    def test_lock_unlock(self):
        """Test locking and unlocking the vault"""
        # Create a user
        self.vault.create_user("testuser", "Test@Password123")
        
        # Lock the vault
        lock_result = self.vault.lock()
        self.assertTrue(lock_result['success'])
        self.assertFalse(self.vault.check_lock_status())  # Vault should be locked
        
        # Unlock the vault
        unlock_result = self.vault.unlock("Test@Password123")
        self.assertTrue(unlock_result['success'])
        self.assertTrue(self.vault.check_lock_status())  # Vault should be unlocked
    
    def test_auto_lock(self):
        """Test auto-locking functionality"""
        # Create a user
        self.vault.create_user("testuser", "Test@Password123")
        
        # Set a very short auto-lock time
        self.vault.auto_lock_time = 1  # 1 second
        self.vault.last_activity = time.time() - 2  # Activity 2 seconds ago
        
        # Check lock status should trigger auto-lock
        self.assertFalse(self.vault.check_lock_status())  # Should return False as vault is now locked
    
    def test_add_get_password(self):
        """Test adding and retrieving passwords"""
        # Create a user
        self.vault.create_user("testuser", "Test@Password123")
        
        # Add a password
        test_entry = {
            "title": "Test Entry",
            "username": "testuser@example.com",
            "password": "SecretPassword123!",
            "url": "https://example.com",
            "notes": "This is a test entry"
        }
        
        add_result = self.vault.add_password(test_entry)
        self.assertTrue(add_result['success'])
        self.assertIn('entry_id', add_result)
        
        entry_id = add_result['entry_id']
        
        # Get the password
        get_result = self.vault.get_password(entry_id)
        self.assertTrue(get_result['success'])
        self.assertEqual(get_result['entry']['title'], "Test Entry")
        self.assertEqual(get_result['entry']['username'], "testuser@example.com")
        self.assertEqual(get_result['entry']['password'], "SecretPassword123!")
    
    def test_update_password(self):
        """Test updating passwords"""
        # Create a user
        self.vault.create_user("testuser", "Test@Password123")
        
        # Add a password
        test_entry = {
            "title": "Test Entry",
            "username": "testuser@example.com",
            "password": "SecretPassword123!"
        }
        
        add_result = self.vault.add_password(test_entry)
        entry_id = add_result['entry_id']
        
        # Update the password
        updates = {
            "title": "Updated Entry",
            "password": "NewPassword456!"
        }
        
        update_result = self.vault.update_password(entry_id, updates)
        self.assertTrue(update_result['success'])
        
        # Get the updated entry
        get_result = self.vault.get_password(entry_id)
        self.assertEqual(get_result['entry']['title'], "Updated Entry")
        self.assertEqual(get_result['entry']['password'], "NewPassword456!")
        self.assertEqual(get_result['entry']['username'], "testuser@example.com")  # Unchanged
    
    def test_delete_password(self):
        """Test deleting passwords"""
        # Create a user
        self.vault.create_user("testuser", "Test@Password123")
        
        # Add a password
        test_entry = {
            "title": "Test Entry",
            "username": "testuser@example.com",
            "password": "SecretPassword123!"
        }
        
        add_result = self.vault.add_password(test_entry)
        entry_id = add_result['entry_id']
        
        # Delete the password
        delete_result = self.vault.delete_password(entry_id)
        self.assertTrue(delete_result['success'])
        
        # Try to get the deleted entry
        get_result = self.vault.get_password(entry_id)
        self.assertFalse(get_result['success'])
    
    def test_password_generation(self):
        """Test password generation"""
        # Generate a password
        result = self.vault.generate_password({
            'length': 20,
            'include_uppercase': True,
            'include_lowercase': True,
            'include_numbers': True,
            'include_symbols': True
        })
        
        self.assertTrue(result['success'])
        self.assertIsInstance(result['password'], str)
        self.assertEqual(len(result['password']), 20)
        
        # Check that it includes various character types
        password = result['password']
        self.assertTrue(any(c.isupper() for c in password))
        self.assertTrue(any(c.islower() for c in password))
        self.assertTrue(any(c.isdigit() for c in password))
        self.assertTrue(any(not c.isalnum() for c in password))
    
    def test_passphrase_generation(self):
        """Test passphrase generation"""
        # Generate a passphrase
        result = self.vault.generate_passphrase({
            'word_count': 4,
            'capitalize': True,
            'include_number': True,
            'include_symbol': True
        })
        
        self.assertTrue(result['success'])
        self.assertIsInstance(result['passphrase'], str)
        
        # Should have 4 words plus possible number and symbol
        parts = result['passphrase'].split('-')
        self.assertGreaterEqual(len(parts), 4)


if __name__ == "__main__":
    unittest.main() 