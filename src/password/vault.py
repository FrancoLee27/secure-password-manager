"""
Core vault manager for the password manager.
Handles secure storage and management of passwords with encryption.
"""

import os
import json
import time
import uuid
import base64
import sys
from datetime import datetime
from pathlib import Path

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from config.config import (
    MEMORY_WIPE_TIMEOUT, MAX_FAILED_ATTEMPTS, AUTO_LOCK_TIMEOUT, DB_DIRECTORY
)
from src.crypto.encryption import encryption_service
from src.auth.auth import auth_service
from src.storage.storage import StorageService
from src.password.generator import password_generator
from src.password.strength import strength_analyzer
from src.password.breach_checker import breach_checker


class VaultManager:
    """
    Core vault manager for the password manager.
    Handles secure storage and management of passwords with encryption.
    """
    
    def __init__(self):
        """Initialize the vault manager"""
        self.storage = StorageService()
        self.storage.initialize()
        
        self.vault_key = None
        self.auto_lock_time = None
        self.unlocked = False
        self.last_activity = None
        
        # Add auto_lock_timeout attribute for the GUI
        self.auto_lock_timeout = AUTO_LOCK_TIMEOUT
        
        # Try to load session state if it exists
        self._load_session_state()
    
    def _get_session_file_path(self):
        """Get the path to the session file"""
        db_dir = Path(DB_DIRECTORY)
        if not db_dir.exists():
            db_dir.mkdir(parents=True, exist_ok=True)
        
        return db_dir / 'session.dat'
    
    def _get_key_file_path(self):
        """Get the path to the temporary key file"""
        db_dir = Path(DB_DIRECTORY)
        if not db_dir.exists():
            db_dir.mkdir(parents=True, exist_ok=True)
        
        return db_dir / 'key.tmp'
    
    def _save_session_state(self):
        """
        Save session state for auto-resume.
        The session state is encrypted with the vault key.
        """
        if not self.vault_key or not self.unlocked:
            return False
        
        try:
            session_data = {
                'unlocked': self.unlocked,
                'auto_lock_time': self.auto_lock_time,
                'last_activity': time.time()
            }
            
            # Convert to JSON
            session_json = json.dumps(session_data)
            
            # Encrypt session data
            encrypted, iv, auth_tag = encryption_service.encrypt(self.vault_key, session_json)
            
            # Convert binary data to base64 for storage
            encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
            iv_b64 = base64.b64encode(iv).decode('utf-8')
            auth_tag_b64 = base64.b64encode(auth_tag).decode('utf-8')
            
            # Save to file
            with open(self._get_session_file_path(), 'w') as f:
                json.dump({
                    'encrypted': encrypted_b64,
                    'iv': iv_b64,
                    'auth_tag': auth_tag_b64
                }, f)
            
            return True
        except Exception as e:
            print(f"Error saving session state: {str(e)}")
            return False
    
    def _load_session_state(self):
        """
        Load session state if available.
        Returns False if no session state is available or can't be loaded.
        """
        session_path = self._get_session_file_path()
        key_path = self._get_key_file_path()
        
        if not session_path.exists() or not key_path.exists():
            return False
        
        try:
            # Load key
            with open(key_path, 'r') as f:
                key_data = json.load(f)
                key_b64 = key_data.get('key')
                self.vault_key = base64.b64decode(key_b64)
            
            # Load session
            with open(session_path, 'r') as f:
                session_data = json.load(f)
                encrypted_b64 = session_data.get('encrypted')
                iv_b64 = session_data.get('iv')
                auth_tag_b64 = session_data.get('auth_tag')
                
                # Decode from base64
                encrypted = base64.b64decode(encrypted_b64)
                iv = base64.b64decode(iv_b64)
                auth_tag = base64.b64decode(auth_tag_b64)
                
                # Decrypt
                decrypted = encryption_service.decrypt(self.vault_key, encrypted, iv, auth_tag)
                session = json.loads(decrypted)
                
                # Check if session is valid and not expired
                self.unlocked = session.get('unlocked', False)
                self.auto_lock_time = session.get('auto_lock_time', AUTO_LOCK_TIMEOUT)
                self.last_activity = session.get('last_activity', time.time())
                
                # Check if session is expired
                if time.time() - self.last_activity > self.auto_lock_time:
                    self.lock()
                    return False
                
                # Set vault key in storage
                self.storage.set_vault_key(self.vault_key)
                
                return True
        except Exception as e:
            print(f"Error loading session state: {str(e)}")
            self.lock()
            return False
    
    def _remove_session_files(self):
        """Remove session files for security"""
        try:
            session_path = self._get_session_file_path()
            key_path = self._get_key_file_path()
            
            if session_path.exists():
                os.remove(session_path)
            if key_path.exists():
                os.remove(key_path)
                
            return True
        except Exception as e:
            print(f"Error removing session files: {str(e)}")
            return False
    
    def create_user(self, username, master_password):
        """
        Create a new user and initialize the vault
        
        Args:
            username (str): Username for the new user
            master_password (str): Master password
            
        Returns:
            dict: Result of the operation
        """
        try:
            # Check if user already exists
            user = self.storage.get_user()
            if user:
                return {
                    'success': False,
                    'message': 'User already exists'
                }
            
            # Create vault key from master password
            vault_key, salt = encryption_service.create_vault_key(master_password)
            
            # Hash master password
            hashed_password = auth_service.hash_master_password(master_password)
            
            # Create user data
            user_data = {
                'username': username,
                'vault_key_salt': salt,
                'created_at': datetime.now().isoformat()
            }
            
            # Save user
            result = self.storage.save_user(user_data)
            if not result['success']:
                return result
            
            # Set the vault key and mark as unlocked
            self.vault_key = vault_key
            self.storage.set_vault_key(vault_key)
            self.unlocked = True
            self.last_activity = time.time()
            self.auto_lock_time = AUTO_LOCK_TIMEOUT
            
            # Save session state and temp key file
            self._save_session_state()
            
            # Save key temporarily (will be removed on lock)
            with open(self._get_key_file_path(), 'w') as f:
                json.dump({
                    'key': base64.b64encode(vault_key).decode('utf-8')
                }, f)
            
            return {
                'success': True,
                'message': 'User created and vault unlocked'
            }
        except Exception as e:
            return {
                'success': False,
                'message': str(e)
            }
    
    def unlock(self, master_password, auto_lock_seconds=AUTO_LOCK_TIMEOUT):
        """
        Unlock the vault with the master password
        
        Args:
            master_password (str): Master password
            auto_lock_seconds (int): Time in seconds for auto-lock
            
        Returns:
            dict: Result of the operation
        """
        try:
            # Check lock status
            if self.unlocked and self.vault_key:
                # Already unlocked
                self.last_activity = time.time()
                self.auto_lock_time = auto_lock_seconds
                self._save_session_state()
                
                return {
                    'success': True,
                    'message': 'Vault already unlocked'
                }
            
            # Get user data
            user = self.storage.get_user()
            if not user:
                return {
                    'success': False,
                    'message': 'No user exists. Please create a user first.'
                }
            
            # Derive key from master password
            vault_key = encryption_service.derive_key(
                master_password,
                user['vault_key_salt'],
                purpose='vault_key'
            )
            
            # Verify by trying to decrypt a vault item
            self.storage.set_vault_key(vault_key)
            items = self.storage.get_all_vault_items()
            
            # If we got here, the key is correct
            self.vault_key = vault_key
            self.unlocked = True
            self.last_activity = time.time()
            self.auto_lock_time = auto_lock_seconds
            
            # Reset failed attempts
            self.storage.update_failed_attempts(increment=False)
            
            # Save session state
            self._save_session_state()
            
            # Save key temporarily (will be removed on lock)
            with open(self._get_key_file_path(), 'w') as f:
                json.dump({
                    'key': base64.b64encode(vault_key).decode('utf-8')
                }, f)
            
            return {
                'success': True,
                'message': 'Vault unlocked successfully'
            }
        except Exception as e:
            # Increment failed attempts
            self.storage.update_failed_attempts(increment=True)
            
            return {
                'success': False,
                'message': f"Failed to unlock vault: {str(e)}"
            }
    
    def lock(self):
        """
        Lock the vault
        
        Returns:
            dict: Result of the operation
        """
        try:
            # Clear the vault key from memory and storage
            if self.vault_key:
                # Convert to bytearray for secure wiping
                key_bytes = bytearray(self.vault_key)
                encryption_service.secure_wipe(key_bytes)
                self.vault_key = None
            
            # Clear in storage
            self.storage.clear_vault_key()
            
            # Reset state
            self.unlocked = False
            self.last_activity = None
            
            # Remove session files
            self._remove_session_files()
            
            return {
                'success': True,
                'message': 'Vault locked successfully'
            }
        except Exception as e:
            return {
                'success': False,
                'message': f"Failed to lock vault: {str(e)}"
            }
    
    def check_lock_status(self):
        """
        Check if the vault should be auto-locked due to inactivity
        
        Returns:
            bool: True if the vault is unlocked, False otherwise
        """
        if not self.unlocked or not self.last_activity:
            return False
        
        # Check if auto-lock timeout has passed
        if time.time() - self.last_activity > self.auto_lock_time:
            self.lock()
            return False
        
        # Update last activity
        self.last_activity = time.time()
        return True
    
    def add_password(self, entry):
        """
        Add a new password entry to the vault
        
        Args:
            entry (dict): Password entry to add
            
        Returns:
            dict: Result of the operation
        """
        # Check if vault is unlocked
        if not self.check_lock_status():
            return {
                'success': False,
                'message': 'Vault is locked'
            }
        
        try:
            # Generate ID if not provided
            if 'id' not in entry:
                entry['id'] = str(uuid.uuid4())
            
            # Add timestamps
            now = datetime.now().isoformat()
            entry['created_at'] = now
            entry['updated_at'] = now
            
            # Analyze password strength
            password = entry.get('password', '')
            strength_result = strength_analyzer.analyze_password(password)
            entry['strength'] = {
                'score': strength_result['score'],
                'level': strength_result['strength'],
                'feedback': strength_result['feedback']
            }
            
            # Check for breaches
            breach_result = breach_checker.check_password(password)
            entry['breach'] = breach_result
            
            # Save entry
            result = self.storage.save_vault_item(entry)
            
            # Log the action
            if result['success']:
                self.storage.log_audit({
                    'action': 'add_password',
                    'item_id': entry['id'],
                    'timestamp': now
                })
            
            # Return with entry ID
            if result['success']:
                result['entry_id'] = entry['id']
            
            # Update session state
            self._save_session_state()
            
            return result
        except Exception as e:
            return {
                'success': False,
                'message': str(e)
            }
    
    def get_password(self, entry_id):
        """
        Get a password entry from the vault
        
        Args:
            entry_id (str): ID of the entry to get
            
        Returns:
            dict: Result of the operation with entry
        """
        # Check if vault is unlocked
        if not self.check_lock_status():
            return {
                'success': False,
                'message': 'Vault is locked'
            }
        
        try:
            # Get all items
            items = self.storage.get_all_vault_items()
            
            # Find the requested item
            entry = None
            for item in items:
                if item.get('id') == entry_id:
                    entry = item
                    break
            
            if not entry:
                return {
                    'success': False,
                    'message': 'Entry not found'
                }
            
            # Log the action
            self.storage.log_audit({
                'action': 'get_password',
                'item_id': entry_id,
                'timestamp': datetime.now().isoformat()
            })
            
            # Update session state
            self._save_session_state()
            
            return {
                'success': True,
                'entry': entry
            }
        except Exception as e:
            return {
                'success': False,
                'message': str(e)
            }
    
    def get_all_passwords(self):
        """
        Get all password entries from the vault
        
        Returns:
            dict: Result of the operation with entries
        """
        # Check if vault is unlocked
        if not self.check_lock_status():
            return {
                'success': False,
                'message': 'Vault is locked'
            }
        
        try:
            # Get all items
            items = self.storage.get_all_vault_items()
            
            # Log the action
            self.storage.log_audit({
                'action': 'list_passwords',
                'timestamp': datetime.now().isoformat()
            })
            
            # Update session state
            self._save_session_state()
            
            return {
                'success': True,
                'entries': items
            }
        except Exception as e:
            return {
                'success': False,
                'message': str(e)
            }
    
    def update_password(self, entry_id, updates):
        """
        Update a password entry in the vault
        
        Args:
            entry_id (str): ID of the entry to update
            updates (dict): Fields to update
            
        Returns:
            dict: Result of the operation
        """
        # Check if vault is unlocked
        if not self.check_lock_status():
            return {
                'success': False,
                'message': 'Vault is locked'
            }
        
        try:
            # Get the entry
            get_result = self.get_password(entry_id)
            if not get_result['success']:
                return get_result
            
            # Get the existing entry
            entry = get_result['entry']
            
            # Apply updates
            for key, value in updates.items():
                if key in ['id', 'created_at']:
                    # Don't allow updating these fields
                    continue
                entry[key] = value
            
            # Update timestamp
            entry['updated_at'] = datetime.now().isoformat()
            
            # If password was updated, analyze strength and check for breaches
            if 'password' in updates:
                password = entry['password']
                
                # Analyze password strength
                strength_result = strength_analyzer.analyze_password(password)
                entry['strength'] = {
                    'score': strength_result['score'],
                    'level': strength_result['strength'],
                    'feedback': strength_result['feedback']
                }
                
                # Check for breaches
                breach_result = breach_checker.check_password(password)
                entry['breach'] = breach_result
            
            # Save the updated entry
            result = self.storage.save_vault_item(entry)
            
            # Log the action
            if result['success']:
                self.storage.log_audit({
                    'action': 'update_password',
                    'item_id': entry_id,
                    'timestamp': datetime.now().isoformat()
                })
            
            # Update session state
            self._save_session_state()
            
            return result
        except Exception as e:
            return {
                'success': False,
                'message': str(e)
            }
    
    def delete_password(self, entry_id):
        """
        Delete a password entry from the vault
        
        Args:
            entry_id (str): ID of the entry to delete
            
        Returns:
            dict: Result of the operation
        """
        # Check if vault is unlocked
        if not self.check_lock_status():
            return {
                'success': False,
                'message': 'Vault is locked'
            }
        
        try:
            # Verify the entry exists
            get_result = self.get_password(entry_id)
            if not get_result['success']:
                return get_result
            
            # Delete the entry
            result = self.storage.delete_vault_item(entry_id)
            
            # Log the action
            if result['success']:
                self.storage.log_audit({
                    'action': 'delete_password',
                    'item_id': entry_id,
                    'timestamp': datetime.now().isoformat()
                })
            
            # Update session state
            self._save_session_state()
            
            return result
        except Exception as e:
            return {
                'success': False,
                'message': str(e)
            }
    
    def generate_password(self, options=None):
        """
        Generate a secure random password
        
        Args:
            options (dict, optional): Options for password generation
                - length (int): Length of the password (default: 16)
                - include_uppercase (bool): Include uppercase letters (default: True)
                - include_lowercase (bool): Include lowercase letters (default: True)
                - include_numbers (bool): Include numbers (default: True)
                - include_symbols (bool): Include symbols (default: True)
                - exclude_similar (bool): Exclude similar characters (default: False)
                - exclude (str): Characters to exclude
                
        Returns:
            dict: Result with generated password
        """
        try:
            # Set default options if not provided
            if options is None:
                options = {}
            
            # Map options to password generator format
            generator_options = {
                'length': options.get('length', 16),
                'uppercase': options.get('include_uppercase', True),
                'lowercase': options.get('include_lowercase', True),
                'numbers': options.get('include_numbers', True),
                'symbols': options.get('include_symbols', True),
                'exclude_similar': options.get('exclude_similar', False),
                'exclude': options.get('exclude', '')
            }
            
            # Generate password
            password = password_generator.generate_password(generator_options)
            
            # Analyze strength
            strength_result = strength_analyzer.analyze_password(password)
            
            # Check for breaches
            breach_result = breach_checker.check_password(password)
            
            # Update session state if vault is unlocked
            if self.check_lock_status():
                self._save_session_state()
            
            return {
                'success': True,
                'password': password,
                'strength': {
                    'score': strength_result['score'],
                    'level': strength_result['strength'],
                    'feedback': strength_result['feedback']
                },
                'breach': breach_result
            }
        except Exception as e:
            return {
                'success': False,
                'message': str(e)
            }
    
    def generate_passphrase(self, options=None):
        """
        Generate a secure passphrase
        
        Args:
            options (dict, optional): Options for passphrase generation
            
        Returns:
            dict: Result with generated passphrase
        """
        try:
            # Set default options if not provided
            if options is None:
                options = {}
            
            # Generate passphrase
            passphrase = password_generator.generate_passphrase(options)
            
            # Analyze strength
            strength_result = strength_analyzer.analyze_password(passphrase)
            
            # Check for breaches
            breach_result = breach_checker.check_password(passphrase)
            
            # Update session state if vault is unlocked
            if self.check_lock_status():
                self._save_session_state()
            
            return {
                'success': True,
                'passphrase': passphrase,
                'strength': {
                    'score': strength_result['score'],
                    'level': strength_result['strength'],
                    'feedback': strength_result['feedback']
                },
                'breach': breach_result
            }
        except Exception as e:
            return {
                'success': False,
                'message': str(e)
            }
    
    def close(self):
        """Close the vault and clean up resources"""
        # Lock the vault
        self.lock()
        
        # Close storage
        self.storage.close()


# Singleton instance
vault_manager = VaultManager() 