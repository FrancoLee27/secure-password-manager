"""
Storage service for secure data persistence using SQLite with encryption.
"""

import os
import sqlite3
import json
import sys
import time
import base64
from pathlib import Path

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from config.config import DB_DIRECTORY, DB_FILENAME
from src.crypto.encryption import encryption_service


class StorageService:
    """Storage service for secure data persistence with encryption"""
    
    def __init__(self):
        """Initialize the storage service"""
        self.conn = None
        self.cursor = None
        self.vault_key = None
        self.db_path = self._get_db_path()
        self.initialized = False
    
    def _get_db_path(self):
        """Get the database file path"""
        # Ensure directory exists
        db_dir = Path(DB_DIRECTORY)
        if not db_dir.exists():
            db_dir.mkdir(parents=True, exist_ok=True)
        
        return db_dir / DB_FILENAME
    
    def initialize(self):
        """Initialize the database connection and tables"""
        try:
            # Create connection
            self.conn = sqlite3.connect(self.db_path)
            
            # Enable foreign keys
            self.conn.execute("PRAGMA foreign_keys = ON")
            
            self.cursor = self.conn.cursor()
            
            # Set up tables
            self._setup_tables()
            
            self.initialized = True
            return True
            
        except Exception as e:
            print(f"Error initializing database: {str(e)}")
            if self.conn:
                self.conn.close()
            self.initialized = False
            return False
    
    def _setup_tables(self):
        """Set up the database tables"""
        # Create user table
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            vault_key_salt TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        ''')
        
        # Create vault table
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS vault (
            id TEXT PRIMARY KEY,
            encrypted_data TEXT NOT NULL,
            iv TEXT NOT NULL,
            auth_tag TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        ''')
        
        # Create categories table
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        ''')
        
        # Create tags table
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS tags (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        ''')
        
        # Create item_tags table
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS item_tags (
            item_id TEXT NOT NULL,
            tag_id INTEGER NOT NULL,
            PRIMARY KEY (item_id, tag_id)
        )
        ''')
        
        # Create security_questions table
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_questions (
            id INTEGER PRIMARY KEY,
            question TEXT NOT NULL,
            hashed_answer TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        ''')
        
        # Create audit log table
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY,
            action TEXT NOT NULL,
            item_id TEXT,
            timestamp TEXT NOT NULL
        )
        ''')
        
        # Create failed_attempts table
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS failed_attempts (
            id INTEGER PRIMARY KEY,
            count INTEGER NOT NULL,
            last_attempt TEXT NOT NULL
        )
        ''')
        
        # Commit changes
        self.conn.commit()
    
    def set_vault_key(self, key):
        """
        Set the vault encryption key
        
        Args:
            key (bytes): Encryption key
        """
        self.vault_key = key
    
    def clear_vault_key(self):
        """Clear the vault key from memory"""
        if self.vault_key:
            # Convert to bytearray for secure wiping
            key_bytes = bytearray(self.vault_key)
            encryption_service.secure_wipe(key_bytes)
            self.vault_key = None
    
    def save_user(self, user_data):
        """
        Save user data to the database
        
        Args:
            user_data (dict): User data including vault_key_salt
            
        Returns:
            dict: Result of the operation
        """
        if not self.initialized:
            self.initialize()
        
        try:
            # Check if user already exists
            self.cursor.execute('SELECT COUNT(*) FROM user')
            count = self.cursor.fetchone()[0]
            
            if count > 0:
                return {
                    'success': False,
                    'message': 'User already exists'
                }
            
            # Insert user
            self.cursor.execute(
                'INSERT INTO user (username, vault_key_salt, created_at) VALUES (?, ?, ?)',
                (user_data['username'], user_data['vault_key_salt'], user_data['created_at'])
            )
            self.conn.commit()
            
            return {
                'success': True,
                'message': 'User created successfully'
            }
        except Exception as e:
            return {
                'success': False,
                'message': str(e)
            }
    
    def get_user(self):
        """
        Get user data from the database
        
        Returns:
            dict: User data
        """
        if not self.initialized:
            self.initialize()
            
        try:
            self.cursor.execute('SELECT username, vault_key_salt, created_at FROM user LIMIT 1')
            row = self.cursor.fetchone()
            
            if not row:
                return None
            
            return {
                'username': row[0],
                'vault_key_salt': row[1],
                'created_at': row[2]
            }
        except Exception as e:
            print(f"Error getting user: {str(e)}")
            return None
    
    def save_vault_item(self, item):
        """
        Save an encrypted item to the vault
        
        Args:
            item (dict): Item to save
            
        Returns:
            dict: Result of the operation
        """
        if not self.initialized:
            self.initialize()
            
        if not self.vault_key:
            return {
                'success': False,
                'message': 'Vault key not set'
            }
        
        try:
            # Convert item to JSON
            item_json = json.dumps(item)
            
            # Encrypt the item
            encrypted, iv, auth_tag = encryption_service.encrypt(self.vault_key, item_json)
            
            # Convert binary data to base64 for storage
            encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
            iv_b64 = base64.b64encode(iv).decode('utf-8')
            auth_tag_b64 = base64.b64encode(auth_tag).decode('utf-8')
            
            # Check if item already exists
            self.cursor.execute('SELECT COUNT(*) FROM vault WHERE id = ?', (item['id'],))
            count = self.cursor.fetchone()[0]
            
            if count > 0:
                # Update existing item
                self.cursor.execute(
                    'UPDATE vault SET encrypted_data = ?, iv = ?, auth_tag = ?, updated_at = ? WHERE id = ?',
                    (encrypted_b64, iv_b64, auth_tag_b64, item['updated_at'], item['id'])
                )
            else:
                # Insert new item
                self.cursor.execute(
                    'INSERT INTO vault (id, encrypted_data, iv, auth_tag, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)',
                    (item['id'], encrypted_b64, iv_b64, auth_tag_b64, item['created_at'], item['updated_at'])
                )
            
            self.conn.commit()
            
            return {
                'success': True,
                'message': 'Item saved successfully'
            }
        except Exception as e:
            return {
                'success': False,
                'message': str(e)
            }
    
    def get_all_vault_items(self):
        """
        Get all items from the vault, decrypting them
        
        Returns:
            list: List of decrypted items
        """
        if not self.initialized:
            self.initialize()
            
        if not self.vault_key:
            return []
        
        try:
            self.cursor.execute('SELECT id, encrypted_data, iv, auth_tag FROM vault')
            rows = self.cursor.fetchall()
            
            items = []
            for row in rows:
                # Get encrypted data
                item_id = row[0]
                encrypted_b64 = row[1]
                iv_b64 = row[2]
                auth_tag_b64 = row[3]
                
                # Decode from base64
                encrypted = base64.b64decode(encrypted_b64)
                iv = base64.b64decode(iv_b64)
                auth_tag = base64.b64decode(auth_tag_b64)
                
                # Decrypt the item
                try:
                    decrypted = encryption_service.decrypt(self.vault_key, encrypted, iv, auth_tag)
                    item = json.loads(decrypted)
                    items.append(item)
                except Exception as e:
                    # Skip items that can't be decrypted
                    print(f"Failed to decrypt item {item_id}: {str(e)}")
                    continue
            
            return items
        except Exception as e:
            print(f"Error getting vault items: {str(e)}")
            return []
    
    def delete_vault_item(self, item_id):
        """
        Delete an item from the vault
        
        Args:
            item_id (str): ID of the item to delete
            
        Returns:
            dict: Result of the operation
        """
        if not self.initialized:
            self.initialize()
            
        try:
            # Check if item exists
            self.cursor.execute('SELECT COUNT(*) FROM vault WHERE id = ?', (item_id,))
            count = self.cursor.fetchone()[0]
            
            if count == 0:
                return {
                    'success': False,
                    'message': 'Item not found'
                }
            
            # Delete item
            self.cursor.execute('DELETE FROM vault WHERE id = ?', (item_id,))
            self.conn.commit()
            
            return {
                'success': True,
                'message': 'Item deleted successfully'
            }
        except Exception as e:
            return {
                'success': False,
                'message': str(e)
            }
    
    def log_audit(self, log_data):
        """
        Log an action in the audit log
        
        Args:
            log_data (dict): Log data
            
        Returns:
            bool: Success status
        """
        if not self.initialized:
            self.initialize()
            
        try:
            item_id = log_data.get('item_id', None)
            
            self.cursor.execute(
                'INSERT INTO audit_log (action, item_id, timestamp) VALUES (?, ?, ?)',
                (log_data['action'], item_id, log_data['timestamp'])
            )
            self.conn.commit()
            
            return True
        except Exception as e:
            print(f"Error logging audit: {str(e)}")
            return False
    
    def update_failed_attempts(self, increment=True):
        """
        Update the failed attempts counter
        
        Args:
            increment (bool): Whether to increment or reset the counter
            
        Returns:
            dict: Current failed attempts data
        """
        if not self.initialized:
            self.initialize()
            
        try:
            # Get current count
            self.cursor.execute('SELECT count, last_attempt FROM failed_attempts ORDER BY id DESC LIMIT 1')
            row = self.cursor.fetchone()
            
            current_time = time.time()
            
            if not row:
                # No record yet
                count = 1 if increment else 0
                self.cursor.execute(
                    'INSERT INTO failed_attempts (count, last_attempt) VALUES (?, ?)',
                    (count, current_time)
                )
            else:
                current_count = row[0]
                count = current_count + 1 if increment else 0
                
                self.cursor.execute(
                    'INSERT INTO failed_attempts (count, last_attempt) VALUES (?, ?)',
                    (count, current_time)
                )
            
            self.conn.commit()
            
            return {
                'count': count,
                'last_attempt': current_time
            }
        except Exception as e:
            print(f"Error updating failed attempts: {str(e)}")
            return {
                'count': 0,
                'last_attempt': current_time
            }
    
    def close(self):
        """Close the database connection"""
        if self.conn:
            self.conn.close()
            self.conn = None
            self.cursor = None
            self.initialized = False


# Don't create a singleton instance here
# Each vault manager should create its own storage service 