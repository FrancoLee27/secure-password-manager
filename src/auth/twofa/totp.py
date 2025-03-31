"""
TOTP (Time-based One-Time Password) implementation for two-factor authentication.
"""

import os
import pyotp
import base64
import qrcode
import io
import sys
from pathlib import Path

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))))

from src.crypto.encryption import encryption_service
from config.config import DB_DIRECTORY


class TOTPService:
    """Time-based One-Time Password service for 2FA"""
    
    def __init__(self):
        """Initialize the TOTP service"""
        self.backup_codes_dir = Path(DB_DIRECTORY) / 'backup_codes'
        if not self.backup_codes_dir.exists():
            self.backup_codes_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_secret(self):
        """
        Generate a new TOTP secret
        
        Returns:
            str: Base32 encoded secret key
        """
        return pyotp.random_base32()
    
    def get_provisioning_uri(self, secret, username, issuer="Secure Password Manager"):
        """
        Get the provisioning URI for TOTP setup
        
        Args:
            secret (str): The TOTP secret
            username (str): The username for the account
            issuer (str): The name of the issuer
            
        Returns:
            str: The provisioning URI for QR code generation
        """
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(username, issuer_name=issuer)
    
    def generate_qr_code(self, provisioning_uri):
        """
        Generate a QR code image for the provisioning URI
        
        Args:
            provisioning_uri (str): The TOTP provisioning URI
            
        Returns:
            bytes: PNG image data
        """
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        img_buffer = io.BytesIO()
        img.save(img_buffer, format="PNG")
        
        return img_buffer.getvalue()
    
    def verify_code(self, secret, code):
        """
        Verify a TOTP code
        
        Args:
            secret (str): The TOTP secret
            code (str): The code to verify
            
        Returns:
            bool: True if code is valid
        """
        totp = pyotp.TOTP(secret)
        return totp.verify(code)
    
    def generate_backup_codes(self, count=10, length=8):
        """
        Generate backup codes for recovery
        
        Args:
            count (int): Number of codes to generate
            length (int): Length of each code
            
        Returns:
            list: List of backup codes
        """
        backup_codes = []
        for _ in range(count):
            # Generate random bytes and convert to hex
            random_bytes = os.urandom(length // 2)  # 8 chars = 4 bytes
            code = random_bytes.hex()
            backup_codes.append(code)
        
        return backup_codes
    
    def encrypt_totp_secret(self, vault_key, secret):
        """
        Encrypt the TOTP secret with the vault key
        
        Args:
            vault_key (bytes): The vault encryption key
            secret (str): The TOTP secret
            
        Returns:
            dict: Encrypted TOTP secret data
        """
        encrypted, iv, auth_tag = encryption_service.encrypt(vault_key, secret)
        
        return {
            'encrypted': base64.b64encode(encrypted).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'auth_tag': base64.b64encode(auth_tag).decode('utf-8')
        }
    
    def decrypt_totp_secret(self, vault_key, encrypted_data):
        """
        Decrypt the TOTP secret with the vault key
        
        Args:
            vault_key (bytes): The vault encryption key
            encrypted_data (dict): The encrypted TOTP secret data
            
        Returns:
            str: The decrypted TOTP secret
        """
        encrypted = base64.b64decode(encrypted_data['encrypted'])
        iv = base64.b64decode(encrypted_data['iv'])
        auth_tag = base64.b64decode(encrypted_data['auth_tag'])
        
        return encryption_service.decrypt(vault_key, encrypted, iv, auth_tag)
    
    def save_backup_codes(self, username, vault_key, backup_codes):
        """
        Save encrypted backup codes for a user
        
        Args:
            username (str): The username
            vault_key (bytes): The vault encryption key
            backup_codes (list): List of backup codes
            
        Returns:
            bool: True if successful
        """
        try:
            # Convert backup codes to string
            backup_codes_str = ','.join(backup_codes)
            
            # Encrypt the backup codes
            encrypted, iv, auth_tag = encryption_service.encrypt(vault_key, backup_codes_str)
            
            # Save to file
            backup_file = self.backup_codes_dir / f"{username}_backup.dat"
            with open(backup_file, 'wb') as f:
                # Format: IV + auth_tag + encrypted data
                f.write(len(iv).to_bytes(1, byteorder='big'))
                f.write(iv)
                f.write(len(auth_tag).to_bytes(1, byteorder='big'))
                f.write(auth_tag)
                f.write(encrypted)
            
            return True
        except Exception as e:
            print(f"Error saving backup codes: {str(e)}")
            return False
    
    def load_backup_codes(self, username, vault_key):
        """
        Load encrypted backup codes for a user
        
        Args:
            username (str): The username
            vault_key (bytes): The vault encryption key
            
        Returns:
            list: List of backup codes, or None if error
        """
        try:
            backup_file = self.backup_codes_dir / f"{username}_backup.dat"
            if not backup_file.exists():
                return None
            
            with open(backup_file, 'rb') as f:
                # Read IV
                iv_len = int.from_bytes(f.read(1), byteorder='big')
                iv = f.read(iv_len)
                
                # Read auth tag
                auth_tag_len = int.from_bytes(f.read(1), byteorder='big')
                auth_tag = f.read(auth_tag_len)
                
                # Read encrypted data
                encrypted = f.read()
            
            # Decrypt the backup codes
            backup_codes_str = encryption_service.decrypt(vault_key, encrypted, iv, auth_tag)
            
            # Split into list
            return backup_codes_str.split(',')
        except Exception as e:
            print(f"Error loading backup codes: {str(e)}")
            return None
    
    def verify_backup_code(self, username, vault_key, provided_code):
        """
        Verify a backup code and remove it if used
        
        Args:
            username (str): The username
            vault_key (bytes): The vault encryption key
            provided_code (str): The backup code to verify
            
        Returns:
            bool: True if code is valid
        """
        # Load existing backup codes
        backup_codes = self.load_backup_codes(username, vault_key)
        if not backup_codes:
            return False
        
        # Check if provided code is in the list
        if provided_code in backup_codes:
            # Remove the used code
            backup_codes.remove(provided_code)
            
            # Save the updated list
            self.save_backup_codes(username, vault_key, backup_codes)
            return True
        
        return False


# Singleton instance
totp_service = TOTPService() 