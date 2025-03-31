"""
WebAuthn (FIDO2) implementation for hardware security key authentication.
"""

import os
import sys
import base64
import json
import secrets
from pathlib import Path
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes
)
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    AuthenticatorAttachment
)

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))))

from src.crypto.encryption import encryption_service
from config.config import DB_DIRECTORY

# Custom implementation of bytes_to_base64url
def bytes_to_base64url(data):
    """Convert bytes to Base64URL encoding without padding"""
    base64_encoded = base64.b64encode(data).decode('ascii')
    # Replace + with -, / with _, and remove =
    return base64_encoded.replace('+', '-').replace('/', '_').rstrip('=')

class WebAuthnService:
    """WebAuthn service for hardware security key authentication"""
    
    def __init__(self):
        """Initialize the WebAuthn service"""
        self.webauthn_dir = Path(DB_DIRECTORY) / 'webauthn'
        if not self.webauthn_dir.exists():
            self.webauthn_dir.mkdir(parents=True, exist_ok=True)
        
        # This would typically come from environment variables or config
        self.rp_name = "Secure Password Manager"
        self.rp_id = "localhost"  # In production, this would be your domain
        self.origin = "http://localhost:5001"  # In production, this would be your origin
    
    def _generate_user_id(self):
        """
        Generate a unique user ID for WebAuthn
        
        Returns:
            bytes: A random 32-byte ID
        """
        return secrets.token_bytes(32)
    
    def _get_credentials_file_path(self, username):
        """
        Get the path to the credentials file for a user
        
        Args:
            username (str): The username
            
        Returns:
            Path: The path to the credentials file
        """
        return self.webauthn_dir / f"{username}_credentials.json"
    
    def start_registration(self, username, display_name=None):
        """
        Start WebAuthn registration process
        
        Args:
            username (str): The username
            display_name (str, optional): The display name (defaults to username)
            
        Returns:
            dict: Registration options for the client
        """
        if display_name is None:
            display_name = username
        
        # Generate a user ID for WebAuthn registration
        user_id = self._generate_user_id()
        
        # Get stored credentials for the user (if any)
        existing_credentials = self._load_credentials(username)
        exclude_credentials = []
        
        if existing_credentials:
            # Convert existing credentials to exclude list to prevent re-registration
            exclude_credentials = [
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred['id']))
                for cred in existing_credentials
            ]
        
        # Generate registration options
        options = generate_registration_options(
            rp_id=self.rp_id,
            rp_name=self.rp_name,
            user_id=user_id,
            user_name=username,
            user_display_name=display_name,
            attestation="none",
            exclude_credentials=exclude_credentials,
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
                resident_key=ResidentKeyRequirement.DISCOURAGED,
                user_verification=UserVerificationRequirement.PREFERRED
            )
        )
        
        # Store the challenge for later verification
        self._save_challenge(username, options.challenge)
        
        # Convert to JSON
        return options_to_json(options)
    
    def verify_registration(self, username, credential, client_data):
        """
        Verify WebAuthn registration response
        
        Args:
            username (str): The username
            credential (dict): The credential response from client
            client_data (dict): The client data from response
            
        Returns:
            bool: True if registration is verified
        """
        try:
            # Get the saved challenge
            challenge = self._load_challenge(username)
            if not challenge:
                return False
            
            # Verify the registration response
            verification = verify_registration_response(
                credential=credential,
                expected_challenge=challenge,
                expected_origin=self.origin,
                expected_rp_id=self.rp_id
            )
            
            if verification.verified:
                # Save the credential
                return self._save_credential(username, credential, verification)
            
            return False
        except Exception as e:
            print(f"Error verifying WebAuthn registration: {str(e)}")
            return False
        finally:
            # Always clean up the challenge
            self._delete_challenge(username)
    
    def start_authentication(self, username):
        """
        Start WebAuthn authentication process
        
        Args:
            username (str): The username
            
        Returns:
            dict: Authentication options for the client
        """
        # Get stored credentials for the user
        credentials = self._load_credentials(username)
        if not credentials:
            return None
        
        # Get credential IDs from stored credentials
        allow_credentials = [
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred['id']))
            for cred in credentials
        ]
        
        # Generate authentication options
        options = generate_authentication_options(
            rp_id=self.rp_id,
            allow_credentials=allow_credentials,
            user_verification=UserVerificationRequirement.PREFERRED
        )
        
        # Store the challenge for later verification
        self._save_challenge(username, options.challenge)
        
        # Convert to JSON
        return options_to_json(options)
    
    def verify_authentication(self, username, credential, client_data):
        """
        Verify WebAuthn authentication response
        
        Args:
            username (str): The username
            credential (dict): The credential response from client
            client_data (dict): The client data from response
            
        Returns:
            bool: True if authentication is verified
        """
        try:
            # Get the saved challenge
            challenge = self._load_challenge(username)
            if not challenge:
                return False
            
            # Get the user's credentials
            credentials = self._load_credentials(username)
            if not credentials:
                return False
            
            # Find the credential with matching ID
            credential_id = credential.get('id')
            stored_credential = None
            
            for cred in credentials:
                if cred['id'] == credential_id:
                    stored_credential = cred
                    break
            
            if not stored_credential:
                return False
            
            # Verify the authentication response
            verification = verify_authentication_response(
                credential=credential,
                expected_challenge=challenge,
                expected_origin=self.origin,
                expected_rp_id=self.rp_id,
                credential_public_key=base64url_to_bytes(stored_credential['public_key']),
                credential_current_sign_count=stored_credential.get('sign_count', 0)
            )
            
            if verification.verified:
                # Update the credential sign count
                stored_credential['sign_count'] = verification.new_sign_count
                self._update_credential(username, stored_credential)
                return True
            
            return False
        except Exception as e:
            print(f"Error verifying WebAuthn authentication: {str(e)}")
            return False
        finally:
            # Always clean up the challenge
            self._delete_challenge(username)
    
    def encrypt_credentials(self, vault_key, credentials):
        """
        Encrypt WebAuthn credentials with the vault key
        
        Args:
            vault_key (bytes): The vault encryption key
            credentials (list): The WebAuthn credentials
            
        Returns:
            dict: Encrypted credentials data
        """
        # Convert credentials to JSON string
        credentials_json = json.dumps(credentials)
        
        # Encrypt credentials
        encrypted, iv, auth_tag = encryption_service.encrypt(vault_key, credentials_json)
        
        return {
            'encrypted': base64.b64encode(encrypted).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'auth_tag': base64.b64encode(auth_tag).decode('utf-8')
        }
    
    def decrypt_credentials(self, vault_key, encrypted_data):
        """
        Decrypt WebAuthn credentials with the vault key
        
        Args:
            vault_key (bytes): The vault encryption key
            encrypted_data (dict): The encrypted credentials data
            
        Returns:
            list: The decrypted WebAuthn credentials
        """
        encrypted = base64.b64decode(encrypted_data['encrypted'])
        iv = base64.b64decode(encrypted_data['iv'])
        auth_tag = base64.b64decode(encrypted_data['auth_tag'])
        
        # Decrypt credentials
        credentials_json = encryption_service.decrypt(vault_key, encrypted, iv, auth_tag)
        
        # Parse JSON
        return json.loads(credentials_json)
    
    def _save_credential(self, username, credential, verification):
        """
        Save a verified credential
        
        Args:
            username (str): The username
            credential (dict): The credential from client
            verification (VerifiedRegistration): The verification result
            
        Returns:
            bool: True if successful
        """
        try:
            # Get existing credentials
            credentials = self._load_credentials(username) or []
            
            # Prepare new credential
            new_credential = {
                'id': credential['id'],
                'public_key': bytes_to_base64url(verification.credential_public_key),
                'sign_count': verification.sign_count,
                'aaguid': bytes_to_base64url(verification.aaguid),
                'created_at': str(verification.pkcro.time_created)
            }
            
            # Add to list
            credentials.append(new_credential)
            
            # Save credentials
            credentials_file = self._get_credentials_file_path(username)
            with open(credentials_file, 'w') as f:
                json.dump(credentials, f)
            
            return True
        except Exception as e:
            print(f"Error saving WebAuthn credential: {str(e)}")
            return False
    
    def _update_credential(self, username, updated_credential):
        """
        Update a credential (e.g., sign count)
        
        Args:
            username (str): The username
            updated_credential (dict): The updated credential
            
        Returns:
            bool: True if successful
        """
        try:
            # Get existing credentials
            credentials = self._load_credentials(username)
            if not credentials:
                return False
            
            # Find and update the credential
            credential_id = updated_credential['id']
            for i, cred in enumerate(credentials):
                if cred['id'] == credential_id:
                    credentials[i] = updated_credential
                    break
            
            # Save credentials
            credentials_file = self._get_credentials_file_path(username)
            with open(credentials_file, 'w') as f:
                json.dump(credentials, f)
            
            return True
        except Exception as e:
            print(f"Error updating WebAuthn credential: {str(e)}")
            return False
    
    def _load_credentials(self, username):
        """
        Load credentials for a user
        
        Args:
            username (str): The username
            
        Returns:
            list: List of credentials or None if not found
        """
        try:
            credentials_file = self._get_credentials_file_path(username)
            if not credentials_file.exists():
                return []
            
            with open(credentials_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading WebAuthn credentials: {str(e)}")
            return []
    
    def _save_challenge(self, username, challenge):
        """
        Save an authentication/registration challenge
        
        Args:
            username (str): The username
            challenge (bytes): The challenge
            
        Returns:
            bool: True if successful
        """
        try:
            challenge_file = self.webauthn_dir / f"{username}_challenge.dat"
            with open(challenge_file, 'wb') as f:
                f.write(challenge)
            return True
        except Exception as e:
            print(f"Error saving WebAuthn challenge: {str(e)}")
            return False
    
    def _load_challenge(self, username):
        """
        Load a saved challenge
        
        Args:
            username (str): The username
            
        Returns:
            bytes: The challenge or None if not found
        """
        try:
            challenge_file = self.webauthn_dir / f"{username}_challenge.dat"
            if not challenge_file.exists():
                return None
            
            with open(challenge_file, 'rb') as f:
                return f.read()
        except Exception as e:
            print(f"Error loading WebAuthn challenge: {str(e)}")
            return None
    
    def _delete_challenge(self, username):
        """
        Delete a saved challenge
        
        Args:
            username (str): The username
            
        Returns:
            bool: True if successful
        """
        try:
            challenge_file = self.webauthn_dir / f"{username}_challenge.dat"
            if challenge_file.exists():
                os.remove(challenge_file)
            return True
        except Exception as e:
            print(f"Error deleting WebAuthn challenge: {str(e)}")
            return False


# Singleton instance
webauthn_service = WebAuthnService() 