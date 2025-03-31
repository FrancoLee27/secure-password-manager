"""
Configuration settings for the password manager.
"""

import os
from pathlib import Path
from argon2 import Type

# Encryption Configuration
AES_KEY_LENGTH = 32  # 256 bits
AES_IV_LENGTH = 12   # 96 bits for GCM
AES_AUTH_TAG_LENGTH = 16  # 128 bits for GCM

# PBKDF2 Configuration for key derivation
PBKDF2_ITERATIONS = 600000  # Updated to meet 600,000 iterations requirement
PBKDF2_HASH_TYPE = 'sha256'
PBKDF2_SALT_LENGTH = 32     # 256 bits

# Argon2 Configuration for master password hashing
ARGON2_TIME_COST = 3        # Number of iterations
ARGON2_MEMORY_COST = 65536  # 64 MB in KiB
ARGON2_PARALLELISM = 4      # Number of parallel threads
ARGON2_HASH_LENGTH = 32     # 256 bits
ARGON2_TYPE = Type.ID       # Argon2id variant

# Memory Security
MEMORY_WIPE_TIMEOUT = 300   # Seconds to wipe keys from memory when idle

# Vault Configurations
MAX_FAILED_ATTEMPTS = 5     # Maximum failed login attempts before cooldown
AUTO_LOCK_TIMEOUT = 300     # Seconds until vault auto-locks

# Database Configuration
DB_DIRECTORY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
DB_FILENAME = 'vault.db'

# Breach Checking Configuration
HIBP_API_URL = 'https://api.pwnedpasswords.com/range'
HIBP_USER_AGENT = 'SecurePasswordManager/1.0'

# Ensure data directory exists
if not os.path.exists(DB_DIRECTORY):
    Path(DB_DIRECTORY).mkdir(parents=True, exist_ok=True) 