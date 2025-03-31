/**
 * Encryption configuration parameters
 */
module.exports = {
  // AES-256 GCM mode configuration
  ENCRYPTION_ALGORITHM: 'AES-GCM',
  KEY_LENGTH: 32, // 256 bits
  IV_LENGTH: 12, // 96 bits, recommended for GCM
  AUTH_TAG_LENGTH: 16, // 128 bits
  
  // PBKDF2 configuration for key derivation
  PBKDF2_ITERATIONS: 600000,
  PBKDF2_DIGEST: 'sha512',
  SALT_LENGTH: 32, // 256 bits
  
  // Argon2 configuration for master password hashing
  ARGON2_TIME_COST: 3,
  ARGON2_MEMORY_COST: 65536, // 64 MB
  ARGON2_PARALLELISM: 1,
  ARGON2_HASH_LENGTH: 32, // 256 bits
  ARGON2_TYPE: 'argon2id', // Combines security against GPU and side-channel attacks
  
  // Memory security
  AUTOMATIC_MEMORY_WIPE_TIMEOUT: 60000, // 60 seconds
  
  // Vault configurations
  MAX_FAILED_ATTEMPTS: 5,
  AUTO_LOCK_TIMEOUT: 300000 // 5 minutes
}; 