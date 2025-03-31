const crypto = require('crypto');
const config = require('./config');

/**
 * Core encryption service using AES-256 in GCM mode
 * Implements zero-knowledge architecture where encryption/decryption 
 * only occurs at the device level
 */
class EncryptionService {
  /**
   * Derives a key from a password using PBKDF2
   * @param {string} password - The master password
   * @param {Buffer|null} salt - The salt (if null, a new one is generated)
   * @returns {Object} - Object containing the derived key and the salt used
   */
  async deriveKey(password, salt = null) {
    if (!salt) {
      salt = crypto.randomBytes(config.SALT_LENGTH);
    }
    
    return new Promise((resolve, reject) => {
      crypto.pbkdf2(
        password, 
        salt, 
        config.PBKDF2_ITERATIONS, 
        config.KEY_LENGTH, 
        config.PBKDF2_DIGEST, 
        (err, derivedKey) => {
          if (err) return reject(err);
          resolve({
            key: derivedKey,
            salt: salt
          });
        }
      );
    });
  }

  /**
   * Encrypts data using AES-256-GCM
   * @param {Buffer} key - The encryption key
   * @param {string|Object} data - The data to encrypt
   * @returns {Object} - The encrypted data with IV and auth tag
   */
  encrypt(key, data) {
    // Convert objects to JSON strings for encryption
    if (typeof data === 'object') {
      data = JSON.stringify(data);
    }
    
    const iv = crypto.randomBytes(config.IV_LENGTH);
    const cipher = crypto.createCipheriv(
      config.ENCRYPTION_ALGORITHM, 
      key, 
      iv, 
      { authTagLength: config.AUTH_TAG_LENGTH }
    );
    
    let encrypted = cipher.update(data, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    const authTag = cipher.getAuthTag();
    
    return {
      encrypted: encrypted,
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64')
    };
  }

  /**
   * Decrypts data using AES-256-GCM
   * @param {Buffer} key - The decryption key
   * @param {Object} encryptedData - Object containing encrypted data, IV, and auth tag
   * @returns {string|Object} - The decrypted data
   */
  decrypt(key, encryptedData) {
    const iv = Buffer.from(encryptedData.iv, 'base64');
    const authTag = Buffer.from(encryptedData.authTag, 'base64');
    
    const decipher = crypto.createDecipheriv(
      config.ENCRYPTION_ALGORITHM, 
      key, 
      iv, 
      { authTagLength: config.AUTH_TAG_LENGTH }
    );
    
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encryptedData.encrypted, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    
    // Try to parse as JSON if it's a JSON string
    try {
      return JSON.parse(decrypted);
    } catch (e) {
      // If not a valid JSON string, return as is
      return decrypted;
    }
  }

  /**
   * Securely wipes a buffer from memory by overwriting it
   * @param {Buffer} buffer - The buffer to wipe
   */
  secureWipe(buffer) {
    if (buffer && buffer.fill) {
      // Overwrite the buffer with zeros
      buffer.fill(0);
    }
  }

  /**
   * Creates a vault key from a master password
   * @param {string} masterPassword - The master password
   * @param {Buffer|null} salt - The salt (if null, a new one is generated)
   * @returns {Object} - Object containing the vault key and the salt used
   */
  async createVaultKey(masterPassword, salt = null) {
    const { key, salt: usedSalt } = await this.deriveKey(masterPassword, salt);
    return {
      vaultKey: key,
      salt: usedSalt
    };
  }
}

module.exports = new EncryptionService(); 