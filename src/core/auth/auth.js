const argon2 = require('argon2');
const crypto = require('crypto');
const config = require('../encryption/config');
const encryptionService = require('../encryption/encryption');

/**
 * Authentication service for secure user authentication
 */
class AuthService {
  /**
   * Hash the master password using Argon2id
   * @param {string} masterPassword - The master password to hash
   * @returns {Promise<string>} - The hashed password
   */
  async hashMasterPassword(masterPassword) {
    return await argon2.hash(masterPassword, {
      type: argon2.argon2id,
      timeCost: config.ARGON2_TIME_COST,
      memoryCost: config.ARGON2_MEMORY_COST,
      parallelism: config.ARGON2_PARALLELISM,
      hashLength: config.ARGON2_HASH_LENGTH
    });
  }

  /**
   * Verify the master password against a hash
   * @param {string} hash - The stored password hash
   * @param {string} masterPassword - The password to verify
   * @returns {Promise<boolean>} - True if password matches
   */
  async verifyMasterPassword(hash, masterPassword) {
    try {
      return await argon2.verify(hash, masterPassword);
    } catch (err) {
      console.error('Error verifying password:', err);
      return false;
    }
  }

  /**
   * Generate a random recovery key
   * @returns {string} - Base64 encoded recovery key
   */
  generateRecoveryKey() {
    const recoveryKeyBytes = crypto.randomBytes(32);
    return recoveryKeyBytes.toString('base64');
  }

  /**
   * Create backup of vault key using recovery key
   * @param {Buffer} vaultKey - The vault encryption key
   * @param {string} recoveryKey - The recovery key
   * @returns {Object} - Encrypted vault key backup
   */
  async backupVaultKey(vaultKey, recoveryKey) {
    // Convert recovery key from base64 to buffer
    const recoveryKeyBuffer = Buffer.from(recoveryKey, 'base64');
    
    // Encrypt vault key with recovery key
    return encryptionService.encrypt(recoveryKeyBuffer, vaultKey.toString('hex'));
  }

  /**
   * Recover vault key using recovery key
   * @param {Object} encryptedBackup - The encrypted vault key backup
   * @param {string} recoveryKey - The recovery key
   * @returns {Buffer} - The recovered vault key
   */
  async recoverVaultKey(encryptedBackup, recoveryKey) {
    // Convert recovery key from base64 to buffer
    const recoveryKeyBuffer = Buffer.from(recoveryKey, 'base64');
    
    // Decrypt vault key with recovery key
    const decryptedHex = encryptionService.decrypt(recoveryKeyBuffer, encryptedBackup);
    return Buffer.from(decryptedHex, 'hex');
  }

  /**
   * Generate secure security question answers
   * @param {string} answer - The user's answer
   * @returns {Promise<string>} - Hashed answer
   */
  async hashSecurityAnswer(answer) {
    // Normalize answer (lowercase, trim whitespace)
    const normalizedAnswer = answer.toLowerCase().trim();
    return await this.hashMasterPassword(normalizedAnswer);
  }

  /**
   * Verify security question answer
   * @param {string} hashedAnswer - The stored hashed answer
   * @param {string} providedAnswer - The answer to verify
   * @returns {Promise<boolean>} - True if answer matches
   */
  async verifySecurityAnswer(hashedAnswer, providedAnswer) {
    // Normalize answer (lowercase, trim whitespace)
    const normalizedAnswer = providedAnswer.toLowerCase().trim();
    return await this.verifyMasterPassword(hashedAnswer, normalizedAnswer);
  }
}

module.exports = new AuthService(); 