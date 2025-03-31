const storageService = require('../storage/storage');
const encryptionService = require('../encryption/encryption');
const authService = require('../auth/auth');
const passwordGenerator = require('./generator');
const strengthAnalyzer = require('./strength');
const breachChecker = require('./breachChecker');
const crypto = require('crypto');

/**
 * Password Vault Manager
 * Manages the password vault and provides core functionality
 */
class VaultManager {
  constructor() {
    this.isInitialized = false;
    this.isLocked = true;
    this.autoLockTimer = null;
    this.failedAttempts = 0;
    this.vaultKey = null;
  }

  /**
   * Initialize the vault manager
   * @param {string} dbPath - Path to the vault database
   * @returns {Promise<boolean>} - True if initialized successfully
   */
  async initialize(dbPath) {
    try {
      await storageService.initialize(dbPath);
      this.isInitialized = true;
      
      // Check if user exists (vault is set up)
      const user = await storageService.getUser();
      if (user) {
        this.failedAttempts = user.failedAttempts || 0;
      }
      
      return true;
    } catch (error) {
      console.error('Error initializing vault:', error);
      return false;
    }
  }

  /**
   * Create a new vault with a master password
   * @param {string} masterPassword - The master password
   * @returns {Promise<Object>} - Creation result
   */
  async createVault(masterPassword) {
    try {
      // Check password strength first
      const strengthResult = strengthAnalyzer.analyzePassword(masterPassword);
      if (strengthResult.score < 50) {
        return { 
          success: false, 
          error: 'Master password is too weak',
          strengthResult
        };
      }

      // Hash the master password
      const masterPasswordHash = await authService.hashMasterPassword(masterPassword);
      
      // Create vault encryption key from the master password
      const { vaultKey, salt: vaultKeySalt } = await encryptionService.createVaultKey(masterPassword);
      
      // Generate a recovery key
      const recoveryKey = authService.generateRecoveryKey();
      
      // Encrypt vault key with recovery key for backup
      const recoveryKeyBackup = await authService.backupVaultKey(vaultKey, recoveryKey);
      
      // Save user data
      await storageService.saveUser({
        masterPasswordHash,
        vaultKeySalt,
        recoveryKeyBackup
      });
      
      // Set the vault key and unlock the vault
      this.setVaultKey(vaultKey);
      
      return {
        success: true,
        recoveryKey
      };
    } catch (error) {
      console.error('Error creating vault:', error);
      return { 
        success: false, 
        error: error.message
      };
    }
  }

  /**
   * Unlock the vault with master password
   * @param {string} masterPassword - The master password
   * @returns {Promise<Object>} - Unlock result
   */
  async unlockVault(masterPassword) {
    try {
      // Check if user exists
      const user = await storageService.getUser();
      if (!user) {
        return { 
          success: false, 
          error: 'Vault does not exist'
        };
      }
      
      // Check if too many failed attempts
      if (user.failedAttempts >= 5) {
        return {
          success: false,
          error: 'Too many failed attempts. Consider using recovery options.',
          locked: true
        };
      }
      
      // Verify the master password
      const isCorrect = await authService.verifyMasterPassword(
        user.masterPasswordHash, 
        masterPassword
      );
      
      if (!isCorrect) {
        // Increment failed attempts
        await this.updateFailedAttempts(user.failedAttempts + 1);
        
        return {
          success: false,
          error: 'Incorrect master password',
          remainingAttempts: 5 - (user.failedAttempts + 1)
        };
      }
      
      // Reset failed attempts
      if (user.failedAttempts > 0) {
        await this.updateFailedAttempts(0);
      }
      
      // Derive the vault key from the master password and salt
      const { key: vaultKey } = await encryptionService.deriveKey(
        masterPassword, 
        user.vaultKeySalt
      );
      
      // Set the vault key and unlock the vault
      this.setVaultKey(vaultKey);
      
      return {
        success: true
      };
    } catch (error) {
      console.error('Error unlocking vault:', error);
      return { 
        success: false, 
        error: error.message
      };
    }
  }

  /**
   * Lock the vault by clearing the encryption key
   */
  lockVault() {
    // Clear the vault key
    this.clearVaultKey();
    
    // Log the action
    storageService.logAudit('Vault locked');
    
    return { success: true };
  }

  /**
   * Set up and start the auto-lock timer
   * @param {number} timeout - Timeout in milliseconds
   */
  startAutoLockTimer(timeout) {
    // Clear any existing timer
    this.clearAutoLockTimer();
    
    // Set new timer
    this.autoLockTimer = setTimeout(() => {
      this.lockVault();
    }, timeout);
  }

  /**
   * Clear the auto-lock timer
   */
  clearAutoLockTimer() {
    if (this.autoLockTimer) {
      clearTimeout(this.autoLockTimer);
      this.autoLockTimer = null;
    }
  }

  /**
   * Reset the auto-lock timer (e.g., after user activity)
   * @param {number} timeout - Timeout in milliseconds
   */
  resetAutoLockTimer(timeout) {
    this.startAutoLockTimer(timeout);
  }

  /**
   * Update the failed attempts counter
   * @param {number} attempts - New attempt count
   * @returns {Promise<void>}
   */
  async updateFailedAttempts(attempts) {
    this.failedAttempts = attempts;
    
    // Update in the database
    await storageService.db.run(
      'UPDATE user SET failed_attempts = ? WHERE id = 1',
      [attempts]
    );
  }

  /**
   * Set the vault encryption key
   * @param {Buffer} key - The encryption key
   */
  setVaultKey(key) {
    this.vaultKey = Buffer.from(key);
    storageService.setVaultKey(this.vaultKey);
    this.isLocked = false;
    
    // Start auto-lock timer
    this.startAutoLockTimer(300000); // 5 minutes
  }

  /**
   * Clear the vault encryption key
   */
  clearVaultKey() {
    if (this.vaultKey) {
      encryptionService.secureWipe(this.vaultKey);
      this.vaultKey = null;
    }
    
    storageService.clearVaultKey();
    this.isLocked = true;
    this.clearAutoLockTimer();
  }

  /**
   * Add a password to the vault
   * @param {Object} passwordEntry - Password entry to add
   * @returns {Promise<Object>} - Addition result
   */
  async addPassword(passwordEntry) {
    if (this.isLocked) {
      return { 
        success: false, 
        error: 'Vault is locked'
      };
    }
    
    try {
      // Validate entry
      if (!passwordEntry.name || !passwordEntry.password) {
        return {
          success: false,
          error: 'Name and password are required'
        };
      }
      
      // Check password strength
      const strengthResult = strengthAnalyzer.analyzePassword(passwordEntry.password);
      
      // Add metadata
      const entry = {
        ...passwordEntry,
        created: Date.now(),
        updated: Date.now(),
        strengthScore: strengthResult.score
      };
      
      // Save to vault
      const id = await storageService.saveVaultItem(entry);
      
      // Log the action
      await storageService.logAudit('Password added', { id });
      
      // Reset auto-lock timer
      this.resetAutoLockTimer(300000);
      
      return {
        success: true,
        id,
        strength: strengthResult
      };
    } catch (error) {
      console.error('Error adding password:', error);
      return { 
        success: false, 
        error: error.message
      };
    }
  }

  /**
   * Update a password in the vault
   * @param {Object} passwordEntry - Password entry to update
   * @returns {Promise<Object>} - Update result
   */
  async updatePassword(passwordEntry) {
    if (this.isLocked) {
      return { 
        success: false, 
        error: 'Vault is locked'
      };
    }
    
    try {
      // Validate entry
      if (!passwordEntry.id) {
        return {
          success: false,
          error: 'Password ID is required'
        };
      }
      
      // Get existing password for history
      const passwords = await storageService.getAllVaultItems();
      const existingPassword = passwords.find(p => p.id === passwordEntry.id);
      
      if (!existingPassword) {
        return {
          success: false,
          error: 'Password not found'
        };
      }
      
      // Check password strength if password changed
      let strengthResult = null;
      if (passwordEntry.password && passwordEntry.password !== existingPassword.password) {
        strengthResult = strengthAnalyzer.analyzePassword(passwordEntry.password);
      }
      
      // Prepare history
      const history = existingPassword.history || [];
      const historicalEntry = {
        password: existingPassword.password,
        updatedAt: existingPassword.updated
      };
      
      // Limit history to 10 entries
      if (history.length >= 10) {
        history.shift(); // Remove oldest entry
      }
      
      // Add current password to history
      history.push(historicalEntry);
      
      // Update entry
      const entry = {
        ...existingPassword,
        ...passwordEntry,
        history,
        updated: Date.now()
      };
      
      if (strengthResult) {
        entry.strengthScore = strengthResult.score;
      }
      
      // Save to vault
      await storageService.saveVaultItem(entry);
      
      // Log the action
      await storageService.logAudit('Password updated', { id: passwordEntry.id });
      
      // Reset auto-lock timer
      this.resetAutoLockTimer(300000);
      
      return {
        success: true,
        strength: strengthResult
      };
    } catch (error) {
      console.error('Error updating password:', error);
      return { 
        success: false, 
        error: error.message
      };
    }
  }

  /**
   * Delete a password from the vault
   * @param {number} id - ID of the password to delete
   * @returns {Promise<Object>} - Deletion result
   */
  async deletePassword(id) {
    if (this.isLocked) {
      return { 
        success: false, 
        error: 'Vault is locked'
      };
    }
    
    try {
      // Delete from vault
      await storageService.deleteVaultItem(id);
      
      // Log the action
      await storageService.logAudit('Password deleted', { id });
      
      // Reset auto-lock timer
      this.resetAutoLockTimer(300000);
      
      return {
        success: true
      };
    } catch (error) {
      console.error('Error deleting password:', error);
      return { 
        success: false, 
        error: error.message
      };
    }
  }

  /**
   * Get all passwords from the vault
   * @returns {Promise<Object>} - Passwords result
   */
  async getAllPasswords() {
    if (this.isLocked) {
      return { 
        success: false, 
        error: 'Vault is locked'
      };
    }
    
    try {
      // Get all passwords
      const passwords = await storageService.getAllVaultItems();
      
      // Reset auto-lock timer
      this.resetAutoLockTimer(300000);
      
      return {
        success: true,
        passwords
      };
    } catch (error) {
      console.error('Error getting passwords:', error);
      return { 
        success: false, 
        error: error.message
      };
    }
  }

  /**
   * Generate a secure password
   * @param {Object} options - Password generation options
   * @returns {Object} - Generated password
   */
  generatePassword(options = {}) {
    try {
      // Generate password
      const password = passwordGenerator.generatePassword(options);
      
      // Analyze strength
      const strengthResult = strengthAnalyzer.analyzePassword(password);
      
      return {
        success: true,
        password,
        strength: strengthResult
      };
    } catch (error) {
      console.error('Error generating password:', error);
      return { 
        success: false, 
        error: error.message
      };
    }
  }

  /**
   * Generate a secure passphrase
   * @param {Object} options - Passphrase generation options
   * @returns {Object} - Generated passphrase
   */
  generatePassphrase(options = {}) {
    try {
      // Generate passphrase
      const passphrase = passwordGenerator.generatePassphrase(options);
      
      // Analyze strength
      const strengthResult = strengthAnalyzer.analyzePassword(passphrase);
      
      return {
        success: true,
        passphrase,
        strength: strengthResult
      };
    } catch (error) {
      console.error('Error generating passphrase:', error);
      return { 
        success: false, 
        error: error.message
      };
    }
  }

  /**
   * Check if a password has been compromised in known data breaches
   * @param {string} password - Password to check
   * @returns {Promise<Object>} - Breach check result
   */
  async checkPasswordBreach(password) {
    try {
      // Check for breaches
      const breachResult = await breachChecker.checkPassword(password);
      
      return {
        success: true,
        ...breachResult
      };
    } catch (error) {
      console.error('Error checking for breaches:', error);
      return { 
        success: false, 
        error: error.message
      };
    }
  }

  /**
   * Check all vault passwords for breaches
   * @returns {Promise<Object>} - Breach check results
   */
  async checkAllPasswordBreaches() {
    if (this.isLocked) {
      return { 
        success: false, 
        error: 'Vault is locked'
      };
    }
    
    try {
      // Get all passwords
      const passwordsResult = await this.getAllPasswords();
      if (!passwordsResult.success) {
        return passwordsResult;
      }
      
      const results = [];
      
      // Check each password
      for (const entry of passwordsResult.passwords) {
        const breachResult = await this.checkPasswordBreach(entry.password);
        
        if (breachResult.success && breachResult.breached) {
          results.push({
            id: entry.id,
            name: entry.name,
            website: entry.website,
            username: entry.username,
            breachCount: breachResult.occurrenceCount,
            message: breachResult.message
          });
        }
      }
      
      return {
        success: true,
        results,
        compromisedCount: results.length,
        totalChecked: passwordsResult.passwords.length
      };
    } catch (error) {
      console.error('Error checking all passwords for breaches:', error);
      return { 
        success: false, 
        error: error.message
      };
    }
  }

  /**
   * Recover vault using recovery key
   * @param {string} recoveryKey - Recovery key
   * @param {string} newMasterPassword - New master password
   * @returns {Promise<Object>} - Recovery result
   */
  async recoverVault(recoveryKey, newMasterPassword) {
    try {
      // Check if user exists
      const user = await storageService.getUser();
      if (!user || !user.recoveryKeyBackup) {
        return { 
          success: false, 
          error: 'Vault does not exist or no recovery key set'
        };
      }
      
      // Check new password strength
      const strengthResult = strengthAnalyzer.analyzePassword(newMasterPassword);
      if (strengthResult.score < 50) {
        return { 
          success: false, 
          error: 'New master password is too weak',
          strengthResult
        };
      }
      
      // Recover vault key using recovery key
      const vaultKey = await authService.recoverVaultKey(
        user.recoveryKeyBackup,
        recoveryKey
      );
      
      // Create new master password hash
      const newMasterPasswordHash = await authService.hashMasterPassword(newMasterPassword);
      
      // Create new salt for the vault key derivation
      const { salt: newVaultKeySalt } = await encryptionService.createVaultKey(newMasterPassword);
      
      // Generate a new recovery key
      const newRecoveryKey = authService.generateRecoveryKey();
      
      // Create new recovery key backup
      const newRecoveryKeyBackup = await authService.backupVaultKey(vaultKey, newRecoveryKey);
      
      // Update user data
      await storageService.saveUser({
        masterPasswordHash: newMasterPasswordHash,
        vaultKeySalt: newVaultKeySalt,
        recoveryKeyBackup: newRecoveryKeyBackup
      });
      
      // Reset failed attempts
      await this.updateFailedAttempts(0);
      
      // Set the vault key and unlock the vault
      this.setVaultKey(vaultKey);
      
      // Log the action
      await storageService.logAudit('Vault recovered');
      
      return {
        success: true,
        newRecoveryKey
      };
    } catch (error) {
      console.error('Error recovering vault:', error);
      return { 
        success: false, 
        error: 'Invalid recovery key or recovery failed'
      };
    }
  }

  /**
   * Change the master password
   * @param {string} currentMasterPassword - Current master password
   * @param {string} newMasterPassword - New master password
   * @returns {Promise<Object>} - Change result
   */
  async changeMasterPassword(currentMasterPassword, newMasterPassword) {
    try {
      // Verify current master password
      const unlockResult = await this.unlockVault(currentMasterPassword);
      if (!unlockResult.success) {
        return unlockResult;
      }
      
      // Check new password strength
      const strengthResult = strengthAnalyzer.analyzePassword(newMasterPassword);
      if (strengthResult.score < 50) {
        return { 
          success: false, 
          error: 'New master password is too weak',
          strengthResult
        };
      }
      
      // Get the current vault key
      const vaultKey = this.vaultKey;
      
      // Create new master password hash
      const newMasterPasswordHash = await authService.hashMasterPassword(newMasterPassword);
      
      // Create new salt for the vault key derivation
      const { salt: newVaultKeySalt } = await encryptionService.deriveKey(newMasterPassword);
      
      // Generate a new recovery key
      const newRecoveryKey = authService.generateRecoveryKey();
      
      // Create new recovery key backup
      const newRecoveryKeyBackup = await authService.backupVaultKey(vaultKey, newRecoveryKey);
      
      // Update user data
      await storageService.saveUser({
        masterPasswordHash: newMasterPasswordHash,
        vaultKeySalt: newVaultKeySalt,
        recoveryKeyBackup: newRecoveryKeyBackup
      });
      
      // Log the action
      await storageService.logAudit('Master password changed');
      
      return {
        success: true,
        newRecoveryKey
      };
    } catch (error) {
      console.error('Error changing master password:', error);
      return { 
        success: false, 
        error: error.message
      };
    }
  }
}

module.exports = new VaultManager(); 