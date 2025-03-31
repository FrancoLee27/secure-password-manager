const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const encryptionService = require('../encryption/encryption');

/**
 * Storage service for securely managing encrypted data
 */
class StorageService {
  constructor() {
    this.db = null;
    this.vaultKey = null;
  }

  /**
   * Initialize the database
   * @param {string} dbPath - Path to the database file
   * @returns {Promise<void>}
   */
  async initialize(dbPath) {
    return new Promise((resolve, reject) => {
      // Ensure directory exists
      const dir = path.dirname(dbPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      this.db = new sqlite3.Database(dbPath, async (err) => {
        if (err) {
          reject(err);
          return;
        }

        try {
          await this.setupTables();
          resolve();
        } catch (err) {
          reject(err);
        }
      });
    });
  }

  /**
   * Set up the database tables
   * @returns {Promise<void>}
   */
  async setupTables() {
    return new Promise((resolve, reject) => {
      this.db.serialize(() => {
        // User table with master password hash and salt
        this.db.run(`CREATE TABLE IF NOT EXISTS user (
          id INTEGER PRIMARY KEY,
          master_password_hash TEXT NOT NULL,
          vault_key_salt TEXT NOT NULL,
          recovery_key_backup TEXT,
          failed_attempts INTEGER DEFAULT 0,
          last_access INTEGER
        )`);

        // Encrypted vault data
        this.db.run(`CREATE TABLE IF NOT EXISTS vault (
          id INTEGER PRIMARY KEY,
          encrypted_data TEXT NOT NULL,
          iv TEXT NOT NULL,
          auth_tag TEXT NOT NULL,
          updated_at INTEGER NOT NULL
        )`);

        // Categories for organizing passwords
        this.db.run(`CREATE TABLE IF NOT EXISTS categories (
          id INTEGER PRIMARY KEY,
          encrypted_data TEXT NOT NULL,
          iv TEXT NOT NULL,
          auth_tag TEXT NOT NULL,
          updated_at INTEGER NOT NULL
        )`);

        // Tags for additional organization
        this.db.run(`CREATE TABLE IF NOT EXISTS tags (
          id INTEGER PRIMARY KEY,
          encrypted_data TEXT NOT NULL,
          iv TEXT NOT NULL,
          auth_tag TEXT NOT NULL,
          updated_at INTEGER NOT NULL
        )`);

        // Security questions for recovery
        this.db.run(`CREATE TABLE IF NOT EXISTS security_questions (
          id INTEGER PRIMARY KEY,
          question_id INTEGER NOT NULL,
          encrypted_question TEXT NOT NULL,
          question_iv TEXT NOT NULL,
          question_auth_tag TEXT NOT NULL,
          answer_hash TEXT NOT NULL,
          created_at INTEGER NOT NULL
        )`);

        // Audit log for sensitive operations
        this.db.run(`CREATE TABLE IF NOT EXISTS audit_log (
          id INTEGER PRIMARY KEY,
          action TEXT NOT NULL,
          timestamp INTEGER NOT NULL,
          metadata TEXT
        )`);
      }, (err) => {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      });
    });
  }

  /**
   * Set the vault encryption key
   * @param {Buffer} key - The encryption key
   */
  setVaultKey(key) {
    this.vaultKey = Buffer.from(key);
  }

  /**
   * Clear the vault key from memory
   */
  clearVaultKey() {
    if (this.vaultKey) {
      encryptionService.secureWipe(this.vaultKey);
      this.vaultKey = null;
    }
  }

  /**
   * Save user data
   * @param {Object} userData - User data including master password hash and salt
   * @returns {Promise<void>}
   */
  async saveUser(userData) {
    return new Promise((resolve, reject) => {
      const { masterPasswordHash, vaultKeySalt, recoveryKeyBackup } = userData;
      
      this.db.run(
        `INSERT OR REPLACE INTO user 
        (id, master_password_hash, vault_key_salt, recovery_key_backup, last_access) 
        VALUES (1, ?, ?, ?, ?)`,
        [
          masterPasswordHash, 
          vaultKeySalt.toString('base64'), 
          recoveryKeyBackup ? JSON.stringify(recoveryKeyBackup) : null,
          Date.now()
        ],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
  }

  /**
   * Get user data
   * @returns {Promise<Object>} - User data
   */
  async getUser() {
    return new Promise((resolve, reject) => {
      this.db.get(
        'SELECT * FROM user WHERE id = 1',
        (err, row) => {
          if (err) {
            reject(err);
          } else if (!row) {
            resolve(null);
          } else {
            resolve({
              masterPasswordHash: row.master_password_hash,
              vaultKeySalt: Buffer.from(row.vault_key_salt, 'base64'),
              recoveryKeyBackup: row.recovery_key_backup ? JSON.parse(row.recovery_key_backup) : null,
              failedAttempts: row.failed_attempts,
              lastAccess: row.last_access
            });
          }
        }
      );
    });
  }

  /**
   * Save an item to the vault
   * @param {Object} item - The item to save
   * @returns {Promise<number>} - The ID of the saved item
   */
  async saveVaultItem(item) {
    if (!this.vaultKey) {
      throw new Error('Vault is locked. Cannot save item.');
    }

    const encryptedData = encryptionService.encrypt(this.vaultKey, item);
    const timestamp = Date.now();

    return new Promise((resolve, reject) => {
      if (item.id) {
        // Update existing item
        this.db.run(
          `UPDATE vault 
          SET encrypted_data = ?, iv = ?, auth_tag = ?, updated_at = ? 
          WHERE id = ?`,
          [
            encryptedData.encrypted, 
            encryptedData.iv, 
            encryptedData.authTag, 
            timestamp,
            item.id
          ],
          function(err) {
            if (err) reject(err);
            else resolve(item.id);
          }
        );
      } else {
        // Insert new item
        this.db.run(
          `INSERT INTO vault 
          (encrypted_data, iv, auth_tag, updated_at) 
          VALUES (?, ?, ?, ?)`,
          [
            encryptedData.encrypted, 
            encryptedData.iv, 
            encryptedData.authTag, 
            timestamp
          ],
          function(err) {
            if (err) reject(err);
            else resolve(this.lastID);
          }
        );
      }
    });
  }

  /**
   * Get all items from the vault
   * @returns {Promise<Array>} - Array of decrypted vault items
   */
  async getAllVaultItems() {
    if (!this.vaultKey) {
      throw new Error('Vault is locked. Cannot retrieve items.');
    }

    return new Promise((resolve, reject) => {
      this.db.all(
        'SELECT id, encrypted_data, iv, auth_tag, updated_at FROM vault',
        (err, rows) => {
          if (err) {
            reject(err);
            return;
          }

          try {
            const items = rows.map(row => {
              const decrypted = encryptionService.decrypt(this.vaultKey, {
                encrypted: row.encrypted_data,
                iv: row.iv,
                authTag: row.auth_tag
              });
              
              // Add the database ID and updated timestamp to the decrypted item
              decrypted.id = row.id;
              decrypted.updatedAt = row.updated_at;
              
              return decrypted;
            });
            
            resolve(items);
          } catch (e) {
            reject(e);
          }
        }
      );
    });
  }

  /**
   * Delete an item from the vault
   * @param {number} id - The ID of the item to delete
   * @returns {Promise<void>}
   */
  async deleteVaultItem(id) {
    return new Promise((resolve, reject) => {
      this.db.run(
        'DELETE FROM vault WHERE id = ?',
        [id],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
  }

  /**
   * Record an action in the audit log
   * @param {string} action - The action performed
   * @param {Object} metadata - Additional metadata about the action
   * @returns {Promise<void>}
   */
  async logAudit(action, metadata = {}) {
    return new Promise((resolve, reject) => {
      this.db.run(
        'INSERT INTO audit_log (action, timestamp, metadata) VALUES (?, ?, ?)',
        [action, Date.now(), JSON.stringify(metadata)],
        (err) => {
          if (err) reject(err);
          else resolve();
        }
      );
    });
  }

  /**
   * Close the database connection
   * @returns {Promise<void>}
   */
  async close() {
    this.clearVaultKey();
    
    return new Promise((resolve, reject) => {
      if (this.db) {
        this.db.close((err) => {
          if (err) reject(err);
          else {
            this.db = null;
            resolve();
          }
        });
      } else {
        resolve();
      }
    });
  }
}

module.exports = new StorageService(); 