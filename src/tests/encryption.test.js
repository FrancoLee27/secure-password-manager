const encryptionService = require('../core/encryption/encryption');
const config = require('../core/encryption/config');
const crypto = require('crypto');

describe('Encryption Service', () => {
  test('deriveKey should derive key from password with correct length', async () => {
    const password = 'TestPassword123!';
    const { key, salt } = await encryptionService.deriveKey(password);
    
    expect(key).toBeInstanceOf(Buffer);
    expect(key.length).toBe(config.KEY_LENGTH);
    expect(salt).toBeInstanceOf(Buffer);
    expect(salt.length).toBe(config.SALT_LENGTH);
  });
  
  test('deriveKey should derive same key with same password and salt', async () => {
    const password = 'TestPassword123!';
    const salt = crypto.randomBytes(config.SALT_LENGTH);
    
    const result1 = await encryptionService.deriveKey(password, salt);
    const result2 = await encryptionService.deriveKey(password, salt);
    
    expect(result1.key.toString('hex')).toBe(result2.key.toString('hex'));
    expect(result1.salt.toString('hex')).toBe(result2.salt.toString('hex'));
  });
  
  test('deriveKey should derive different keys with different passwords', async () => {
    const password1 = 'TestPassword123!';
    const password2 = 'DifferentPassword456@';
    const salt = crypto.randomBytes(config.SALT_LENGTH);
    
    const result1 = await encryptionService.deriveKey(password1, salt);
    const result2 = await encryptionService.deriveKey(password2, salt);
    
    expect(result1.key.toString('hex')).not.toBe(result2.key.toString('hex'));
  });
  
  test('encrypt should encrypt data with expected format', () => {
    const key = crypto.randomBytes(config.KEY_LENGTH);
    const data = 'Secret data to encrypt';
    
    const encryptedData = encryptionService.encrypt(key, data);
    
    expect(encryptedData).toHaveProperty('encrypted');
    expect(encryptedData).toHaveProperty('iv');
    expect(encryptedData).toHaveProperty('authTag');
    expect(typeof encryptedData.encrypted).toBe('string');
    expect(typeof encryptedData.iv).toBe('string');
    expect(typeof encryptedData.authTag).toBe('string');
  });
  
  test('decrypt should correctly decrypt encrypted data', () => {
    const key = crypto.randomBytes(config.KEY_LENGTH);
    const originalData = 'Secret data to encrypt';
    
    const encryptedData = encryptionService.encrypt(key, originalData);
    const decryptedData = encryptionService.decrypt(key, encryptedData);
    
    expect(decryptedData).toBe(originalData);
  });
  
  test('encrypt and decrypt should work with objects', () => {
    const key = crypto.randomBytes(config.KEY_LENGTH);
    const originalData = { 
      username: 'testuser', 
      password: 'secretpassword',
      url: 'https://example.com',
      tags: ['personal', 'important']
    };
    
    const encryptedData = encryptionService.encrypt(key, originalData);
    const decryptedData = encryptionService.decrypt(key, encryptedData);
    
    expect(decryptedData).toEqual(originalData);
  });
  
  test('decrypt should fail with wrong key', () => {
    const correctKey = crypto.randomBytes(config.KEY_LENGTH);
    const wrongKey = crypto.randomBytes(config.KEY_LENGTH);
    const originalData = 'Secret data to encrypt';
    
    const encryptedData = encryptionService.encrypt(correctKey, originalData);
    
    expect(() => {
      encryptionService.decrypt(wrongKey, encryptedData);
    }).toThrow();
  });
  
  test('secureWipe should overwrite buffer data', () => {
    const buffer = Buffer.from('sensitive-data');
    const originalContent = Buffer.from(buffer);
    
    encryptionService.secureWipe(buffer);
    
    // Check that buffer no longer contains the original content
    expect(buffer.equals(originalContent)).toBe(false);
    
    // Check that buffer is filled with zeros
    const zeroFilled = Buffer.alloc(buffer.length, 0);
    expect(buffer.equals(zeroFilled)).toBe(true);
  });
}); 