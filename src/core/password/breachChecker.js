const crypto = require('crypto');
const https = require('https');

/**
 * Service for checking if passwords have been compromised in known data breaches
 * using the "Have I Been Pwned" API with k-anonymity model for privacy
 */
class BreachChecker {
  constructor() {
    this.pwnedApiUrl = 'https://api.pwnedpasswords.com/range/';
    this.userAgent = 'SecurePasswordManager/1.0';
  }

  /**
   * Check if a password has been compromised in known data breaches
   * @param {string} password - The password to check
   * @returns {Promise<Object>} - Breach check results
   */
  async checkPassword(password) {
    try {
      // Generate SHA-1 hash of the password
      const sha1Hash = this.hashPassword(password);
      
      // Split the hash into prefix and suffix for k-anonymity
      const prefix = sha1Hash.substring(0, 5);
      const suffix = sha1Hash.substring(5).toUpperCase();
      
      // Get all hash suffixes that match the prefix
      const matchingHashes = await this.getMatchingHashes(prefix);
      
      // Check if our suffix is in the results
      const match = matchingHashes.find(hash => hash.suffix === suffix);
      
      return {
        breached: match !== undefined,
        occurrenceCount: match ? match.count : 0,
        message: this.generateMessage(match)
      };
    } catch (error) {
      console.error('Error checking for breaches:', error);
      return {
        breached: false,
        occurrenceCount: 0,
        message: 'Unable to check password against known breaches',
        error: error.message
      };
    }
  }

  /**
   * Hash a password using SHA-1 (for HIBP API compatibility only)
   * @param {string} password - The password to hash
   * @returns {string} - SHA-1 hash of the password
   */
  hashPassword(password) {
    return crypto
      .createHash('sha1')
      .update(password)
      .digest('hex')
      .toUpperCase();
  }

  /**
   * Query HIBP API with k-anonymity to get matching hash suffixes
   * @param {string} hashPrefix - First 5 characters of password hash
   * @returns {Promise<Array>} - Matching hash suffixes with counts
   */
  async getMatchingHashes(hashPrefix) {
    return new Promise((resolve, reject) => {
      const requestOptions = {
        headers: {
          'User-Agent': this.userAgent
        }
      };
      
      const req = https.get(
        `${this.pwnedApiUrl}${hashPrefix}`,
        requestOptions,
        (res) => {
          if (res.statusCode !== 200) {
            reject(new Error(`HIBP API request failed: ${res.statusCode}`));
            return;
          }
          
          let data = '';
          res.on('data', (chunk) => {
            data += chunk;
          });
          
          res.on('end', () => {
            try {
              // Parse response into hash suffix and count pairs
              const results = data
                .split('\r\n')
                .filter(line => line.length > 0)
                .map(line => {
                  const [suffix, countStr] = line.split(':');
                  return {
                    suffix,
                    count: parseInt(countStr, 10)
                  };
                });
              
              resolve(results);
            } catch (error) {
              reject(error);
            }
          });
        }
      );
      
      req.on('error', (error) => {
        reject(error);
      });
      
      req.end();
    });
  }

  /**
   * Generate a message based on breach check results
   * @param {Object|undefined} match - Matching hash data
   * @returns {string} - Result message
   */
  generateMessage(match) {
    if (!match) {
      return 'Good news! This password hasn\'t been found in any known data breaches.';
    }
    
    if (match.count === 1) {
      return 'Warning: This password has been found in 1 data breach. It is recommended to choose a different password.';
    }
    
    let severityLevel = 'Warning';
    if (match.count > 1000) {
      severityLevel = 'Critical';
    } else if (match.count > 100) {
      severityLevel = 'Severe';
    } else if (match.count > 10) {
      severityLevel = 'High Risk';
    }
    
    return `${severityLevel}: This password has been found in ${match.count.toLocaleString()} data breaches. You should definitely choose a different password.`;
  }
}

module.exports = new BreachChecker(); 