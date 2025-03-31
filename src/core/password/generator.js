const crypto = require('crypto');

/**
 * Service for generating cryptographically secure passwords and passphrases
 */
class PasswordGenerator {
  constructor() {
    // Character sets for different password types
    this.charsets = {
      uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
      lowercase: 'abcdefghijklmnopqrstuvwxyz',
      numbers: '0123456789',
      symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
    };
    
    // Words for passphrase generation (common but secure words)
    this.words = [
      'apple', 'beach', 'cloud', 'dream', 'earth', 'flame', 'grass', 'house', 
      'image', 'judge', 'knife', 'level', 'money', 'night', 'ocean', 'paper', 
      'queen', 'river', 'stone', 'table', 'unity', 'value', 'water', 'xenon', 
      'youth', 'zebra', 'album', 'brake', 'chair', 'dance', 'eagle', 'fault', 
      'globe', 'heart', 'inbox', 'jewel', 'kiosk', 'light', 'music', 'north',
      'opera', 'plant', 'quark', 'radio', 'sugar', 'tiger', 'urban', 'voice',
      'wheel', 'xylophone', 'yacht', 'zesty'
      // Full dictionary would be much larger in production
    ];
  }

  /**
   * Generate a cryptographically secure random password
   * @param {Object} options - Password generation options
   * @param {number} options.length - Password length (default: 16)
   * @param {boolean} options.uppercase - Include uppercase letters (default: true)
   * @param {boolean} options.lowercase - Include lowercase letters (default: true)
   * @param {boolean} options.numbers - Include numbers (default: true)
   * @param {boolean} options.symbols - Include symbols (default: true)
   * @param {boolean} options.excludeSimilar - Exclude similar characters like 1, l, I, 0, O (default: false)
   * @param {string} options.exclude - Characters to exclude (default: '')
   * @returns {string} - Generated password
   */
  generatePassword(options = {}) {
    // Default options
    const opts = {
      length: options.length || 16,
      uppercase: options.uppercase !== false,
      lowercase: options.lowercase !== false,
      numbers: options.numbers !== false,
      symbols: options.symbols !== false,
      excludeSimilar: options.excludeSimilar || false,
      exclude: options.exclude || ''
    };

    // Characters to exclude
    const excludeChars = opts.exclude.split('');
    if (opts.excludeSimilar) {
      excludeChars.push(...'1lI0O'.split(''));
    }

    // Build charset based on options
    let charset = '';
    if (opts.uppercase) {
      charset += this.charsets.uppercase;
    }
    if (opts.lowercase) {
      charset += this.charsets.lowercase;
    }
    if (opts.numbers) {
      charset += this.charsets.numbers;
    }
    if (opts.symbols) {
      charset += this.charsets.symbols;
    }

    // Remove excluded characters from charset
    charset = charset
      .split('')
      .filter(char => !excludeChars.includes(char))
      .join('');

    if (charset.length === 0) {
      throw new Error('No characters available for password generation');
    }

    // Generate password
    return this.generateRandomString(charset, opts.length);
  }

  /**
   * Generate a passphrase with random words
   * @param {Object} options - Passphrase generation options
   * @param {number} options.wordCount - Number of words (default: 4)
   * @param {string} options.separator - Word separator (default: '-')
   * @param {boolean} options.capitalize - Capitalize each word (default: false)
   * @returns {string} - Generated passphrase
   */
  generatePassphrase(options = {}) {
    // Default options
    const opts = {
      wordCount: options.wordCount || 4,
      separator: options.separator || '-',
      capitalize: options.capitalize || false,
      includeNumber: options.includeNumber || false,
      includeSymbol: options.includeSymbol || false
    };

    // Select random words
    const selectedWords = [];
    for (let i = 0; i < opts.wordCount; i++) {
      const randomIndex = this.getSecureRandomInt(0, this.words.length - 1);
      let word = this.words[randomIndex];
      
      if (opts.capitalize) {
        word = word.charAt(0).toUpperCase() + word.slice(1);
      }
      
      selectedWords.push(word);
    }

    // Build passphrase
    let passphrase = selectedWords.join(opts.separator);

    // Add a number if requested
    if (opts.includeNumber) {
      passphrase += opts.separator + this.getSecureRandomInt(0, 999);
    }

    // Add a symbol if requested
    if (opts.includeSymbol) {
      const symbols = this.charsets.symbols;
      const randomSymbol = symbols.charAt(this.getSecureRandomInt(0, symbols.length - 1));
      passphrase += randomSymbol;
    }

    return passphrase;
  }

  /**
   * Generate a cryptographically secure random string
   * @param {string} charset - Character set to use
   * @param {number} length - Length of the string
   * @returns {string} - Random string
   */
  generateRandomString(charset, length) {
    const randomChars = [];
    const charsetLength = charset.length;

    // Get secure random values
    const randomValues = crypto.randomBytes(length);

    // Convert to characters from the charset
    for (let i = 0; i < length; i++) {
      const randomIndex = randomValues[i] % charsetLength;
      randomChars.push(charset.charAt(randomIndex));
    }

    return randomChars.join('');
  }

  /**
   * Generate a cryptographically secure random integer
   * @param {number} min - Minimum value (inclusive)
   * @param {number} max - Maximum value (inclusive)
   * @returns {number} - Random integer
   */
  getSecureRandomInt(min, max) {
    const range = max - min + 1;
    
    // Ensure unbiased random number
    const bitsNeeded = Math.ceil(Math.log2(range));
    const bytesNeeded = Math.ceil(bitsNeeded / 8);
    const mask = Math.pow(2, bitsNeeded) - 1;
    
    let randomValue;
    do {
      const randomBytes = crypto.randomBytes(bytesNeeded);
      randomValue = 0;
      
      // Convert bytes to number
      for (let i = 0; i < bytesNeeded; i++) {
        randomValue = (randomValue << 8) | randomBytes[i];
      }
      
      // Apply mask to get only the bits we need
      randomValue = randomValue & mask;
    } while (randomValue >= range);
    
    return min + randomValue;
  }
}

module.exports = new PasswordGenerator(); 