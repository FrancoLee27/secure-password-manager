/**
 * Service for analyzing password strength using entropy
 * and pattern detection
 */
class PasswordStrengthAnalyzer {
  constructor() {
    this.commonPatterns = [
      // Sequential patterns
      'abcdef', 'qwerty', 'asdfgh', 'zxcvbn', '123456', '654321',
      
      // Keyboard patterns
      'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1qaz2wsx', 'qazwsx',
      
      // Common date formats
      /\d{2}\/\d{2}\/\d{2,4}/,  // DD/MM/YYYY
      /\d{2}\-\d{2}\-\d{2,4}/,  // DD-MM-YYYY
      /\d{2}\.\d{2}\.\d{2,4}/,  // DD.MM.YYYY
      
      // Common words
      'password', 'admin', 'welcome', 'letmein', 'monkey', 'dragon',
      'football', 'baseball', 'superman', 'batman', 'trustno1'
    ];
    
    // Common substitutions
    this.substitutions = {
      'a': ['@', '4'],
      'b': ['8'],
      'e': ['3'],
      'i': ['1', '!'],
      'l': ['1', '|'],
      'o': ['0'],
      's': ['$', '5'],
      't': ['+', '7'],
      'z': ['2']
    };
  }

  /**
   * Calculate password strength using entropy formula E = L × log₂(R)
   * where L is password length and R is pool size
   * @param {string} password - The password to analyze
   * @returns {Object} - Password strength details
   */
  analyzePassword(password) {
    if (!password || password.length === 0) {
      return {
        score: 0,
        entropy: 0,
        strength: 'Very Weak',
        poolSize: 0,
        feedback: 'Please enter a password.'
      };
    }

    // Calculate character pool size
    const poolSize = this.calculatePoolSize(password);
    
    // Calculate entropy
    const entropy = this.calculateEntropy(password.length, poolSize);
    
    // Check for common patterns
    const patternMatch = this.checkForPatterns(password);
    
    // Check for repetition
    const repetition = this.checkForRepetition(password);
    
    // Apply penalties
    let adjustedEntropy = entropy;
    if (patternMatch.found) {
      adjustedEntropy *= 0.5;  // 50% penalty for common patterns
    }
    
    if (repetition.found) {
      adjustedEntropy *= 0.7;  // 30% penalty for repetition
    }
    
    // Determine score (0-100)
    const score = this.calculateScore(adjustedEntropy);
    
    // Determine strength category
    const strength = this.determineStrength(score);
    
    // Generate feedback
    const feedback = this.generateFeedback(score, patternMatch, repetition, password.length);
    
    return {
      score,
      entropy: Math.round(adjustedEntropy * 100) / 100,
      rawEntropy: Math.round(entropy * 100) / 100,
      strength,
      poolSize,
      patterns: patternMatch.patterns,
      repetition: repetition.details,
      feedback
    };
  }

  /**
   * Calculate character pool size based on the characters used
   * @param {string} password - The password
   * @returns {number} - The pool size
   */
  calculatePoolSize(password) {
    let hasLowercase = false;
    let hasUppercase = false;
    let hasDigits = false;
    let hasSymbols = false;
    
    for (let i = 0; i < password.length; i++) {
      const char = password.charAt(i);
      
      if (/[a-z]/.test(char)) {
        hasLowercase = true;
      } else if (/[A-Z]/.test(char)) {
        hasUppercase = true;
      } else if (/[0-9]/.test(char)) {
        hasDigits = true;
      } else {
        hasSymbols = true;
      }
    }
    
    let poolSize = 0;
    if (hasLowercase) poolSize += 26;  // a-z
    if (hasUppercase) poolSize += 26;  // A-Z
    if (hasDigits) poolSize += 10;     // 0-9
    if (hasSymbols) poolSize += 33;    // Special characters
    
    return poolSize;
  }

  /**
   * Calculate entropy using the formula E = L × log₂(R)
   * @param {number} length - Password length
   * @param {number} poolSize - Character pool size
   * @returns {number} - Entropy in bits
   */
  calculateEntropy(length, poolSize) {
    if (poolSize <= 1) return 0;
    return length * (Math.log(poolSize) / Math.log(2));
  }

  /**
   * Check if password contains common patterns
   * @param {string} password - The password to check
   * @returns {Object} - Pattern match details
   */
  checkForPatterns(password) {
    const lowerPassword = password.toLowerCase();
    const foundPatterns = [];
    
    // Check for common patterns
    for (const pattern of this.commonPatterns) {
      if (pattern instanceof RegExp) {
        if (pattern.test(password)) {
          foundPatterns.push('Format pattern');
        }
      } else {
        if (lowerPassword.includes(pattern)) {
          foundPatterns.push(pattern);
        }
      }
    }
    
    // Check for variations with substitutions
    const normalizedPassword = this.normalizePassword(lowerPassword);
    for (const pattern of this.commonPatterns) {
      if (typeof pattern === 'string' && normalizedPassword.includes(pattern)) {
        foundPatterns.push(`${pattern} (with substitutions)`);
      }
    }
    
    return {
      found: foundPatterns.length > 0,
      patterns: foundPatterns
    };
  }

  /**
   * Normalize password by reversing common character substitutions
   * @param {string} password - The password to normalize
   * @returns {string} - Normalized password
   */
  normalizePassword(password) {
    let normalized = password;
    
    // Replace substitutions with original characters
    for (const [original, subs] of Object.entries(this.substitutions)) {
      for (const sub of subs) {
        normalized = normalized.replace(new RegExp(sub, 'g'), original);
      }
    }
    
    return normalized;
  }

  /**
   * Check for character repetition in the password
   * @param {string} password - The password to check
   * @returns {Object} - Repetition details
   */
  checkForRepetition(password) {
    // Check for repeated characters
    const charCounts = {};
    for (const char of password) {
      charCounts[char] = (charCounts[char] || 0) + 1;
    }
    
    // Count repeated characters
    const repeatedChars = Object.entries(charCounts)
      .filter(([_, count]) => count > 1)
      .map(([char, count]) => ({char, count}));
    
    // Check for sequential repeated characters (e.g., "aaa", "111")
    const sequentialRegex = /(.)\1{2,}/g;
    const sequentialMatches = [...password.matchAll(sequentialRegex)]
      .map(match => ({sequence: match[0], length: match[0].length}));
    
    return {
      found: repeatedChars.length > 0 || sequentialMatches.length > 0,
      details: {
        repeatedChars,
        sequentialRepeats: sequentialMatches
      }
    };
  }

  /**
   * Calculate score (0-100) based on entropy
   * @param {number} entropy - Password entropy
   * @returns {number} - Score from 0-100
   */
  calculateScore(entropy) {
    // Score thresholds
    // <40 bits: weak, 40-60 bits: medium, 60-80 bits: strong, >80 bits: very strong
    if (entropy <= 0) return 0;
    if (entropy >= 100) return 100;
    
    // Mapping entropy to score
    if (entropy < 40) {
      // 0-40 entropy maps to 0-50 score
      return Math.floor((entropy / 40) * 50);
    } else if (entropy < 60) {
      // 40-60 entropy maps to 50-75 score
      return Math.floor(50 + ((entropy - 40) / 20) * 25);
    } else if (entropy < 80) {
      // 60-80 entropy maps to 75-90 score
      return Math.floor(75 + ((entropy - 60) / 20) * 15);
    } else {
      // 80-100 entropy maps to 90-100 score
      return Math.floor(90 + ((entropy - 80) / 20) * 10);
    }
  }

  /**
   * Determine password strength category
   * @param {number} score - Password score (0-100)
   * @returns {string} - Strength category
   */
  determineStrength(score) {
    if (score < 20) return 'Very Weak';
    if (score < 50) return 'Weak';
    if (score < 75) return 'Medium';
    if (score < 90) return 'Strong';
    return 'Very Strong';
  }

  /**
   * Generate feedback based on password analysis
   * @param {number} score - Password score
   * @param {Object} patternMatch - Pattern match details
   * @param {Object} repetition - Repetition details
   * @param {number} length - Password length
   * @returns {Array<string>} - Feedback messages
   */
  generateFeedback(score, patternMatch, repetition, length) {
    const feedback = [];
    
    // Length feedback
    if (length < 8) {
      feedback.push('Password is too short. Use at least 8 characters.');
    } else if (length < 12) {
      feedback.push('Consider using a longer password for better security.');
    }
    
    // Pattern feedback
    if (patternMatch.found) {
      feedback.push('Password contains common patterns that are easy to guess.');
    }
    
    // Repetition feedback
    if (repetition.found) {
      if (repetition.details.sequentialRepeats.length > 0) {
        feedback.push('Avoid repeated sequences of characters.');
      }
      if (repetition.details.repeatedChars.length > 0) {
        feedback.push('Using the same character multiple times weakens your password.');
      }
    }
    
    // General feedback based on score
    if (score < 50) {
      feedback.push('Mix uppercase, lowercase, numbers, and symbols.');
    } else if (score < 75 && length < 16) {
      feedback.push('Consider using a longer password with more varied characters.');
    } else if (score >= 90) {
      feedback.push('Excellent password strength!');
    }
    
    return feedback;
  }
}

module.exports = new PasswordStrengthAnalyzer(); 