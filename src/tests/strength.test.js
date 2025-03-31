const strengthAnalyzer = require('../core/password/strength');

describe('Password Strength Analyzer', () => {
  test('should return zero score for empty password', () => {
    const result = strengthAnalyzer.analyzePassword('');
    expect(result.score).toBe(0);
    expect(result.strength).toBe('Very Weak');
  });
  
  test('should calculate entropy correctly based on character sets', () => {
    // Only lowercase (poolSize = 26)
    const lowerOnly = strengthAnalyzer.analyzePassword('abcdefgh');
    
    // Lowercase + uppercase (poolSize = 52)
    const lowerUpper = strengthAnalyzer.analyzePassword('abcdEFGH');
    
    // Lowercase + uppercase + numbers (poolSize = 62)
    const lowerUpperNum = strengthAnalyzer.analyzePassword('abcDEF123');
    
    // All character sets (poolSize = 95)
    const allSets = strengthAnalyzer.analyzePassword('abCD12#$');
    
    expect(lowerOnly.entropy).toBeLessThan(lowerUpper.entropy);
    expect(lowerUpper.entropy).toBeLessThan(lowerUpperNum.entropy);
    expect(lowerUpperNum.entropy).toBeLessThan(allSets.entropy);
    
    // Verify exact entropy calculations
    // E = L × log₂(R)
    expect(lowerOnly.rawEntropy).toBeCloseTo(8 * Math.log2(26), 1);
    expect(allSets.rawEntropy).toBeCloseTo(8 * Math.log2(95), 1);
  });
  
  test('should identify common patterns in passwords', () => {
    const commonPatterns = [
      'password123',
      '12345678',
      'qwerty1',
      'abcdef',
      'admin123'
    ];
    
    commonPatterns.forEach(password => {
      const result = strengthAnalyzer.analyzePassword(password);
      expect(result.patterns.length).toBeGreaterThan(0);
    });
  });
  
  test('should apply penalties for common patterns', () => {
    const withPattern = strengthAnalyzer.analyzePassword('password123');
    const noPattern = strengthAnalyzer.analyzePassword('j5K8$mPq2@');
    
    // Both have similar length but withPattern should have lower score due to penalty
    expect(withPattern.score).toBeLessThan(noPattern.score);
    expect(withPattern.entropy).toBeLessThan(withPattern.rawEntropy);
  });
  
  test('should detect character repetition', () => {
    const withRepetition = strengthAnalyzer.analyzePassword('aabbccdd11');
    expect(withRepetition.repetition.repeatedChars.length).toBe(6); // a, b, c, d, 1 each appears twice
    
    const withSequentialRepetition = strengthAnalyzer.analyzePassword('aaabbbccc');
    expect(withSequentialRepetition.repetition.sequentialRepeats.length).toBe(3); // aaa, bbb, ccc
  });
  
  test('should apply penalties for repetition', () => {
    const withRepetition = strengthAnalyzer.analyzePassword('aaaabbbb');
    const noRepetition = strengthAnalyzer.analyzePassword('abcdefgh');
    
    // Same length and character set, but withRepetition should have lower score
    expect(withRepetition.score).toBeLessThan(noRepetition.score);
    expect(withRepetition.entropy).toBeLessThan(withRepetition.rawEntropy);
  });
  
  test('should categorize passwords correctly', () => {
    const veryWeak = strengthAnalyzer.analyzePassword('123');
    const weak = strengthAnalyzer.analyzePassword('password');
    const medium = strengthAnalyzer.analyzePassword('Password123');
    const strong = strengthAnalyzer.analyzePassword('P@ssw0rd!123');
    const veryStrong = strengthAnalyzer.analyzePassword('P@$$w0rd!123#%^&*()_+');
    
    expect(veryWeak.strength).toBe('Very Weak');
    expect(weak.strength).toBe('Weak');
    expect(medium.strength).toBe('Medium');
    expect(strong.strength).toBe('Strong');
    expect(veryStrong.strength).toBe('Very Strong');
  });
  
  test('should provide helpful feedback for weak passwords', () => {
    const shortPassword = strengthAnalyzer.analyzePassword('abc123');
    expect(shortPassword.feedback.length).toBeGreaterThan(0);
    expect(shortPassword.feedback.some(fb => fb.includes('too short'))).toBe(true);
    
    const repeatedPassword = strengthAnalyzer.analyzePassword('aaaabbbb');
    expect(repeatedPassword.feedback.some(fb => fb.includes('repeated'))).toBe(true);
    
    const patternPassword = strengthAnalyzer.analyzePassword('password123');
    expect(patternPassword.feedback.some(fb => fb.includes('common patterns'))).toBe(true);
  });
  
  test('should recognize passwords with substitutions', () => {
    const withSubstitutions = strengthAnalyzer.analyzePassword('p@$$w0rd');
    expect(withSubstitutions.patterns.length).toBeGreaterThan(0);
    expect(withSubstitutions.patterns.some(p => p.includes('with substitutions'))).toBe(true);
  });
  
  test('should analyze length impact on password strength', () => {
    const short = strengthAnalyzer.analyzePassword('Aa1!');
    const medium = strengthAnalyzer.analyzePassword('Aa1!Bb2@');
    const long = strengthAnalyzer.analyzePassword('Aa1!Bb2@Cc3#Dd4$');
    
    // Same character set diversity but different lengths
    expect(short.score).toBeLessThan(medium.score);
    expect(medium.score).toBeLessThan(long.score);
  });
}); 