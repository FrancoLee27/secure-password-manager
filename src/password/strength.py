"""
Password strength analyzer.
Evaluates password strength using various criteria.
"""

import re
import sys
import os
import math

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


class StrengthAnalyzer:
    """Analyzes password strength using multiple factors"""
    
    def __init__(self):
        """Initialize the strength analyzer"""
        # Patterns for different character types
        self.patterns = {
            'uppercase': r'[A-Z]',
            'lowercase': r'[a-z]',
            'numbers': r'[0-9]',
            'symbols': r'[^A-Za-z0-9]'
        }
        
        # Common patterns to penalize
        self.common_patterns = [
            r'12345',
            r'qwerty',
            r'asdf',
            r'password',
            r'admin',
            r'welcome',
            r'letmein',
            r'monkey',
            r'abc123',
            r'111111',
            r'123123',
            r'123321',
            r'654321'
        ]
        
        # Common words to penalize
        self.common_words = [
            'password', 'admin', 'welcome', 'login', 'user', 
            'guest', 'qwerty', 'letmein', 'monkey', 'dragon',
            'baseball', 'football', 'master', 'sunshine', 'iloveyou',
            'princess', 'rockyou', 'shadow', 'superman', 'butterfly',
            'trustno', 'jennifer', 'hunter', 'ranger', 'harley'
        ]
    
    def calculate_entropy(self, password):
        """
        Calculate the information entropy of a password
        
        Args:
            password (str): The password to analyze
            
        Returns:
            float: The calculated entropy
        """
        # Count character classes used
        char_classes = 0
        
        if re.search(self.patterns['uppercase'], password):
            char_classes += 26
        
        if re.search(self.patterns['lowercase'], password):
            char_classes += 26
        
        if re.search(self.patterns['numbers'], password):
            char_classes += 10
        
        if re.search(self.patterns['symbols'], password):
            char_classes += 33  # Approximate number of common symbols
        
        # If no character classes are detected, default to lowercase (minimum)
        if char_classes == 0:
            char_classes = 26
        
        # Calculate entropy: log2(char_classes^length)
        # Equivalent to: length * log2(char_classes)
        entropy = len(password) * math.log2(char_classes)
        
        return entropy
    
    def has_common_patterns(self, password):
        """
        Check if the password contains common patterns
        
        Args:
            password (str): The password to check
            
        Returns:
            bool: True if common patterns found
        """
        password_lower = password.lower()
        
        # Check for common patterns
        for pattern in self.common_patterns:
            if re.search(pattern, password_lower):
                return True
        
        # Check for common words
        for word in self.common_words:
            if word in password_lower:
                return True
        
        # Check for sequences
        for i in range(len(password) - 2):
            # Check for character sequences like 'abc', '123', etc.
            if (ord(password[i+1]) - ord(password[i]) == 1 and
                ord(password[i+2]) - ord(password[i+1]) == 1):
                return True
            
            # Check for reverse sequences
            if (ord(password[i]) - ord(password[i+1]) == 1 and
                ord(password[i+1]) - ord(password[i+2]) == 1):
                return True
            
            # Check for repeated characters
            if password[i] == password[i+1] and password[i+1] == password[i+2]:
                return True
        
        return False
    
    def analyze_password(self, password):
        """
        Analyze password strength
        
        Args:
            password (str): The password to analyze
            
        Returns:
            dict: Analysis results with score and feedback
        """
        if not password:
            return {
                'score': 0,
                'strength': 'Very Weak',
                'feedback': 'Password cannot be empty.'
            }
        
        # Calculate base score
        score = 0
        feedback = []
        
        # Length check
        if len(password) < 8:
            score -= 1
            feedback.append("Use at least 8 characters.")
        elif len(password) >= 12:
            score += 1
        
        if len(password) >= 16:
            score += 1
        
        # Character type checks
        has_upper = bool(re.search(self.patterns['uppercase'], password))
        has_lower = bool(re.search(self.patterns['lowercase'], password))
        has_numbers = bool(re.search(self.patterns['numbers'], password))
        has_symbols = bool(re.search(self.patterns['symbols'], password))
        
        char_types_count = sum([has_upper, has_lower, has_numbers, has_symbols])
        
        if char_types_count <= 1:
            score -= 1
            feedback.append("Use a mix of character types (uppercase, lowercase, numbers, symbols).")
        elif char_types_count >= 3:
            score += 1
        
        if char_types_count == 4:
            score += 1
        
        # Entropy calculation
        entropy = self.calculate_entropy(password)
        
        if entropy < 40:
            score -= 1
        elif entropy >= 60:
            score += 1
        
        if entropy >= 80:
            score += 1
        
        # Common pattern check
        if self.has_common_patterns(password):
            score -= 2
            feedback.append("Avoid common patterns and dictionary words.")
        
        # Adjust final score to be between 0 and 4
        final_score = max(0, min(4, score + 2))  # Base score is 2
        
        # Determine strength label
        strength_labels = {
            0: 'Very Weak',
            1: 'Weak',
            2: 'Moderate',
            3: 'Strong',
            4: 'Very Strong'
        }
        
        strength = strength_labels[final_score]
        
        # Add general feedback if no specific issues were found
        if not feedback:
            if final_score <= 2:
                feedback.append("Consider using a longer password with more varied characters.")
            else:
                feedback.append("Good password practices detected.")
        
        return {
            'score': final_score,
            'strength': strength,
            'feedback': " ".join(feedback)
        }


# Singleton instance
strength_analyzer = StrengthAnalyzer()


# Top-level function for easier importing
def analyze_password(password):
    """
    Analyze password strength (convenience function)
    
    Args:
        password (str): The password to analyze
        
    Returns:
        dict: Analysis results with score and feedback
    """
    return strength_analyzer.analyze_password(password) 