"""
Password generator.
Generates cryptographically secure passwords and passphrases.
"""

import os
import random
import string
import sys

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


class PasswordGenerator:
    """Generates secure random passwords and passphrases"""
    
    def __init__(self):
        """Initialize the password generator"""
        # Define character sets
        self.uppercase_chars = string.ascii_uppercase
        self.lowercase_chars = string.ascii_lowercase
        self.digit_chars = string.digits
        self.symbol_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?/~"
        self.similar_chars = "iIl1Lo0O"
        
        # Load common words for passphrases
        self.common_words = [
            # Common English words for passphrases (4-8 letters)
            "apple", "baker", "cable", "dance", "eagle", "fable", "garden", "house",
            "igloo", "jumbo", "kiosk", "lemon", "music", "north", "ocean", "paper",
            "queen", "river", "sugar", "table", "uncle", "voice", "water", "xenon",
            "yacht", "zebra", "actor", "brave", "cloud", "dream", "event", "focus",
            "glass", "happy", "input", "judge", "knife", "light", "money", "night",
            "opera", "plane", "quiet", "radio", "storm", "train", "unity", "video",
            "woman", "youth", "album", "beach", "candy", "diary", "earth", "field",
            "guide", "horse", "image", "jewel", "kings", "lunch", "magic", "novel",
            "orbit", "peace", "quest", "robot", "space", "tiger", "urban", "value",
            "wagon", "xylophone", "young", "zesty", "amber", "basic", "coral", "draft",
            "enjoy", "flour", "grape", "hotel", "ivory", "joint", "kayak", "liver",
            "major", "noble", "oasis", "pearl", "quick", "royal", "solid", "trust",
            "ultra", "vital", "world", "xerox", "yield", "zones", "award", "blend",
            "craft", "dwell", "essay", "flute", "glide", "haste", "index", "joker",
            "knack", "lotus", "maker", "nerve", "onion", "pride", "quote", "relay"
        ]
    
    def generate_password(self, options=None):
        """
        Generate a secure random password
        
        Args:
            options (dict, optional): Options for password generation
                - length (int): Length of the password (default: 16)
                - uppercase (bool): Include uppercase letters (default: True)
                - lowercase (bool): Include lowercase letters (default: True)
                - numbers (bool): Include numbers (default: True)
                - symbols (bool): Include symbols (default: True)
                - exclude_similar (bool): Exclude similar characters (default: False)
                - exclude (str): Characters to exclude
                
        Returns:
            str: Generated password
        """
        # Set default options
        if options is None:
            options = {}
        
        length = options.get('length', 16)
        include_uppercase = options.get('uppercase', True)
        include_lowercase = options.get('lowercase', True)
        include_numbers = options.get('numbers', True)
        include_symbols = options.get('symbols', True)
        exclude_similar = options.get('exclude_similar', False)
        exclude_chars = options.get('exclude', '')
        
        # Prepare character pool
        char_pool = ""
        required_chars = []
        
        if include_uppercase:
            pool = self._remove_excluded_chars(self.uppercase_chars, exclude_chars, exclude_similar)
            char_pool += pool
            if pool:  # Only add a required character if there are characters left after exclusion
                required_chars.append(self._secure_random_choice(pool))
        
        if include_lowercase:
            pool = self._remove_excluded_chars(self.lowercase_chars, exclude_chars, exclude_similar)
            char_pool += pool
            if pool:
                required_chars.append(self._secure_random_choice(pool))
        
        if include_numbers:
            pool = self._remove_excluded_chars(self.digit_chars, exclude_chars, exclude_similar)
            char_pool += pool
            if pool:
                required_chars.append(self._secure_random_choice(pool))
        
        if include_symbols:
            pool = self._remove_excluded_chars(self.symbol_chars, exclude_chars, exclude_similar)
            char_pool += pool
            if pool:
                required_chars.append(self._secure_random_choice(pool))
        
        # Ensure we have characters to work with
        if not char_pool:
            raise ValueError("No characters available after applying exclusions")
        
        # Generate the password
        password = []
        
        # Add required characters first
        password.extend(required_chars)
        
        # Fill the rest with random characters
        for _ in range(length - len(required_chars)):
            password.append(self._secure_random_choice(char_pool))
        
        # Shuffle the password to mix the required characters randomly
        self._secure_shuffle(password)
        
        return ''.join(password)
    
    def generate_passphrase(self, options=None):
        """
        Generate a secure random passphrase
        
        Args:
            options (dict, optional): Options for passphrase generation
                - word_count (int): Number of words (default: 4)
                - capitalize (bool): Capitalize words (default: True)
                - include_number (bool): Include a number (default: True)
                - include_symbol (bool): Include a symbol (default: True)
                - delimiter (str): Word delimiter (default: '-')
                
        Returns:
            str: Generated passphrase
        """
        # Set default options
        if options is None:
            options = {}
        
        word_count = options.get('word_count', 4)
        capitalize = options.get('capitalize', True)
        include_number = options.get('include_number', True)
        include_symbol = options.get('include_symbol', True)
        delimiter = options.get('delimiter', '-')
        
        # Select random words
        words = []
        for _ in range(word_count):
            word = self._secure_random_choice(self.common_words)
            
            # Capitalize if enabled
            if capitalize:
                word = word.capitalize()
            
            words.append(word)
        
        # Add a number if enabled
        if include_number:
            position = self._secure_random_int(0, len(words))
            number = str(self._secure_random_int(0, 9999))
            words.insert(position, number)
        
        # Add a symbol if enabled
        if include_symbol:
            position = self._secure_random_int(0, len(words))
            symbol = self._secure_random_choice(self.symbol_chars)
            words.insert(position, symbol)
        
        # Join words with delimiter
        return delimiter.join(words)
    
    def _remove_excluded_chars(self, char_set, exclude_chars, exclude_similar):
        """
        Remove excluded characters from a character set
        
        Args:
            char_set (str): Character set to filter
            exclude_chars (str): Characters to exclude
            exclude_similar (bool): Whether to exclude similar characters
            
        Returns:
            str: Filtered character set
        """
        result = char_set
        
        # Remove explicitly excluded characters
        for char in exclude_chars:
            result = result.replace(char, '')
        
        # Remove similar characters if requested
        if exclude_similar:
            for char in self.similar_chars:
                result = result.replace(char, '')
        
        return result
    
    def _secure_random_choice(self, sequence):
        """
        Make a cryptographically secure random choice from a sequence
        
        Args:
            sequence (sequence): Sequence to choose from
            
        Returns:
            Any: Random element from the sequence
        """
        if not sequence:
            raise ValueError("Cannot choose from an empty sequence")
        
        return sequence[self._secure_random_int(0, len(sequence) - 1)]
    
    def _secure_random_int(self, min_value, max_value):
        """
        Generate a cryptographically secure random integer
        
        Args:
            min_value (int): Minimum value inclusive
            max_value (int): Maximum value inclusive
            
        Returns:
            int: Random integer
        """
        return random.SystemRandom().randint(min_value, max_value)
    
    def _secure_shuffle(self, sequence):
        """
        Shuffle a sequence using cryptographically secure randomness
        
        Args:
            sequence (list): Sequence to shuffle
            
        Returns:
            None: Shuffles in place
        """
        system_random = random.SystemRandom()
        system_random.shuffle(sequence)


# Singleton instance
password_generator = PasswordGenerator()


# Top-level functions for easier importing
def generate_password(options=None):
    """
    Generate a secure random password (convenience function)
    
    Args:
        options (dict, optional): Options for password generation
            
    Returns:
        str: Generated password
    """
    return password_generator.generate_password(options)


def generate_passphrase(options=None):
    """
    Generate a secure random passphrase (convenience function)
    
    Args:
        options (dict, optional): Options for passphrase generation
            
    Returns:
        str: Generated passphrase
    """
    return password_generator.generate_passphrase(options) 