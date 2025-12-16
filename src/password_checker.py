"""
Password strength validation utilities.
"""

import re
from typing import List, Tuple

class PasswordChecker:
    """Check password strength against common requirements."""
    
    @staticmethod
    def check_strength(password: str) -> Tuple[bool, List[str]]:
        """Check password strength and return issues."""
        issues = []
        
        if len(password) < 12:
            issues.append("Password should be at least 12 characters")
        
        if not re.search(r'[A-Z]', password):
            issues.append("Password should contain at least one uppercase letter")
        
        if not re.search(r'[a-z]', password):
            issues.append("Password should contain at least one lowercase letter")
        
        if not re.search(r'\d', password):
            issues.append("Password should contain at least one digit")
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            issues.append("Password should contain at least one special character")
        
        # Check for common patterns
        common_patterns = ['123', 'abc', 'qwerty', 'password', 'admin']
        if any(pattern in password.lower() for pattern in common_patterns):
            issues.append("Password contains common weak patterns")
        
        return len(issues) == 0, issues
    
    @staticmethod
    def estimate_crack_time(password: str) -> str:
        """Very basic crack time estimation."""
        # Simplified estimation - real calculation would be more complex
        length = len(password)
        charset = 0
        
        if re.search(r'[a-z]', password):
            charset += 26
        if re.search(r'[A-Z]', password):
            charset += 26
        if re.search(r'\d', password):
            charset += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            charset += 33
        
        if charset == 0:
            return "Very weak"
        
        # Very rough estimation
        combinations = charset ** length
        guesses_per_second = 1e9  # 1 billion guesses/sec for modern GPU
        
        seconds = combinations / guesses_per_second
        
        if seconds < 60:
            return "Seconds"
        elif seconds < 3600:
            return f"{seconds/60:.0f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.0f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.0f} days"
        else:
            return f"{seconds/31536000:.0f} years"
