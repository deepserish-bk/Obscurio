"""
Security logging for audit trail.
"""

import logging
from datetime import datetime
from typing import Optional

class SecurityLogger:
    """Log security-relevant events."""
    
    def __init__(self, log_file: str = "obscurio_audit.log"):
        self.logger = logging.getLogger('obscurio_security')
        self.logger.setLevel(logging.INFO)
        
        # File handler
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        fh.setFormatter(formatter)
        
        self.logger.addHandler(fh)
    
    def log_vault_access(self, action: str, success: bool, ip: Optional[str] = None):
        """Log vault access attempts."""
        ip_info = f" from {ip}" if ip else ""
        status = "SUCCESS" if success else "FAILED"
        self.logger.info(f"Vault {action}{ip_info} - {status}")
    
    def log_credential_access(self, service: str, action: str):
        """Log credential access."""
        self.logger.info(f"Credential {action} for service: {service}")
    
    def log_security_event(self, event: str, details: str = ""):
        """Log general security events."""
        details_str = f" - {details}" if details else ""
        self.logger.warning(f"Security event: {event}{details_str}")

# Global logger instance
security_logger = SecurityLogger()
