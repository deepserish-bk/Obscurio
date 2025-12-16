"""
Custom exceptions for Obscurio.
"""

class ObscurioError(Exception):
    """Base exception for Obscurio."""
    pass

class EncryptionError(ObscurioError):
    """Encryption/decryption related errors."""
    pass

class VaultError(ObscurioError):
    """Vault file operation errors."""
    pass

class AuthenticationError(ObscurioError):
    """Password authentication failures."""
    pass

class IntegrityError(ObscurioError):
    """Data integrity check failures."""
    pass
