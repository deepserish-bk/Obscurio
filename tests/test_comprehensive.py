#!/usr/bin/env python3
"""
Comprehensive tests for Obscurio password manager.
"""

import pytest
import tempfile
import os
import json
import base64
from unittest.mock import patch, MagicMock

from src.obscurio import (
    Vault, Credential, EncryptionManager,
    main, print_banner, interactive_menu
)
from src.errors import EncryptionError
from src.password_checker import PasswordChecker
from src.logger import SecurityLogger, security_logger


class TestPasswordChecker:
    """Test password strength checking."""
    
    def test_strong_password(self):
        """Test that strong passwords pass all checks."""
        strong_passwords = [
            "StrongPass123!@#",
            "AnotherGood1$Password",
            "Test1234!abcdefg"
        ]
        
        for password in strong_passwords:
            is_strong, issues = PasswordChecker.check_strength(password)
            assert is_strong == True, f"Password '{password}' should be strong"
            assert issues == [], f"Password '{password}' should have no issues"
    
    def test_weak_passwords(self):
        """Test that weak passwords are correctly identified."""
        weak_cases = [
            ("short", ["Password should be at least 12 characters"]),
            ("nouppercase123!", ["Password should contain at least one uppercase letter"]),
            ("NOLOWERCASE123!", ["Password should contain at least one lowercase letter"]),
            ("NoDigitsHere!", ["Password should contain at least one digit"]),
            ("NoSpecial123", ["Password should contain at least one special character"]),
            ("password123!", ["Password contains common weak patterns"]),
        ]
        
        for password, expected_issues in weak_cases:
            is_strong, issues = PasswordChecker.check_strength(password)
            assert is_strong == False, f"Password '{password}' should be weak"
            # Check that at least one expected issue is found
            assert any(issue in str(issues) for issue in expected_issues), \
                f"Password '{password}' should have issues: {expected_issues}"
    
    def test_crack_time_estimation(self):
        """Test crack time estimation (basic)."""
        # Simple smoke test
        estimations = []
        for pwd in ["a", "abc", "Password123!", "VeryLongPassword123!@#$%"]:
            estimation = PasswordChecker.estimate_crack_time(pwd)
            estimations.append((pwd, estimation))
            assert isinstance(estimation, str)
            assert len(estimation) > 0
        
        # Longer passwords should have longer crack times
        short_est = PasswordChecker.estimate_crack_time("a")
        long_est = PasswordChecker.estimate_crack_time("VeryLongPassword123!@#$%")
        # Note: This is a qualitative check, not quantitative
        print(f"Crack time estimates: '{short_est}' vs '{long_est}'")


class TestEncryptionManager:
    """Test cryptographic operations."""
    
    def setup_method(self):
        """Create encryption manager for each test."""
        self.manager = EncryptionManager()
        self.test_key = b'\x00' * 32  # Test key for AES-256
        self.test_salt = b'\x11' * 16
    
    def test_generate_salt(self):
        """Test salt generation."""
        salt = self.manager.generate_salt()
        assert isinstance(salt, bytes)
        assert len(salt) == self.manager.salt_size
    
    def test_generate_nonce(self):
        """Test nonce generation."""
        nonce = self.manager.generate_nonce()
        assert isinstance(nonce, bytes)
        assert len(nonce) == self.manager.nonce_size
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test that encryption and decryption work correctly together."""
        test_data = "Test secret data 123!@#"
        
        # Encrypt
        encrypted, nonce_b64 = self.manager.encrypt_data(self.test_key, test_data)
        
        # Verify outputs
        assert isinstance(encrypted, str)
        assert isinstance(nonce_b64, str)
        
        # Should be base64 encoded
        try:
            base64.b64decode(encrypted)
            base64.b64decode(nonce_b64)
        except Exception:
            pytest.fail("Encrypted data or nonce not valid base64")
        
        # Decrypt
        decrypted = self.manager.decrypt_data(self.test_key, encrypted, nonce_b64)
        
        # Should get original data back
        assert decrypted == test_data
    
    def test_decrypt_failure(self):
        """Test decryption fails with wrong key or corrupted data."""
        # Encrypt some data
        test_data = "Test data"
        encrypted, nonce_b64 = self.manager.encrypt_data(self.test_key, test_data)
        
        # Try with wrong key
        wrong_key = b'\xff' * 32
        with pytest.raises(ValueError, match="Decryption failed"):
            self.manager.decrypt_data(wrong_key, encrypted, nonce_b64)
        
        # Try with corrupted data
        corrupted_data = "not_base64_data"
        with pytest.raises(ValueError):
            self.manager.decrypt_data(self.test_key, corrupted_data, nonce_b64)


class TestVault:
    """Test vault operations."""
    
    def setup_method(self):
        """Create temporary vault file for each test."""
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
        self.temp_file.close()
        self.vault_path = self.temp_file.name
    
    def teardown_method(self):
        """Clean up temporary files."""
        if os.path.exists(self.vault_path):
            os.unlink(self.vault_path)
    
    def test_vault_initialization(self):
        """Test vault creation with default values."""
        vault = Vault(self.vault_path)
        
        assert vault.vault_path == self.vault_path
        assert vault.credentials == {}
        assert vault.master_key is None
        assert vault.salt is None
        assert vault.is_locked is True
        assert vault.version == "1.0"
    
    def test_create_vault(self):
        """Test creating a new vault."""
        vault = Vault(self.vault_path)
        
        # Vault shouldn't exist yet
        assert not os.path.exists(self.vault_path)
        
        # Create vault
        result = vault.create_vault("TestPassword123!")
        assert result is True
        assert vault.is_locked is False
        assert vault.salt is not None
        assert vault.master_key is not None
        
        # Vault file should now exist
        assert os.path.exists(self.vault_path)
    
    def test_create_existing_vault(self):
        """Test that creating existing vault fails."""
        vault = Vault(self.vault_path)
        
        # Create first vault
        vault.create_vault("TestPassword123!")
        
        # Try to create again
        vault2 = Vault(self.vault_path)
        result = vault2.create_vault("AnotherPassword")
        assert result is False  # Should fail
    
    @patch('builtins.input', return_value='')
    @patch('getpass.getpass', side_effect=['TestPassword123!', 'TestPassword123!'])
    def test_vault_lifecycle(self, mock_getpass, mock_input):
        """Test complete vault lifecycle: create, add, retrieve, lock."""
        vault = Vault(self.vault_path)
        
        # Create vault
        success = vault.create_vault("TestPassword123!")
        assert success is True
        
        # Add credential
        vault.add_credential("GitHub", "testuser", "testpass123", url="https://github.com")
        
        # Verify credential was added
        assert "GitHub" in vault.credentials
        cred = vault.credentials["GitHub"]
        assert cred.service == "GitHub"
        assert cred.url == "https://github.com"
        
        # Retrieve credential (mocking user input for getpass if needed)
        result = vault.get_credential("GitHub")
        assert result is not None
        username, password = result
        assert username == "testuser"
        assert password == "testpass123"
        
        # Lock vault
        vault.lock()
        assert vault.is_locked is True
        assert vault.master_key is None
        
        # Should not be able to retrieve when locked
        result = vault.get_credential("GitHub")
        assert result is None
    
    def test_auto_lock(self):
        """Test auto-lock functionality."""
        vault = Vault(self.vault_path)
        
        # Create and unlock vault
        vault.create_vault("TestPassword123!")
        
        # Mock time to simulate inactivity
        with patch('src.obscurio.datetime') as mock_datetime:
            from datetime import datetime, timedelta
            
            # Set current time to 10 minutes in the future
            future_time = datetime.now() + timedelta(minutes=10)
            mock_datetime.now.return_value = future_time
            
            # Try to get credential - should auto-lock
            result = vault.get_credential("NonExistent")
            assert result is None
            assert vault.is_locked is True


class TestIntegration:
    """Integration tests for full application flow."""
    
    def setup_method(self):
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
        self.temp_file.close()
        self.vault_path = self.temp_file.name
    
    def teardown_method(self):
        if os.path.exists(self.vault_path):
            os.unlink(self.vault_path)
    
    @patch('builtins.input')
    @patch('getpass.getpass')
    @patch('builtins.print')
    def test_main_with_new_vault(self, mock_print, mock_getpass, mock_input):
        """Test main function creating new vault."""
        # Mock user choices: create vault, then exit
        mock_input.side_effect = ['y', '6']  # Create vault, then exit
        mock_getpass.side_effect = ['TestPassword123!', 'TestPassword123!', '']
        
        # Temporarily modify vault path
        original_main = main
        with patch('src.obscurio.Vault') as MockVault:
            mock_vault_instance = MagicMock()
            mock_vault_instance.vault_path = self.vault_path
            mock_vault_instance.is_locked = False
            MockVault.return_value = mock_vault_instance
            
            # Mock os.path.exists to return False (no existing vault)
            with patch('os.path.exists', return_value=False):
                # Should run without errors
                try:
                    main()
                    assert True
                except SystemExit:
                    pass  # Expected if main calls sys.exit()
                except Exception as e:
                    pytest.fail(f"main() raised unexpected exception: {e}")


def test_security_logger():
    """Test security logging functionality."""
    # Create logger with temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix='.log') as temp_log:
        temp_log.close()
        logger = SecurityLogger(temp_log.name)
        
        # Log some events
        logger.log_vault_access("unlock", True)
        logger.log_credential_access("GitHub", "retrieved")
        logger.log_security_event("Failed login attempt", "3 attempts from 192.168.1.1")
        
        # Verify log file was created and has content
        assert os.path.exists(temp_log.name)
        with open(temp_log.name, 'r') as f:
            content = f.read()
            assert "vault unlock" in content.lower()
            assert "credential" in content.lower()
            assert "security event" in content.lower()
        
        # Clean up
        os.unlink(temp_log.name)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
