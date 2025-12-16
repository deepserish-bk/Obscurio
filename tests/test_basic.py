import unittest
from src.obscurio import Vault, Credential

class TestObscurio(unittest.TestCase):
    def test_vault_creation(self):
        vault = Vault("test_vault.enc")
        self.assertEqual(vault.vault_path, "test_vault.enc")
        self.assertTrue(vault.is_locked)
    
    def test_credential_creation(self):
        cred = Credential("GitHub", "user", "pass")
        self.assertEqual(cred.service, "GitHub")
        self.assertEqual(cred.username, "user")

if __name__ == "__main__":
    unittest.main()
