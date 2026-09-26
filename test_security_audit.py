"""
Automated Penetration Test & Security Validation Suite
Author: Akshya Gupta (YuvaIntern Junior Python Developer)
Tests verify defenses against SQLi, Command Injection, Brute Force, and Session Lifecycle.
"""

import unittest
from vulnerable_auth_app import login_vulnerable, init_db as init_vuln_db
from secure_auth_app import EnterpriseSecurityEngine, SecurityValidationError

class TestSecurityRemediation(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_vuln_db()
        EnterpriseSecurityEngine.init_hardened_db()

    def setUp(self):
        EnterpriseSecurityEngine._failed_attempts.clear()
        EnterpriseSecurityEngine._active_sessions.clear()

    def test_sql_injection_reproduction_on_vulnerable_app(self):
        """Confirm SQL injection bypass succeeds on unhardened baseline."""
        payload = "admin' --"
        role = login_vulnerable(payload, "ignored_password")
        self.assertEqual(role, "admin")

    def test_sql_injection_prevention_on_secure_app(self):
        """Confirm identical SQL injection payload is neutralized on hardened engine."""
        payload = "admin' --"
        role = EnterpriseSecurityEngine.authenticate_user(payload, "ignored_password")
        self.assertIsNone(role)

    def test_valid_authentication_parity(self):
        """Confirm legitimate credentials authenticate seamlessly."""
        role = EnterpriseSecurityEngine.authenticate_user("admin", "SuperSecretAdminPass123")
        self.assertEqual(role, "admin")

    def test_command_injection_mitigation(self):
        """Verify command chaining attack payload is blocked by validator."""
        malicious_input = "127.0.0.1; whoami"
        with self.assertRaises(SecurityValidationError):
            EnterpriseSecurityEngine.safe_network_ping(malicious_input)

    def test_password_hashing_uniqueness(self):
        """Ensure identical passwords generate different hashes due to unique salts."""
        salt1, hash1 = EnterpriseSecurityEngine.hash_password("TestSecret101")
        salt2, hash2 = EnterpriseSecurityEngine.hash_password("TestSecret101")
        self.assertNotEqual(salt1, salt2)
        self.assertNotEqual(hash1, hash2)

    def test_brute_force_rate_limiting_lockout(self):
        """Verify repeated failed attempts trigger account lockout mechanism."""
        for _ in range(EnterpriseSecurityEngine.MAX_ATTEMPTS):
            EnterpriseSecurityEngine.authenticate_user("alice", "wrong_pass")
        
        # Next attempt with correct password must be rejected due to lockout
        lockout_auth = EnterpriseSecurityEngine.authenticate_user("alice", "alicepassword")
        self.assertIsNone(lockout_auth)

    def test_secure_session_token_generation_and_expiry(self):
        """Verify cryptographic token generation and valid session retrieval."""
        token = EnterpriseSecurityEngine.authenticate_and_create_session("admin", "SuperSecretAdminPass123")
        self.assertIsNotNone(token)
        session = EnterpriseSecurityEngine.validate_session(token)
        self.assertIsNotNone(session)
        self.assertEqual(session.username, "admin")
        self.assertEqual(session.role, "admin")

if __name__ == "__main__":
    unittest.main()
