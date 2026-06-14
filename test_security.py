import unittest
import json
from app import app
from database import init_db, execute_query
import capability
import encryption

class AegisSecurityTestSuite(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        # Initialize database schemas
        init_db()
        
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
        
        # Clean sandbox databases and insert fresh test users
        execute_query("DELETE FROM users WHERE username IN ('test_user_a', 'test_user_b')")
        execute_query("DELETE FROM vault_data")
        execute_query("DELETE FROM attack_logs")
        
        # Create user A
        import bcrypt
        pw_hash = bcrypt.hashpw(b"password123", bcrypt.gensalt()).decode("utf-8")
        self.user_a_id = execute_query(
            "INSERT INTO users (username, password_hash) VALUES ('test_user_a', ?)", 
            (pw_hash,)
        )
        # Create user B
        self.user_b_id = execute_query(
            "INSERT INTO users (username, password_hash) VALUES ('test_user_b', ?)", 
            (pw_hash,)
        )
        
        # Generate capabilities for User A
        self.read_cap_a = capability.generate_capability_code(self.user_a_id, "vault:read")
        self.write_cap_a = capability.generate_capability_code(self.user_a_id, "vault:write")
        
        # Seed sensitive record for User B (which User A shouldn't see)
        key_b = encryption.get_encryption_key("test_user_b")
        cipher_b = encryption.encrypt_data("SSN-OF-USER-B: 999-00-1111", key_b)
        execute_query(
            "INSERT INTO vault_data (user_id, title, encrypted_content) VALUES (?, 'B Secret', ?)",
            (self.user_b_id, cipher_b)
        )
        
        # Seed sensitive record for User A
        key_a = encryption.get_encryption_key("test_user_a")
        cipher_a = encryption.encrypt_data("SSN-OF-USER-A: 000-22-3333", key_a)
        self.item_a_id = execute_query(
            "INSERT INTO vault_data (user_id, title, encrypted_content) VALUES (?, 'A Secret', ?)",
            (self.user_a_id, cipher_a)
        )

    def test_normal_query_success(self):
        """1. NORMAL CASE: Valid query with correct capability code returns data successfully."""
        # Log in as test_user_a
        self.app.post("/api/login", json={"username": "test_user_a", "password": "password123"})
        
        # Query simulation endpoint with safe payload
        response = self.app.post("/api/simulate", json={
            "payload": "A Secret",
            "capability_code": self.read_cap_a,
            "waf_enabled": True,
            "parameterized_enabled": True,
            "decryption_enabled": True,
            "capability_check_enabled": True
        })
        
        data = json.loads(response.data.decode("utf-8"))
        self.assertEqual(data["status"], "SUCCESS")
        self.assertEqual(len(data["results"]), 1)
        self.assertEqual(data["results"][0]["title"], "A Secret")
        self.assertEqual(data["results"][0]["encrypted_content"], "SSN-OF-USER-A: 000-22-3333")

    def test_layer1_waf_blocks_sqli(self):
        """2. LAYER 1: SQL Injection payload is blocked at WAF (threat filter)."""
        self.app.post("/api/login", json={"username": "test_user_a", "password": "password123"})
        
        # SQLi payload
        payload = "' OR 1=1 --"
        response = self.app.post("/api/simulate", json={
            "payload": payload,
            "capability_code": self.read_cap_a,
            "waf_enabled": True, # WAF active
            "parameterized_enabled": True,
            "decryption_enabled": True,
            "capability_check_enabled": True
        })
        
        data = json.loads(response.data.decode("utf-8"))
        self.assertEqual(data["status"], "BLOCKED")
        self.assertIn("WAF", data["message"])
        self.assertTrue(data["threat_score"] >= 3)
        self.assertEqual(data["results"], [])

    def test_layer2_parameterization_blocks_sqli_even_with_waf_off(self):
        """3. LAYER 2: If Layer 1 (WAF) is disabled, Parameterized Queries neutralize the SQLi attack."""
        self.app.post("/api/login", json={"username": "test_user_a", "password": "password123"})
        
        # SQLi payload
        payload = "' OR 1=1 --"
        response = self.app.post("/api/simulate", json={
            "payload": payload,
            "capability_code": self.read_cap_a,
            "waf_enabled": False, # Layer 1 bypassed!
            "parameterized_enabled": True, # Layer 2 parameterization active
            "decryption_enabled": True,
            "capability_check_enabled": True
        })
        
        data = json.loads(response.data.decode("utf-8"))
        self.assertEqual(data["status"], "SUCCESS") # Execution finishes without crashing
        self.assertEqual(data["results"], []) # No rows matched title like payload

    def test_layer2_aes_encryption_protects_confidentiality_during_full_sqli(self):
        """4. LAYER 2: If WAF is OFF and Parameterization is OFF (vulnerable query runs),
        the data remains secure because it is AES encrypted and cannot be decrypted without User B's key."""
        self.app.post("/api/login", json={"username": "test_user_a", "password": "password123"})
        
        # Injected search to dump all vault rows with balanced parentheses
        payload = "') OR 1=1 --"
        response = self.app.post("/api/simulate", json={
            "payload": payload,
            "capability_code": self.read_cap_a,
            "waf_enabled": False, # Layer 1 disabled
            "parameterized_enabled": False, # Layer 2 parameterized queries disabled (vulnerable!)
            "decryption_enabled": True, # Request tries to decrypt columns
            "capability_check_enabled": True
        })
        
        data = json.loads(response.data.decode("utf-8"))
        self.assertEqual(data["status"], "SUCCESS")
        
        # We got rows from both user A and user B due to successful SQLi injection!
        self.assertEqual(len(data["results"]), 2)
        
        # Let's inspect rows
        row_a = next(r for r in data["results"] if r["title"] == "A Secret")
        row_b = next(r for r in data["results"] if r["title"] == "B Secret")
        
        # Row A belongs to test_user_a, so it decrypts fine
        self.assertEqual(row_a["encrypted_content"], "SSN-OF-USER-A: 000-22-3333")
        
        # Row B belongs to test_user_b, so attempting to decrypt with key of user_a fails!
        # This checks that AES key separation holds confidentiality.
        self.assertTrue(row_b["encrypted_content"].startswith("[Decryption Failed"))

    def test_capability_code_authorization(self):
        """5. LAYER 2: Request with unauthorized capability code is rejected."""
        self.app.post("/api/login", json={"username": "test_user_a", "password": "password123"})
        
        # Query simulation with invalid capability code
        response = self.app.post("/api/simulate", json={
            "payload": "A Secret",
            "capability_code": "CAP-READ-FAKE12345678", # FAKE
            "waf_enabled": True,
            "parameterized_enabled": True,
            "decryption_enabled": True,
            "capability_check_enabled": True # Capability Check active
        })
        
        data = json.loads(response.data.decode("utf-8"))
        self.assertEqual(data["status"], "UNAUTHORIZED")
        self.assertIn("Capability Code", data["message"])
        self.assertEqual(data["results"], [])

if __name__ == "__main__":
    unittest.main()
