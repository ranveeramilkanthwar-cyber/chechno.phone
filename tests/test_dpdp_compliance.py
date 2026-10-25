"""
Unit Tests for PrivaIndia DPDP Act 2023 Compliance & Self-Healing Engine
"""
import sys
import unittest
from pathlib import Path

# Add root and services to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from services.api_gateway.main import (
    blind_hash_phone,
    blind_hash_email,
    CANONICAL_BROKERS,
    generate_statutory_erasure_notice
)
from services.worker_fleet.dom_self_healer import (
    score_dom_element,
    resolve_best_selector
)

class TestPrivaIndiaCompliance(unittest.TestCase):

    def test_blind_indexing_deterministic(self):
        """Verify HMAC-SHA256 blind index is deterministic and 64 hex chars."""
        h1 = blind_hash_phone("9820471920")
        h2 = blind_hash_phone("+91-98204-71920")
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)

    def test_blind_indexing_email(self):
        h1 = blind_hash_email("Ranveer.Privacy@Proton.ME")
        h2 = blind_hash_email("ranveer.privacy@proton.me")
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)

    def test_canonical_17_brokers(self):
        """Ensure all 17 canonical Indian brokers and directories are accounted for."""
        self.assertEqual(len(CANONICAL_BROKERS), 17)
        removable_count = sum(1 for b in CANONICAL_BROKERS if b.is_removable)
        exempt_count = sum(1 for b in CANONICAL_BROKERS if not b.is_removable)
        self.assertEqual(removable_count, 15)
        self.assertEqual(exempt_count, 2)
        
        # Verify MCA & Gazette are marked exempt under Sec 3(c)(ii)
        mca = next(b for b in CANONICAL_BROKERS if b.id == "BRK-16")
        self.assertFalse(mca.is_removable)
        self.assertEqual(mca.opt_out_channel, "EXEMPT")

    def test_statutory_notice_generation(self):
        """Verify DPDP Section 12(3) notice contains statutory citations."""
        broker = CANONICAL_BROKERS[0]
        notice = generate_statutory_erasure_notice(
            full_name="Ranveer Sharma",
            phone_e164="+919820471920",
            email="ranveer.privacy@proton.me",
            broker=broker,
            artefact_code="DPDP-IN-2026-88419A"
        )
        self.assertIn("SECTION 12(3)", notice)
        self.assertIn("DPDP ACT 2023", notice)
        self.assertIn("Ranveer Sharma", notice)
        self.assertIn("72 hours", notice)

    def test_dom_self_healer_resolution(self):
        """Test shadow DOM heuristic recovery of broken scraper selectors."""
        candidates = [
            {"tag": "div", "text": "Advertisement", "id": "banner-ad", "visible": True},
            {"tag": "button", "text": "Opt Out & Delete My Data", "id": "btn-custom-remove", "visible": True},
            {"tag": "a", "text": "Home", "id": "nav-home", "visible": True}
        ]
        failed_selector = "button.optout-submit-v1"
        best = resolve_best_selector(candidates, failed_selector)
        self.assertEqual(best, "#btn-custom-remove")
    
    def test_database_persistence_and_blind_hash(self):
        """Test persistent SQLite vault operations and blind indexing."""
        from services.db import get_connection, blind_hash_phone
        conn = get_connection()
        b_hash = blind_hash_phone("9820471920")
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO users (id, phone_blind_hash, masked_phone, full_name, telecom_circle, created_at) "
                "VALUES ('test-user-01', ?, '+91 98****1920', 'Ranveer Test', 'MH_MUMBAI', '2026-10-25T00:00:00Z')",
                (b_hash,)
            )
            row = conn.execute("SELECT * FROM users WHERE phone_blind_hash = ?", (b_hash,)).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["masked_phone"], "+91 98****1920")
        conn.close()

    def test_live_broker_probing_structure(self):
        """Test broker probing metadata and evidence calculation."""
        import asyncio
        from services.broker_engine import scan_all_brokers
        results = asyncio.run(scan_all_brokers("9820471920", "Ranveer Sharma", "MH_MUMBAI"))
        self.assertEqual(len(results), 17)
        for r in results:
            self.assertIn("evidenceHash", r)
            self.assertEqual(len(r["evidenceHash"]), 64)
            self.assertIn("status", r)
            if not r["removable"]:
                self.assertEqual(r["status"], "NOT_REMOVABLE")

    def test_erasure_dispatcher_execution(self):
        """Test erasure dispatcher creates verifiable statutory receipts."""
        import asyncio
        from services.db import get_connection
        from services.erasure_dispatcher import dispatch_erasure_requests
        
        # Prepare scan & listing
        conn = get_connection()
        scan_id = "test-scan-exec"
        with conn:
            conn.execute("INSERT OR REPLACE INTO scans (id, user_id, consent_id, status, started_at) VALUES (?, 'u1', 'c1', 'COMPLETED', 'now')", (scan_id,))
            conn.execute(
                "INSERT OR REPLACE INTO exposure_listings "
                "(id, scan_id, broker_id, broker_name, domain, category, exposed_fields, removable, selected, status, opt_out_channel, dpo_email, evidence_hash, detected_at, updated_at) "
                "VALUES ('listing-test-01', ?, 'BRK-01', 'BajajFin LeadMart DSA', 'leadmart-dsa.in', 'DSA Loan/Credit', '[]', 1, 1, 'EXPOSED', 'REST_WEBHOOK', 'privacy@leadmart.in', 'hash', 'now', 'now')",
                (scan_id,)
            )
        conn.close()

        receipts = asyncio.run(dispatch_erasure_requests(
            scan_id=scan_id,
            broker_ids=["BRK-01"],
            full_name="Ranveer Sharma",
            phone_e164="+919820471920",
            email="ranveer@test.me",
            artefact_code="DPDP-IN-2026-TEST"
        ))
        self.assertEqual(len(receipts), 1)
        self.assertTrue(receipts[0]["receiptCode"].startswith("REC-DPDP-"))
        self.assertEqual(receipts[0]["status"], "REMOVED")

if __name__ == "__main__":
    unittest.main()

