"""
PrivaIndia Database & Cryptographic Identity Ledger
Zero-Plaintext Blind Indexing (HMAC-SHA256) & Persistent SQLite Storage.
DPDP Act 2023 Compliant.
"""
import sqlite3
import hmac
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

DB_PATH = Path(__file__).parent.parent / "privaindia.db"
KMS_PEPPER = os.getenv("KMS_BLIND_INDEX_PEPPER", "in-dpdp-sovereign-pepper-2026").encode("utf-8")

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def blind_hash(val: str) -> str:
    """HMAC-SHA256 blind indexing for sensitive identifiers."""
    clean = val.strip().lower()
    return hmac.new(KMS_PEPPER, clean.encode("utf-8"), hashlib.sha256).hexdigest()

def blind_hash_phone(phone: str) -> str:
    """Normalize phone to E.164 and compute deterministic blind index."""
    digits = "".join(filter(str.isdigit, phone))
    if len(digits) > 10:
        digits = digits[-10:]
    normalized = f"+91{digits}"
    return blind_hash(normalized)

def init_db():
    """Initializes persistent tables matching DPDP Act 2023 Master Architecture."""
    conn = get_connection()
    with conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            phone_blind_hash TEXT NOT NULL UNIQUE,
            email_blind_hash TEXT,
            masked_phone TEXT NOT NULL,
            full_name TEXT NOT NULL,
            telecom_circle TEXT NOT NULL DEFAULT 'MH_MUMBAI',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS consent_artefacts (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            artefact_code TEXT NOT NULL UNIQUE,
            scope TEXT NOT NULL,
            signature TEXT NOT NULL,
            ip_address TEXT DEFAULT '127.0.0.1',
            granted_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            consent_id TEXT NOT NULL,
            status TEXT NOT NULL,
            total_brokers INTEGER DEFAULT 17,
            completed_brokers INTEGER DEFAULT 0,
            exposures_found INTEGER DEFAULT 0,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (consent_id) REFERENCES consent_artefacts(id)
        );

        CREATE TABLE IF NOT EXISTS exposure_listings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            broker_id TEXT NOT NULL,
            broker_name TEXT NOT NULL,
            domain TEXT NOT NULL,
            category TEXT NOT NULL,
            exposed_fields TEXT NOT NULL,
            removable INTEGER NOT NULL,
            selected INTEGER NOT NULL,
            status TEXT NOT NULL,
            opt_out_channel TEXT NOT NULL,
            dpo_email TEXT,
            evidence_hash TEXT NOT NULL,
            detected_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id),
            UNIQUE(scan_id, broker_id)
        );

        CREATE TABLE IF NOT EXISTS removal_requests (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            listing_id TEXT NOT NULL,
            broker_id TEXT NOT NULL,
            artefact_code TEXT NOT NULL,
            dispatched_at TEXT NOT NULL,
            sla_deadline TEXT NOT NULL,
            status TEXT NOT NULL,
            receipt_code TEXT NOT NULL,
            evidence_hash TEXT NOT NULL,
            FOREIGN KEY (listing_id) REFERENCES exposure_listings(id)
        );
        """)
    conn.close()

# Initialize immediately on module import
init_db()
