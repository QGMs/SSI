import json
import sqlite3
import threading
from pathlib import Path

from .utils import ensure_parent_dir, utc_now


class ServerDatabase:
    def __init__(self, db_path):
        self.db_path = Path(db_path).expanduser().resolve()
        ensure_parent_dir(self.db_path)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        self._closed = False
        self._init_db()

    def _init_db(self):
        with self.conn:
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    certificate_pem TEXT NOT NULL,
                    contacts_blob TEXT,
                    registered_at TEXT NOT NULL
                )
                """
            )
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recipient TEXT NOT NULL,
                    sender TEXT NOT NULL,
                    envelope TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS signed_prekeys (
                    username TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (username, key_id)
                )
                """
            )
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS one_time_prekeys (
                    username TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (username, key_id)
                )
                """
            )

    def close(self):
        with self.lock:
            if not self._closed:
                self.conn.close()
                self._closed = True

    def register_user(self, username, certificate_pem):
        with self.lock, self.conn:
            row = self.conn.execute(
                "SELECT certificate_pem FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if row:
                if row["certificate_pem"] == certificate_pem:
                    return True, "Utilizador ja registado com o mesmo certificado."
                return False, "O username ja existe com outro certificado."

            self.conn.execute(
                """
                INSERT INTO users (username, certificate_pem, registered_at)
                VALUES (?, ?, ?)
                """,
                (username, certificate_pem, utc_now()),
            )
            return True, "Utilizador registado com sucesso."

    def get_user_record(self, username):
        with self.lock:
            row = self.conn.execute(
                """
                SELECT username, certificate_pem, registered_at
                FROM users
                WHERE username = ?
                """,
                (username,),
            ).fetchone()

        if not row:
            return None
        return dict(row)

    def get_user_certificate(self, username):
        record = self.get_user_record(username)
        if not record:
            return None
        return record["certificate_pem"]

    def list_users(self):
        with self.lock:
            rows = self.conn.execute(
                "SELECT username, registered_at FROM users ORDER BY username"
            ).fetchall()
        return [dict(row) for row in rows]

    def save_contacts_blob(self, username, blob):
        with self.lock, self.conn:
            self.conn.execute(
                "UPDATE users SET contacts_blob = ? WHERE username = ?",
                (json.dumps(blob), username),
            )

    def load_contacts_blob(self, username):
        with self.lock:
            row = self.conn.execute(
                "SELECT contacts_blob FROM users WHERE username = ?",
                (username,),
            ).fetchone()

        if not row or not row["contacts_blob"]:
            return None
        return json.loads(row["contacts_blob"])

    def upsert_signed_prekey(self, username, signed_prekey):
        with self.lock, self.conn:
            self.conn.execute(
                "UPDATE signed_prekeys SET is_active = 0 WHERE username = ?",
                (username,),
            )
            self.conn.execute(
                """
                INSERT INTO signed_prekeys (username, key_id, public_key, signature, created_at, is_active)
                VALUES (?, ?, ?, ?, ?, 1)
                ON CONFLICT(username, key_id) DO UPDATE SET
                    public_key = excluded.public_key,
                    signature = excluded.signature,
                    created_at = excluded.created_at,
                    is_active = 1
                """,
                (
                    username,
                    signed_prekey["key_id"],
                    signed_prekey["public_key"],
                    signed_prekey["signature"],
                    signed_prekey["created_at"],
                ),
            )

    def store_one_time_prekeys(self, username, one_time_prekeys):
        accepted = []
        with self.lock, self.conn:
            for item in one_time_prekeys:
                cursor = self.conn.execute(
                    """
                    INSERT OR IGNORE INTO one_time_prekeys (username, key_id, public_key, created_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (username, item["key_id"], item["public_key"], item["created_at"]),
                )
                if cursor.rowcount:
                    accepted.append(item["key_id"])
        return accepted

    def acquire_delivery_bundle(self, username):
        with self.lock, self.conn:
            user = self.conn.execute(
                "SELECT certificate_pem FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if not user:
                return None

            signed_prekey = self.conn.execute(
                """
                SELECT key_id, public_key, signature, created_at
                FROM signed_prekeys
                WHERE username = ? AND is_active = 1
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (username,),
            ).fetchone()
            one_time_prekey = self.conn.execute(
                """
                SELECT key_id, public_key, created_at
                FROM one_time_prekeys
                WHERE username = ?
                ORDER BY created_at, key_id
                LIMIT 1
                """,
                (username,),
            ).fetchone()

            if signed_prekey is None or one_time_prekey is None:
                return {
                    "certificate_pem": user["certificate_pem"],
                    "signed_prekey": dict(signed_prekey) if signed_prekey else None,
                    "one_time_prekey": None,
                }

            self.conn.execute(
                "DELETE FROM one_time_prekeys WHERE username = ? AND key_id = ?",
                (username, one_time_prekey["key_id"]),
            )
            return {
                "certificate_pem": user["certificate_pem"],
                "signed_prekey": dict(signed_prekey),
                "one_time_prekey": dict(one_time_prekey),
            }

    def count_one_time_prekeys(self, username):
        with self.lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS total FROM one_time_prekeys WHERE username = ?",
                (username,),
            ).fetchone()
        return row["total"]

    def store_message(self, recipient, sender, envelope):
        with self.lock, self.conn:
            cursor = self.conn.execute(
                """
                INSERT INTO messages (recipient, sender, envelope, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (recipient, sender, json.dumps(envelope), utc_now()),
            )
            return cursor.lastrowid

    def fetch_pending_messages(self, recipient):
        with self.lock:
            rows = self.conn.execute(
                """
                SELECT id, sender, envelope, created_at
                FROM messages
                WHERE recipient = ?
                ORDER BY id
                """,
                (recipient,),
            ).fetchall()

        messages = []
        for row in rows:
            messages.append(
                {
                    "id": row["id"],
                    "sender": row["sender"],
                    "created_at": row["created_at"],
                    "envelope": json.loads(row["envelope"]),
                }
            )
        return messages

    def ack_messages(self, recipient, ids):
        if not ids:
            return 0

        placeholders = ",".join("?" for _ in ids)
        with self.lock, self.conn:
            cursor = self.conn.execute(
                f"DELETE FROM messages WHERE recipient = ? AND id IN ({placeholders})",
                [recipient, *ids],
            )
            return cursor.rowcount
