"""
Email-based OTP recovery for the password manager.

Flow:
1. User registers a recovery email (stored in data/recovery_config.json).
2. On login, if they choose "Forgot password", a 6-digit OTP is generated,
   hashed+stored, and emailed to the registered address.
3. User enters the code; if it matches and has not expired (5 min window),
   they can reset the master password.

Delivery uses Gmail API OAuth. Keep credentials.json local and out of source
control. The first send opens a browser so Google can authorize the app, then
the refresh token is cached at data/gmail_token.json.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional


_OTP_TTL_SECONDS = 300
_OTP_DIGITS = 6
_GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.send"]
_DEFAULT_SENDER = "hibaeljirari98@mail.com"


class RecoveryManager:
    """Handles email-based OTP generation, delivery, and verification."""

    def __init__(self, data_dir: str | Path):
        self._data_dir = Path(data_dir)
        self._config_path = self._data_dir / "recovery_config.json"

    def register_email(self, email: str) -> None:
        """Persist the recovery email address."""
        config = self._load_config()
        config["recovery_email"] = email.strip().lower()
        self._save_config(config)

    def get_recovery_email(self) -> Optional[str]:
        """Return the registered recovery email, or None if not set."""
        return self._load_config().get("recovery_email")

    def has_recovery_email(self) -> bool:
        return bool(self.get_recovery_email())

    def generate_and_send_otp(self) -> bool:
        """
        Generate a 6-digit OTP, store its hash, and email it.

        Returns True on success, False if no email is configured or sending fails.
        """
        email = self.get_recovery_email()
        if not email:
            print("No recovery email configured.")
            return False

        otp = self._generate_otp()
        self._store_otp_hash(otp)

        return self._send_email(email, otp)

    def verify_otp(self, candidate: str) -> bool:
        """
        Return True if candidate matches the stored OTP and has not expired.
        Clears the stored OTP after a successful verification.
        """
        config = self._load_config()
        stored_hash = config.get("otp_hash")
        issued_at = config.get("otp_issued_at", 0)

        if not stored_hash:
            return False

        if time.time() - issued_at > _OTP_TTL_SECONDS:
            self._clear_otp()
            print("OTP has expired. Please request a new one.")
            return False

        candidate_hash = self._hash_otp(candidate.strip())
        if hmac.compare_digest(candidate_hash, stored_hash):
            self._clear_otp()
            return True

        return False

    def _send_email(self, recipient: str, otp: str) -> bool:
        service = self._build_gmail_service()
        if service is None:
            return False

        subject = "Password Manager - Recovery Code"
        body_plain = (
            f"Your recovery code is: {otp}\n\n"
            f"This code expires in {_OTP_TTL_SECONDS // 60} minutes.\n"
            "If you did not request this code, ignore this message."
        )
        body_html = f"""
        <html><body style="font-family:sans-serif;max-width:480px;margin:auto">
          <h2 style="color:#333">Password Manager Recovery</h2>
          <p>Use the code below to reset your master password:</p>
          <div style="font-size:36px;font-weight:bold;letter-spacing:8px;
                      text-align:center;padding:20px;background:#f4f4f4;
                      border-radius:8px;margin:20px 0">{otp}</div>
          <p style="color:#888;font-size:13px">
            Expires in {_OTP_TTL_SECONDS // 60} minutes.
            If you did not request this, ignore this email.
          </p>
        </body></html>
        """

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = os.getenv("PM_GMAIL_SENDER", _DEFAULT_SENDER)
        msg["To"] = recipient
        msg.attach(MIMEText(body_plain, "plain"))
        msg.attach(MIMEText(body_html, "html"))

        try:
            raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
            service.users().messages().send(
                userId="me",
                body={"raw": raw},
            ).execute()
            print(f"Recovery code sent to {recipient}.")
            return True
        except Exception as exc:
            print(f"Failed to send recovery email: {exc}")
            return False

    def _build_gmail_service(self):
        try:
            # Import Google API libraries dynamically to avoid static analysis
            # tooling complaining when they are not installed in the environment.
            import importlib

            Request = importlib.import_module("google.auth.transport.requests").Request
            Credentials = importlib.import_module("google.oauth2.credentials").Credentials
            InstalledAppFlow = importlib.import_module("google_auth_oauthlib.flow").InstalledAppFlow
            build = importlib.import_module("googleapiclient.discovery").build
        except ImportError:
            print("\n" + "=" * 50)
            print("  Gmail API libraries are not installed.")
            print("  Run: .\\.venv\\Scripts\\python.exe -m pip install -r requirements.txt")
            print("=" * 50 + "\n")
            return None

        credentials_path = Path(os.getenv("PM_GMAIL_CREDENTIALS", "credentials.json"))
        token_path = Path(os.getenv("PM_GMAIL_TOKEN", str(self._data_dir / "gmail_token.json")))

        if not credentials_path.exists():
            print(f"Gmail OAuth credentials file not found: {credentials_path}")
            return None

        creds = None
        if token_path.exists():
            creds = Credentials.from_authorized_user_file(str(token_path), _GMAIL_SCOPES)

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(str(credentials_path), _GMAIL_SCOPES)
                creds = flow.run_local_server(port=0)

            token_path.parent.mkdir(parents=True, exist_ok=True)
            token_path.write_text(creds.to_json(), encoding="utf-8")

        return build("gmail", "v1", credentials=creds)

    @staticmethod
    def _generate_otp() -> str:
        return str(secrets.randbelow(10 ** _OTP_DIGITS)).zfill(_OTP_DIGITS)

    @staticmethod
    def _hash_otp(otp: str) -> str:
        return hashlib.sha256(otp.encode()).hexdigest()

    def _store_otp_hash(self, otp: str) -> None:
        config = self._load_config()
        config["otp_hash"] = self._hash_otp(otp)
        config["otp_issued_at"] = time.time()
        self._save_config(config)

    def _clear_otp(self) -> None:
        config = self._load_config()
        config.pop("otp_hash", None)
        config.pop("otp_issued_at", None)
        self._save_config(config)

    def _load_config(self) -> dict:
        if not self._config_path.exists():
            return {}
        try:
            return json.loads(self._config_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save_config(self, config: dict) -> None:
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._config_path.write_text(
            json.dumps(config, indent=2), encoding="utf-8"
        )
