import json
import os
import secrets
import threading
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse

from vault import (
    VAULT_FILE,
    BACKUP_FILE,
    MAGIC,
    MIN_BLOB_LEN,
    WEAK_LEVELS,
    encrypt_vault,
    decrypt_vault,
    check_password_strength,
    generate_password,
    log_security_event,
)


HOST = "127.0.0.1"
PORT = 8000

# Web session locks after this many seconds without user activity.
WEB_AUTO_LOCK_SECONDS = 10

GENERIC_AUTH_ERROR = "Wrong master password OR vault was tampered with."


# ============================================================
# FILE HELPERS
# ============================================================

def write_atomic(path, blob):
    """
    Write bytes to a temporary file, flush to disk, then replace
    the target in one step. A crash leaves the old or the new file,
    never half of one.
    """

    tmp = path + ".tmp"

    try:

        with open(tmp, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())

        os.replace(tmp, path)

    except OSError:

        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass

        raise


def read_vault_file(path):
    """
    Read a vault file and check its basic format.
    Returns the bytes, or None if missing or malformed.
    """

    if not os.path.exists(path):
        return None

    with open(path, "rb") as f:
        blob = f.read()

    if len(blob) < MIN_BLOB_LEN or blob[:4] != MAGIC:
        return None

    return blob


def new_entry_id():
    """
    Random, unguessable ID so edit/delete always target
    exactly one entry (two entries may share a website).
    """

    return secrets.token_hex(8)


def normalise_schema(vault_data):
    """
    Use the same schema as the CLI ("entries"); migrate any
    entries saved by older web versions under "passwords",
    and give every entry a stable ID.
    """

    legacy = vault_data.pop("passwords", [])
    entries = vault_data.setdefault("entries", [])
    entries.extend(legacy)

    for entry in entries:
        if not entry.get("id"):
            entry["id"] = new_entry_id()

    return vault_data


class PasswordManagerHandler(SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory="frontend", **kwargs)

    def send_json(self, status, data):
        response = json.dumps(data).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()

        self.wfile.write(response)

    def read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        if not body:
            return {}

        return json.loads(body.decode("utf-8"))

    def save_current_vault(self):
        """
        Re-encrypt the in-memory vault and write it to disk.
        encrypt_vault draws a fresh salt and nonce on every call.
        """

        blob = encrypt_vault(
            self.server.vault_data,
            self.server.master_password
        )

        write_atomic(VAULT_FILE, blob)

    def find_entry(self, entry_id):
        """
        Return the entry with this ID, or None.
        """

        for entry in self.server.vault_data.get("entries", []):
            if entry.get("id") == entry_id:
                return entry

        return None

    def require_unlocked(self):
        """
        Send 401 and return False if the vault is locked.
        """

        if self.server.vault_data is None:
            self.send_json(
                401,
                {
                    "success": False,
                    "message": "Vault is locked."
                }
            )
            return False

        self.server.last_activity = time.monotonic()

        return True

    # -------------------------
    # GET REQUESTS
    # -------------------------

    def do_GET(self):

        path = urlparse(self.path).path

        if path == "/api/passwords":
            with self.server.state_lock:
                self.get_passwords()
            return

        super().do_GET()

    # -------------------------
    # POST REQUESTS
    # -------------------------

    def do_POST(self):

        path = urlparse(self.path).path

        routes = {
            "/api/unlock": self.unlock_vault,
            "/api/add": self.add_password,
            "/api/edit": self.edit_password,
            "/api/delete": self.delete_password,
            "/api/lock": self.lock_vault,
            "/api/generate": self.generate_password,
            "/api/change-master": self.change_master_password,
            "/api/backup": self.backup_vault,
            "/api/restore": self.restore_vault,
            "/api/ping": self.ping,
        }

        handler = routes.get(path)

        if handler is None:
            self.send_json(
                404,
                {
                    "success": False,
                    "message": "Endpoint not found."
                }
            )
            return

        # One request at a time touches the session state, so the
        # auto-lock thread can never clear it halfway through a request.
        with self.server.state_lock:
            handler()

    # -------------------------
    # UNLOCK VAULT
    # -------------------------

    def unlock_vault(self):

        try:
            data = self.read_json()
            password = data.get("masterPassword", "")

            if not password:
                self.send_json(
                    400,
                    {
                        "success": False,
                        "message": "Master password is required."
                    }
                )
                return

            if not os.path.exists(VAULT_FILE):
                self.send_json(
                    404,
                    {
                        "success": False,
                        "message": "Vault does not exist."
                    }
                )
                return

            with open(VAULT_FILE, "rb") as f:
                blob = f.read()

            vault_data = normalise_schema(
                decrypt_vault(blob, password)
            )

            self.server.vault_data = vault_data
            self.server.master_password = password
            self.server.last_activity = time.monotonic()

            log_security_event("WEB_LOGIN_SUCCESS")

            self.send_json(
                200,
                {
                    "success": True,
                    "message": "Vault unlocked successfully.",
                    "autoLockSeconds": WEB_AUTO_LOCK_SECONDS
                }
            )

        except ValueError:

            log_security_event("WEB_LOGIN_FAILED")

            self.send_json(
                401,
                {
                    "success": False,
                    "message": GENERIC_AUTH_ERROR
                }
            )

        except Exception:
            self.send_json(
                500,
                {
                    "success": False,
                    "message": "Could not unlock the vault."
                }
            )

    # -------------------------
    # GET STORED PASSWORDS
    # -------------------------

    def get_passwords(self):

        if not self.require_unlocked():
            return

        passwords = self.server.vault_data.get("entries", [])

        self.send_json(
            200,
            {
                "success": True,
                "passwords": passwords
            }
        )

    # -------------------------
    # ADD PASSWORD
    # -------------------------

    def add_password(self):

        try:

            if not self.require_unlocked():
                return

            data = self.read_json()

            website = data.get("website", "").strip()
            username = data.get("username", "").strip()
            password = data.get("password", "")

            if not website or not username or not password:
                self.send_json(
                    400,
                    {
                        "success": False,
                        "message": "Website, username and password are required."
                    }
                )
                return

            strength, _ = check_password_strength(password)

            if strength in WEAK_LEVELS:
                self.send_json(
                    400,
                    {
                        "success": False,
                        "message": f"Password is too weak: {strength}"
                    }
                )
                return

            entry = {
                "id": new_entry_id(),
                "website": website,
                "username": username,
                "password": password
            }

            self.server.vault_data.setdefault("entries", []).append(entry)

            self.save_current_vault()

            log_security_event("WEB_PASSWORD_ENTRY_ADDED")

            self.send_json(
                200,
                {
                    "success": True,
                    "message": "Password added successfully."
                }
            )

        except Exception:
            self.send_json(
                500,
                {
                    "success": False,
                    "message": "Could not save the password."
                }
            )

    # -------------------------
    # EDIT PASSWORD ENTRY
    # -------------------------

    def edit_password(self):

        try:

            if not self.require_unlocked():
                return

            data = self.read_json()

            entry_id = data.get("id", "")
            website = data.get("website", "").strip()
            username = data.get("username", "").strip()
            password = data.get("password", "")

            entry = self.find_entry(entry_id)

            if entry is None:
                self.send_json(
                    404,
                    {
                        "success": False,
                        "message": "Entry not found. Refresh and try again."
                    }
                )
                return

            if not website or not username or not password:
                self.send_json(
                    400,
                    {
                        "success": False,
                        "message": "Website, username and password are required."
                    }
                )
                return

            strength, _ = check_password_strength(password)

            if strength in WEAK_LEVELS:
                self.send_json(
                    400,
                    {
                        "success": False,
                        "message": f"Password is too weak: {strength}"
                    }
                )
                return

            # Keep a copy so the change can be undone if saving fails.
            previous = dict(entry)

            entry["website"] = website
            entry["username"] = username
            entry["password"] = password

            try:
                self.save_current_vault()

            except Exception:
                entry.clear()
                entry.update(previous)
                raise

            log_security_event("WEB_PASSWORD_ENTRY_EDITED")

            self.send_json(
                200,
                {
                    "success": True,
                    "message": "Entry updated."
                }
            )

        except Exception:
            self.send_json(
                500,
                {
                    "success": False,
                    "message": "Could not update the entry."
                }
            )

    # -------------------------
    # DELETE PASSWORD ENTRY
    # -------------------------

    def delete_password(self):

        try:

            if not self.require_unlocked():
                return

            data = self.read_json()
            entry_id = data.get("id", "")

            entries = self.server.vault_data.get("entries", [])
            entry = self.find_entry(entry_id)

            if entry is None:
                self.send_json(
                    404,
                    {
                        "success": False,
                        "message": "Entry not found. Refresh and try again."
                    }
                )
                return

            index = entries.index(entry)
            entries.pop(index)

            try:
                self.save_current_vault()

            except Exception:
                entries.insert(index, entry)
                raise

            log_security_event("WEB_PASSWORD_ENTRY_DELETED")

            self.send_json(
                200,
                {
                    "success": True,
                    "message": "Entry deleted."
                }
            )

        except Exception:
            self.send_json(
                500,
                {
                    "success": False,
                    "message": "Could not delete the entry."
                }
            )

    # -------------------------
    # LOCK VAULT (clears decrypted data on the server)
    # -------------------------

    def lock_vault(self):

        clear_session(self.server)

        log_security_event("WEB_VAULT_LOCKED")

        self.send_json(
            200,
            {
                "success": True,
                "message": "Vault locked."
            }
        )

    # -------------------------
    # PING (keeps the session alive while the user is active)
    # -------------------------

    def ping(self):

        if not self.require_unlocked():
            return

        self.send_json(
            200,
            {
                "success": True
            }
        )

    # -------------------------
    # GENERATE PASSWORD
    # -------------------------

    def generate_password(self):

        try:

            password = generate_password(16)

            self.send_json(
                200,
                {
                    "success": True,
                    "password": password
                }
            )

        except Exception:
            self.send_json(
                500,
                {
                    "success": False,
                    "message": "Could not generate password."
                }
            )

    # -------------------------
    # CHANGE MASTER PASSWORD
    # -------------------------

    def change_master_password(self):

        try:

            if not self.require_unlocked():
                return

            data = self.read_json()

            current_pw = data.get("currentPassword", "")
            new_pw = data.get("newPassword", "")
            confirm_pw = data.get("confirmPassword", "")

            if not current_pw or not new_pw or not confirm_pw:
                self.send_json(
                    400,
                    {
                        "success": False,
                        "message": "All three password fields are required."
                    }
                )
                return

            # Prove knowledge of the current master password by
            # decrypting the vault file with it (same check as the CLI).
            blob = read_vault_file(VAULT_FILE)

            if blob is None:
                self.send_json(
                    404,
                    {
                        "success": False,
                        "message": "Vault does not exist."
                    }
                )
                return

            try:
                decrypt_vault(blob, current_pw)

            except ValueError:

                log_security_event("WEB_MASTER_PASSWORD_CHANGE_FAILED")

                self.send_json(
                    401,
                    {
                        "success": False,
                        "message": "Current master password is incorrect."
                    }
                )
                return

            if new_pw == current_pw:
                self.send_json(
                    400,
                    {
                        "success": False,
                        "message": "New master password must be different from the current one."
                    }
                )
                return

            if new_pw != confirm_pw:
                self.send_json(
                    400,
                    {
                        "success": False,
                        "message": "New passwords do not match."
                    }
                )
                return

            label, tips = check_password_strength(new_pw)

            if label in WEAK_LEVELS:
                self.send_json(
                    400,
                    {
                        "success": False,
                        "message": f"New master password is too weak: {label}.",
                        "tips": tips
                    }
                )
                return

            # Re-encrypt: encrypt_vault draws a fresh salt and nonce,
            # so the new password produces a brand-new key.
            new_blob = encrypt_vault(self.server.vault_data, new_pw)

            write_atomic(VAULT_FILE, new_blob)

            self.server.master_password = new_pw

            log_security_event("WEB_MASTER_PASSWORD_CHANGED")

            self.send_json(
                200,
                {
                    "success": True,
                    "message": "Master password changed. Use the new one next time."
                }
            )

        except Exception:
            self.send_json(
                500,
                {
                    "success": False,
                    "message": "Could not change the master password."
                }
            )

    # -------------------------
    # BACKUP VAULT
    # -------------------------

    def backup_vault(self):

        try:

            if not self.require_unlocked():
                return

            blob = read_vault_file(VAULT_FILE)

            if blob is None:
                self.send_json(
                    404,
                    {
                        "success": False,
                        "message": "No valid vault to back up."
                    }
                )
                return

            # The backup is a byte-for-byte copy: still encrypted,
            # still protected by the current master password.
            write_atomic(BACKUP_FILE, blob)

            log_security_event("VAULT_BACKUP_CREATED")

            self.send_json(
                200,
                {
                    "success": True,
                    "message": "Encrypted backup saved."
                }
            )

        except Exception:
            self.send_json(
                500,
                {
                    "success": False,
                    "message": "Backup could not be created."
                }
            )

    # -------------------------
    # RESTORE VAULT
    # -------------------------

    def restore_vault(self):

        try:

            if not self.require_unlocked():
                return

            data = self.read_json()
            backup_pw = data.get("backupPassword", "")

            if not backup_pw:
                self.send_json(
                    400,
                    {
                        "success": False,
                        "message": "Enter the master password of the backup."
                    }
                )
                return

            backup_blob = read_vault_file(BACKUP_FILE)

            if backup_blob is None:
                self.send_json(
                    404,
                    {
                        "success": False,
                        "message": "No valid backup file found."
                    }
                )
                return

            # Verify the backup BEFORE touching the current vault.
            try:
                restored = normalise_schema(
                    decrypt_vault(backup_blob, backup_pw)
                )

            except ValueError:

                log_security_event("VAULT_RESTORE_FAILED")

                self.send_json(
                    401,
                    {
                        "success": False,
                        "message": "Backup authentication failed."
                    }
                )
                return

            # Keep a safety copy of the current vault.
            current_blob = read_vault_file(VAULT_FILE)

            if current_blob is not None:
                write_atomic(VAULT_FILE + ".before_restore", current_blob)

            write_atomic(VAULT_FILE, backup_blob)

            self.server.vault_data = restored
            self.server.master_password = backup_pw

            log_security_event("VAULT_RESTORED")

            count = len(restored.get("entries", []))

            self.send_json(
                200,
                {
                    "success": True,
                    "message": (
                        f"Restored {count} entries. Unlock with the "
                        "backup's master password from now on."
                    )
                }
            )

        except Exception:

            log_security_event("VAULT_RESTORE_FAILED")

            self.send_json(
                500,
                {
                    "success": False,
                    "message": "Could not restore the backup."
                }
            )


class PasswordManagerServer(HTTPServer):

    vault_data = None
    master_password = None
    last_activity = 0.0
    state_lock = threading.Lock()


def clear_session(server):
    """
    Forget the decrypted vault and the master password.
    """

    if server.vault_data is not None:
        server.vault_data.clear()

    server.vault_data = None
    server.master_password = None


def auto_lock_worker(server, stop_event):
    """
    Lock the web session after WEB_AUTO_LOCK_SECONDS without
    activity, even if the browser tab was simply closed.
    """

    while not stop_event.wait(1):

        with server.state_lock:

            if server.vault_data is None:
                continue

            idle = time.monotonic() - server.last_activity

            if idle >= WEB_AUTO_LOCK_SECONDS:
                clear_session(server)
                log_security_event("WEB_SESSION_AUTO_LOCKED")


def main():

    server = PasswordManagerServer(
        (HOST, PORT),
        PasswordManagerHandler
    )

    stop_event = threading.Event()

    threading.Thread(
        target=auto_lock_worker,
        args=(server, stop_event),
        daemon=True
    ).start()

    print(f"Password Manager running at http://{HOST}:{PORT}")
    print(f"Web sessions auto-lock after {WEB_AUTO_LOCK_SECONDS} seconds of inactivity.")
    print("Press Ctrl+C to stop the server.")

    try:
        server.serve_forever()

    except KeyboardInterrupt:
        print("\nServer stopped.")

    finally:

        stop_event.set()
        clear_session(server)
        server.server_close()


if __name__ == "__main__":
    main()