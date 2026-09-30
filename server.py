import json
import os
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse

from vault import (
    VAULT_FILE,
    encrypt_vault,
    decrypt_vault,
    check_password_strength,
    generate_password,
)


HOST = "127.0.0.1"
PORT = 8000


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

    # -------------------------
    # GET REQUESTS
    # -------------------------

    def do_GET(self):

        path = urlparse(self.path).path

        if path == "/api/passwords":
            self.get_passwords()
            return

        super().do_GET()

    def get_passwords(self):

        if not hasattr(self.server, "vault_data"):
            self.send_json(
                401,
                {
                    "success": False,
                    "message": "Vault is locked."
                }
            )
            return

        passwords = self.server.vault_data.get("passwords", [])

        self.send_json(
            200,
            {
                "success": True,
                "passwords": passwords
            }
        )

    # -------------------------
    # POST REQUESTS
    # -------------------------

    def do_POST(self):

        path = urlparse(self.path).path

        if path == "/api/unlock":
            self.unlock_vault()
            return

        if path == "/api/add":
            self.add_password()
            return

        if path == "/api/generate":
            self.generate_password()
            return

        self.send_json(
            404,
            {
                "success": False,
                "message": "Endpoint not found."
            }
        )

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

            vault_data = decrypt_vault(blob, password)

            self.server.vault_data = vault_data
            self.server.master_password = password

            self.send_json(
                200,
                {
                    "success": True,
                    "message": "Vault unlocked successfully."
                }
            )

        except ValueError:
            self.send_json(
                401,
                {
                    "success": False,
                    "message": "Wrong master password OR vault was tampered with."
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

        if not hasattr(self.server, "vault_data"):
            self.send_json(
                401,
                {
                    "success": False,
                    "message": "Vault is locked."
                }
            )
            return

        passwords = self.server.vault_data.get("passwords", [])

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

            if not hasattr(self.server, "vault_data"):
                self.send_json(
                    401,
                    {
                        "success": False,
                        "message": "Vault is locked."
                    }
                )
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

            if strength in ("Very Weak", "Weak"):
                self.send_json(
                    400,
                    {
                        "success": False,
                        "message": f"Password is too weak: {strength}"
                    }
                )
                return

            entry = {
                "website": website,
                "username": username,
                "password": password
            }

            if "passwords" not in self.server.vault_data:
                self.server.vault_data["passwords"] = []

            self.server.vault_data["passwords"].append(entry)

            blob = encrypt_vault(
                self.server.vault_data,
                self.server.master_password
            )

            temp_file = VAULT_FILE + ".tmp"

            with open(temp_file, "wb") as f:
                f.write(blob)
                f.flush()
                os.fsync(f.fileno())

            os.replace(temp_file, VAULT_FILE)

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


class PasswordManagerServer(HTTPServer):

    vault_data = None
    master_password = None


def main():

    server = PasswordManagerServer(
        (HOST, PORT),
        PasswordManagerHandler
    )

    print(f"Password Manager running at http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop the server.")

    try:
        server.serve_forever()

    except KeyboardInterrupt:
        print("\nServer stopped.")

    finally:

        if server.master_password is not None:
            server.master_password = None

        if server.vault_data is not None:
            server.vault_data.clear()

        server.server_close()


if __name__ == "__main__":
    main()