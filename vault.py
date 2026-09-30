import os
import json
import getpass
import secrets
import string
import time
import threading
from datetime import datetime

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


# ============================================================
# CONFIGURATION
# ============================================================

VAULT_FILE = "vault.bin"
BACKUP_FILE = "vault_backup.bin"
LOG_FILE = "security.log"

MAGIC = b"PMV1"
MIN_BLOB_LEN = 4 + 16 + 12 + 16

DEFAULT_LENGTH = 16
MIN_GENERATED_LENGTH = 12
MAX_GENERATED_LENGTH = 128

LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
SPECIAL = "!@#$%^&*"

ALL_CHARS = LOWER + UPPER + DIGITS + SPECIAL

COMMON_WORDS = (
    "password",
    "admin",
    "qwerty",
    "letmein",
    "welcome",
)

WEAK_LEVELS = ("Very Weak", "Weak")

MAX_LOGIN_ATTEMPTS = 3
RETRY_DELAYS = (1, 2)

AUTO_LOCK_SECONDS = 120   # 2 minutes


# ============================================================
# STAGE 8 - SECURITY LOGGING
# ============================================================

def log_security_event(event):
    """
    Record a security event.

    Sensitive information is never written to the log.
    """

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    line = f"{timestamp} | {event}\n"

    try:
        with open(
            LOG_FILE,
            "a",
            encoding="utf-8"
        ) as f:

            f.write(line)
            f.flush()
            os.fsync(f.fileno())

    except OSError:
        # Logging failure must not crash the application.
        pass


# ============================================================
# KEY DERIVATION
# ============================================================

def derive_key(password, salt):

    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID,
    )


# ============================================================
# ENCRYPTION
# ============================================================

def encrypt_vault(data, password):

    salt = os.urandom(16)
    nonce = os.urandom(12)

    key = derive_key(
        password,
        salt
    )

    plaintext = json.dumps(
        data,
        ensure_ascii=False
    ).encode("utf-8")

    aes = AESGCM(key)

    ciphertext = aes.encrypt(
        nonce,
        plaintext,
        MAGIC + salt
    )

    return (
        MAGIC
        + salt
        + nonce
        + ciphertext
    )


# ============================================================
# DECRYPTION
# ============================================================

def decrypt_vault(blob, password):

    if len(blob) < MIN_BLOB_LEN:
        raise ValueError(
            "Invalid vault"
        )

    magic = blob[:4]

    if magic != MAGIC:
        raise ValueError(
            "Invalid vault"
        )

    salt = blob[4:20]
    nonce = blob[20:32]
    ciphertext = blob[32:]

    try:

        key = derive_key(
            password,
            salt
        )

        aes = AESGCM(key)

        plaintext = aes.decrypt(
            nonce,
            ciphertext,
            MAGIC + salt
        )

        data = json.loads(
            plaintext.decode("utf-8")
        )

        if not isinstance(data, dict):
            raise ValueError(
                "Invalid vault"
            )

        return data

    except (
        InvalidTag,
        ValueError,
        json.JSONDecodeError
    ):

        raise ValueError(
            "Wrong master password OR vault was tampered with"
        )


# ============================================================
# PASSWORD STRENGTH
# ============================================================

def _has_common_word(password):

    lowered = password.lower()

    return any(
        word in lowered
        for word in COMMON_WORDS
    )


def _has_sequence(password):

    lowered = password.lower()

    sequences = (
        "1234",
        "2345",
        "3456",
        "4567",
        "5678",
        "6789",
        "abcd",
        "bcde",
        "cdef",
        "defg",
        "qwer",
        "wert",
    )

    return any(
        sequence in lowered
        for sequence in sequences
    )


def _has_repeat(password):

    if len(password) < 3:
        return False

    for i in range(
        len(password) - 2
    ):

        if (
            password[i]
            == password[i + 1]
            == password[i + 2]
        ):

            return True

    return False


def check_password_strength(password):

    if not password:

        return (
            "Very Weak",
            ["Password cannot be empty."]
        )

    if len(set(password)) == 1:

        return (
            "Very Weak",
            [
                "Do not use the same character repeatedly."
            ]
        )

    score = 0
    tips = []

    # Length
    if len(password) >= 16:

        score += 3

    elif len(password) >= 12:

        score += 2

    elif len(password) >= 8:

        score += 1

    else:

        tips.append(
            "Use at least 8 characters."
        )

    # Lowercase
    if any(
        c.islower()
        for c in password
    ):

        score += 1

    else:

        tips.append(
            "Add lowercase letters."
        )

    # Uppercase
    if any(
        c.isupper()
        for c in password
    ):

        score += 1

    else:

        tips.append(
            "Add uppercase letters."
        )

    # Digits
    if any(
        c.isdigit()
        for c in password
    ):

        score += 1

    else:

        tips.append(
            "Add numbers."
        )

    # Special characters
    if any(
        c in SPECIAL
        for c in password
    ):

        score += 1

    else:

        tips.append(
            "Add special characters."
        )

    # Common words
    if _has_common_word(password):

        score -= 3

        tips.append(
            "Avoid common words such as password or admin."
        )

    # Sequences
    if _has_sequence(password):

        score -= 2

        tips.append(
            "Avoid predictable sequences."
        )

    # Repeated characters
    if _has_repeat(password):

        score -= 1

        tips.append(
            "Avoid repeated characters."
        )

    if score <= 2:

        label = "Very Weak"

    elif score <= 4:

        label = "Weak"

    elif score == 5:

        label = "Medium"

    elif score == 6:

        label = "Strong"

    else:

        label = "Very Strong"

    if len(password) < 8:

        label = "Very Weak"

    return label, tips


# ============================================================
# SECURE PASSWORD GENERATOR
# ============================================================

def generate_password(n=DEFAULT_LENGTH):

    if n < MIN_GENERATED_LENGTH:

        n = MIN_GENERATED_LENGTH

    if n > MAX_GENERATED_LENGTH:

        n = MAX_GENERATED_LENGTH

    while True:

        password_chars = [
            secrets.choice(LOWER),
            secrets.choice(UPPER),
            secrets.choice(DIGITS),
            secrets.choice(SPECIAL),
        ]

        for _ in range(n - 4):

            password_chars.append(
                secrets.choice(ALL_CHARS)
            )

        # Secure Fisher-Yates shuffle
        for i in range(
            len(password_chars) - 1,
            0,
            -1
        ):

            j = secrets.randbelow(
                i + 1
            )

            password_chars[i], password_chars[j] = (
                password_chars[j],
                password_chars[i],
            )

        password = "".join(
            password_chars
        )

        label, _ = check_password_strength(
            password
        )

        if (
            label in (
                "Strong",
                "Very Strong"
            )
            and not _has_common_word(password)
            and not _has_sequence(password)
            and not _has_repeat(password)
        ):

            return password


# ============================================================
# SAVE VAULT
# ============================================================

def save(data, password):

    blob = encrypt_vault(
        data,
        password
    )

    tmp = VAULT_FILE + ".tmp"

    try:

        with open(
            tmp,
            "wb"
        ) as f:

            f.write(blob)
            f.flush()
            os.fsync(f.fileno())

        os.replace(
            tmp,
            VAULT_FILE
        )

    except OSError:

        try:

            if os.path.exists(tmp):

                os.remove(tmp)

        except OSError:

            pass

        raise

    return blob


# ============================================================
# STAGE 9 - BACKUP
# ============================================================

def backup_vault():

    if not os.path.exists(
        VAULT_FILE
    ):

        print(
            "No vault exists to back up."
        )

        return False

    try:

        with open(
            VAULT_FILE,
            "rb"
        ) as source:

            blob = source.read()

    except OSError:

        print(
            "Could not read the vault."
        )

        return False

    # Make sure the current vault has a valid format.
    if len(blob) < MIN_BLOB_LEN:

        print(
            "Current vault is invalid."
        )

        return False

    if blob[:4] != MAGIC:

        print(
            "Current vault has an invalid format."
        )

        return False

    tmp = BACKUP_FILE + ".tmp"

    try:

        with open(
            tmp,
            "wb"
        ) as destination:

            destination.write(blob)
            destination.flush()
            os.fsync(
                destination.fileno()
            )

        os.replace(
            tmp,
            BACKUP_FILE
        )

    except OSError:

        try:

            if os.path.exists(tmp):

                os.remove(tmp)

        except OSError:

            pass

        print(
            "Backup could not be created."
        )

        return False

    log_security_event(
        "VAULT_BACKUP_CREATED"
    )

    print(
        "Vault backup created successfully."
    )

    return True


# ============================================================
# STAGE 9 - RESTORE
# ============================================================

def restore_vault(session):

    if not os.path.exists(
        BACKUP_FILE
    ):

        print(
            "No backup file found."
        )

        return False

    try:

        with open(
            BACKUP_FILE,
            "rb"
        ) as f:

            backup_blob = f.read()

    except OSError:

        print(
            "Could not read the backup."
        )

        return False

    # Validate backup format.
    if len(backup_blob) < MIN_BLOB_LEN:

        print(
            "Backup file is invalid."
        )

        log_security_event(
            "VAULT_RESTORE_FAILED"
        )

        return False

    if backup_blob[:4] != MAGIC:

        print(
            "Backup file has an invalid format."
        )

        log_security_event(
            "VAULT_RESTORE_FAILED"
        )

        return False

    print(
        "\n--- Restore Vault ---"
    )

    print(
        "The backup must be verified before restoration."
    )

    password = getpass.getpass(
        "Master password for backup: "
    )

    try:

        restored_data = decrypt_vault(
            backup_blob,
            password
        )

    except ValueError:

        log_security_event(
            "VAULT_RESTORE_FAILED"
        )

        print(
            "Backup authentication failed."
        )

        return False

    confirm = input(
        "Restore this backup? [y/N]: "
    ).strip().lower()

    if confirm != "y":

        print(
            "Restore cancelled."
        )

        return False

    # Keep a safety copy of the current vault.
    safety_file = (
        VAULT_FILE
        + ".before_restore"
    )

    try:

        if os.path.exists(
            VAULT_FILE
        ):

            with open(
                VAULT_FILE,
                "rb"
            ) as source:

                current_blob = source.read()

            with open(
                safety_file,
                "wb"
            ) as safety:

                safety.write(
                    current_blob
                )

                safety.flush()

                os.fsync(
                    safety.fileno()
                )

        tmp = VAULT_FILE + ".tmp"

        with open(
            tmp,
            "wb"
        ) as f:

            f.write(
                backup_blob
            )

            f.flush()

            os.fsync(
                f.fileno()
            )

        os.replace(
            tmp,
            VAULT_FILE
        )

    except OSError:

        try:

            if os.path.exists(tmp):

                os.remove(tmp)

        except OSError:

            pass

        print(
            "Could not restore the backup."
        )

        log_security_event(
            "VAULT_RESTORE_FAILED"
        )

        return False

    # Replace the currently decrypted session
    # with the restored data.
    session["data"] = restored_data
    session["pw"] = password
    session["locked"] = False

    session["activity"].set()

    log_security_event(
        "VAULT_RESTORED"
    )

    print(
        "Vault restored successfully."
    )

    print(
        "A safety copy of the previous vault was created."
    )

    return True


# ============================================================
# AUTO-LOCK
# ============================================================

def start_auto_lock(session):

    while not session[
        "stop_timer"
    ].is_set():

        activity_detected = session[
            "activity"
        ].wait(
            AUTO_LOCK_SECONDS
        )

        if session[
            "stop_timer"
        ].is_set():

            break

        if activity_detected:

            session[
                "activity"
            ].clear()

            continue

        if not session["locked"]:

            session["data"].clear()

            session["pw"] = None

            session["locked"] = True

            log_security_event(
                "SESSION_AUTO_LOCKED"
            )

            print(
                "\n\nSession locked due to inactivity."
            )

            print(
                "Your decrypted vault data has been cleared."
            )


def reset_activity_timer(session):

    if not session["locked"]:

        session["activity"].set()


def unlock_session(
    session,
    blob
):

    if not session["locked"]:

        return True

    print(
        "\n--- Unlock Vault ---"
    )

    password = getpass.getpass(
        "Master password: "
    )

    try:

        data = decrypt_vault(
            blob,
            password
        )

    except ValueError:

        log_security_event(
            "LOGIN_FAILED"
        )

        print(
            "Authentication failed."
        )

        return False

    session["pw"] = password

    session["data"] = data

    session["locked"] = False

    session["activity"].set()

    log_security_event(
        "SESSION_UNLOCKED"
    )

    print(
        "Vault unlocked."
    )

    return True


# ============================================================
# CHANGE MASTER PASSWORD
# ============================================================

def change_master_password(
    session,
    blob
):

    if session["locked"]:

        return blob

    print(
        "\n--- Change Master Password ---"
    )

    current_pw = getpass.getpass(
        "Current master password: "
    )

    try:

        verify_data = decrypt_vault(
            blob,
            current_pw
        )

    except ValueError:

        log_security_event(
            "MASTER_PASSWORD_CHANGE_FAILED"
        )

        print(
            "Current master password is incorrect."
        )

        return blob

    if verify_data != session["data"]:

        log_security_event(
            "MASTER_PASSWORD_CHANGE_FAILED"
        )

        print(
            "Session verification failed."
        )

        print(
            "Master password was not changed."
        )

        return blob

    new_pw = getpass.getpass(
        "New master password: "
    )

    if not new_pw:

        print(
            "New master password cannot be empty."
        )

        return blob

    if new_pw == current_pw:

        print(
            "New master password must be different "
            "from the current password."
        )

        return blob

    label, tips = check_password_strength(
        new_pw
    )

    print(
        f"New password strength: {label}"
    )

    if tips:

        for tip in tips:

            print(
                f"  - {tip}"
            )

    if label in WEAK_LEVELS:

        print(
            "New master password is too weak."
        )

        print(
            "Choose a stronger master password."
        )

        return blob

    confirm_pw = getpass.getpass(
        "Confirm new master password: "
    )

    if confirm_pw != new_pw:

        print(
            "New passwords do not match."
        )

        return blob

    try:

        new_blob = encrypt_vault(
            session["data"],
            new_pw
        )

        tmp = VAULT_FILE + ".tmp"

        with open(
            tmp,
            "wb"
        ) as f:

            f.write(new_blob)
            f.flush()
            os.fsync(f.fileno())

        os.replace(
            tmp,
            VAULT_FILE
        )

    except OSError:

        print(
            "Could not save the new master password."
        )

        try:

            if os.path.exists(tmp):

                os.remove(tmp)

        except OSError:

            pass

        return blob

    session["pw"] = new_pw

    log_security_event(
        "MASTER_PASSWORD_CHANGED"
    )

    print(
        "Master password changed successfully."
    )

    print(
        "Your stored passwords were not changed."
    )

    return new_blob


# ============================================================
# MAIN APPLICATION
# ============================================================

def main():

    # --------------------------------------------------------
    # CREATE NEW VAULT
    # --------------------------------------------------------

    if not os.path.exists(
        VAULT_FILE
    ):

        print(
            "No vault found."
        )

        print(
            "Let's create a new password vault."
        )

        while True:

            pw = getpass.getpass(
                "Create master password: "
            )

            if not pw:

                print(
                    "Master password cannot be empty."
                )

                continue

            label, tips = check_password_strength(
                pw
            )

            print(
                f"Password strength: {label}"
            )

            if tips:

                for tip in tips:

                    print(
                        f"  - {tip}"
                    )

            if label in WEAK_LEVELS:

                print(
                    "Please choose a stronger master password."
                )

                continue

            confirm = getpass.getpass(
                "Confirm master password: "
            )

            if confirm != pw:

                print(
                    "Passwords do not match."
                )

                continue

            break

        data = {
            "entries": []
        }

        save(
            data,
            pw
        )

        log_security_event(
            "VAULT_CREATED"
        )

        print(
            "Vault created successfully."
        )

        with open(
            VAULT_FILE,
            "rb"
        ) as f:

            blob = f.read()

    # --------------------------------------------------------
    # EXISTING VAULT
    # --------------------------------------------------------

    else:

        try:

            with open(
                VAULT_FILE,
                "rb"
            ) as f:

                blob = f.read()

        except OSError:

            print(
                "Could not read vault."
            )

            return

        if len(blob) < MIN_BLOB_LEN:

            print(
                "Not a valid vault file."
            )

            return

        pw = None
        data = None

        for attempt in range(
            1,
            MAX_LOGIN_ATTEMPTS + 1
        ):

            pw = getpass.getpass(
                "Master password: "
            )

            try:

                data = decrypt_vault(
                    blob,
                    pw
                )

                log_security_event(
                    "LOGIN_SUCCESS"
                )

                break

            except ValueError:

                log_security_event(
                    "LOGIN_FAILED"
                )

                print(
                    "Authentication failed."
                )

                if attempt < MAX_LOGIN_ATTEMPTS:

                    delay = RETRY_DELAYS[
                        attempt - 1
                    ]

                    print(
                        f"Retrying is allowed after "
                        f"{delay} second(s)."
                    )

                    time.sleep(
                        delay
                    )

                else:

                    log_security_event(
                        "MAX_LOGIN_ATTEMPTS_REACHED"
                    )

                    print(
                        "Maximum login attempts reached."
                    )

                    print(
                        "Vault access denied."
                    )

                    return

    # --------------------------------------------------------
    # SESSION
    # --------------------------------------------------------

    session = {
        "data": data,
        "pw": pw,
        "locked": False,
        "activity": threading.Event(),
        "stop_timer": threading.Event(),
    }

    timer_thread = threading.Thread(
        target=start_auto_lock,
        args=(session,),
        daemon=True
    )

    timer_thread.start()

    reset_activity_timer(
        session
    )

    # --------------------------------------------------------
    # MAIN MENU
    # --------------------------------------------------------

    try:

        while True:

            if session["locked"]:

                print(
                    "\nVault is locked."
                )

                choice = input(
                    "[u]nlock  [q]uit > "
                ).strip().lower()

                if choice == "u":

                    if unlock_session(
                        session,
                        blob
                    ):

                        continue

                    continue

                elif choice == "q":

                    break

                else:

                    print(
                        "Invalid option."
                    )

                continue

            print(
                "\n[a]dd  "
                "[g]et  "
                "[l]ist  "
                "[n]ew password  "
                "[c]hange master password  "
                "[b]ackup  "
                "[r]estore  "
                "[q]uit"
            )

            cmd = input(
                "> "
            ).strip().lower()

            reset_activity_timer(
                session
            )

            # ------------------------------------------------
            # ADD PASSWORD
            # ------------------------------------------------

            if cmd == "a":

                website = input(
                    "Website: "
                ).strip()

                username = input(
                    "Username: "
                ).strip()

                password = getpass.getpass(
                    "Password: "
                )

                label, tips = check_password_strength(
                    password
                )

                print(
                    f"Password strength: {label}"
                )

                if tips:

                    for tip in tips:

                        print(
                            f"  - {tip}"
                        )

                generated = None

                if label in WEAK_LEVELS:

                    choice = input(
                        "\nPassword is weak. "
                        "[c]ontinue anyway, "
                        "[g]enerate a stronger one, "
                        "or cancel (Enter)? "
                    ).strip().lower()

                    if choice == "g":

                        generated = generate_password()

                        password = generated

                        label, _ = check_password_strength(
                            password
                        )

                        print(
                            f"Generated password: "
                            f"{password}"
                        )

                        print(
                            f"Strength: {label}"
                        )

                    elif choice != "c":

                        print(
                            "Password entry cancelled."
                        )

                        continue

                session["data"].setdefault(
                    "entries",
                    []
                )

                session["data"]["entries"].append(
                    {
                        "website": website,
                        "username": username,
                        "password": password,
                    }
                )

                blob = save(
                    session["data"],
                    session["pw"]
                )

                log_security_event(
                    "PASSWORD_ENTRY_ADDED"
                )

                print(
                    "Password saved successfully."
                )

                if generated:

                    print(
                        f"Generated password: "
                        f"{generated}"
                    )

            # ------------------------------------------------
            # GET PASSWORD
            # ------------------------------------------------

            elif cmd == "g":

                entries = session["data"].get(
                    "entries",
                    []
                )

                if not entries:

                    print(
                        "No saved passwords."
                    )

                    continue

                website = input(
                    "Website to retrieve: "
                ).strip()

                found = False

                for entry in entries:

                    if (
                        entry["website"].lower()
                        == website.lower()
                    ):

                        print(
                            f"Username: "
                            f"{entry['username']}"
                        )

                        print(
                            f"Password: "
                            f"{entry['password']}"
                        )

                        log_security_event(
                            "PASSWORD_ENTRY_RETRIEVED"
                        )

                        found = True

                        break

                if not found:

                    print(
                        "No matching password entry found."
                    )

            # ------------------------------------------------
            # LIST PASSWORDS
            # ------------------------------------------------

            elif cmd == "l":

                entries = session["data"].get(
                    "entries",
                    []
                )

                if not entries:

                    print(
                        "No saved passwords."
                    )

                    continue

                print(
                    "\nSaved websites:"
                )

                for i, entry in enumerate(
                    entries,
                    start=1
                ):

                    print(
                        f"{i}. {entry['website']}"
                    )

                log_security_event(
                    "PASSWORD_LIST_VIEWED"
                )

            # ------------------------------------------------
            # GENERATE PASSWORD
            # ------------------------------------------------

            elif cmd == "n":

                length_text = input(
                    f"Password length "
                    f"(default {DEFAULT_LENGTH}): "
                ).strip()

                if not length_text:

                    length = DEFAULT_LENGTH

                else:

                    try:

                        length = int(
                            length_text
                        )

                    except ValueError:

                        print(
                            "Please enter a valid number."
                        )

                        continue

                if length < MIN_GENERATED_LENGTH:

                    print(
                        f"Minimum length is "
                        f"{MIN_GENERATED_LENGTH}."
                    )

                    continue

                if length > MAX_GENERATED_LENGTH:

                    print(
                        f"Maximum length is "
                        f"{MAX_GENERATED_LENGTH}."
                    )

                    continue

                generated = generate_password(
                    length
                )

                label, _ = check_password_strength(
                    generated
                )

                print(
                    f"\nGenerated password: "
                    f"{generated}"
                )

                print(
                    f"Strength: {label}"
                )

                print(
                    "This password has not been saved."
                )

            # ------------------------------------------------
            # CHANGE MASTER PASSWORD
            # ------------------------------------------------

            elif cmd == "c":

                blob = change_master_password(
                    session,
                    blob
                )

                reset_activity_timer(
                    session
                )

            # ------------------------------------------------
            # BACKUP
            # ------------------------------------------------

            elif cmd == "b":

                backup_vault()

                reset_activity_timer(
                    session
                )

            # ------------------------------------------------
            # RESTORE
            # ------------------------------------------------

            elif cmd == "r":

                restored = restore_vault(
                    session
                )

                if restored:

                    with open(
                        VAULT_FILE,
                        "rb"
                    ) as f:

                        blob = f.read()

                reset_activity_timer(
                    session
                )

            # ------------------------------------------------
            # QUIT
            # ------------------------------------------------

            elif cmd == "q":

                break

            else:

                print(
                    "Invalid option."
                )

    finally:

        session["stop_timer"].set()

        session["activity"].set()

        session["data"].clear()

        session["pw"] = None

        session["locked"] = True

        log_security_event(
            "VAULT_LOCKED"
        )

        print(
            "\nVault locked."
        )

        print(
            "Goodbye."
        )


if __name__ == "__main__":
    main()