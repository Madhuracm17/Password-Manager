import os, sys, time, json, hashlib, secrets, tempfile
from vault import encrypt_vault, decrypt_vault, derive_key, MAGIC

REAL_VAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vault.bin")
GENERIC_ERROR = "Wrong master password OR vault was tampered with"

# Harmless test values; secrets are random per run and never printed.
DEMO_SITE = "gmail-test.com"
DEMO_USER = "test@example.com"
DEMO_MASTER = secrets.token_urlsafe(24)
DEMO_DATA = {DEMO_SITE: {"user": DEMO_USER, "password": secrets.token_urlsafe(16)}}

results = []


def check(label, ok):
    results.append(bool(ok))
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")


def header(title):
    print("\n" + "=" * 66)
    print(title)
    print("=" * 66)


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest().upper()


def try_decrypt(blob, password):
    """Returns (success, error_message). Never returns or prints vault contents."""
    try:
        decrypt_vault(blob, password)
        return True, None
    except ValueError as e:
        return False, str(e)


def read_real_vault():
    if not os.path.exists(REAL_VAULT):
        return None
    with open(REAL_VAULT, "rb") as f:      # read-only
        return f.read()


def describe(label, blob):
    magic, salt, nonce, rest = blob[:4], blob[4:20], blob[20:32], blob[32:]
    print(f"  {label}: {len(blob)} bytes total")
    print(f"    header          : {magic!r}")
    print(f"    salt            : {len(salt)} bytes")
    print(f"    nonce           : {len(nonce)} bytes")
    print(f"    ciphertext+tag  : {len(rest)} bytes (last 16 = GCM auth tag)")
    return magic == MAGIC and len(salt) == 16 and len(nonce) == 12 and len(rest) >= 16


# ---------------------------------------------------------------- 1
def demo_wrong_password(blob):
    header("1. WRONG MASTER PASSWORD TEST")
    ok, _ = try_decrypt(blob, DEMO_MASTER)
    check("correct master password decrypts the vault", ok)

    ok, msg = try_decrypt(blob, secrets.token_urlsafe(24))
    print(f"  wrong password (random)     -> {msg}")
    check("completely wrong password is rejected", not ok)

    ok, msg2 = try_decrypt(blob, DEMO_MASTER + "x")
    print(f"  wrong password (near miss)  -> {msg2}")
    check("near-miss password is rejected", not ok)
    check("error message is generic (does not say which cause)", msg == GENERIC_ERROR and msg2 == GENERIC_ERROR)
    print("  (No key, password or vault contents are printed on failure.)")


# ---------------------------------------------------------------- 2
def demo_tampering(blob):
    header("2. AES-GCM TAMPERING DEMONSTRATION")
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "demo_vault.bin")
        with open(path, "wb") as f:
            f.write(blob)
        with open(path, "rb") as f:
            original = f.read()
        print(f"  temporary demo vault: {len(original)} bytes (real vault.bin not used here)")
        check("untampered copy still decrypts (control)", try_decrypt(original, DEMO_MASTER)[0])

        targets = [
            ("magic header (byte 0)", 0),
            ("salt (byte 4)", 4),
            ("nonce (byte 20)", 20),
            ("ciphertext (byte 32)", 32),
            ("auth tag (last byte)", len(original) - 1),
        ]
        for name, i in targets:
            bad = bytearray(original)
            bad[i] ^= 1                       # flip ONE bit in the in-memory copy
            ok, msg = try_decrypt(bytes(bad), DEMO_MASTER)
            print(f"  1 bit flipped in {name:<24} -> {msg}")
            check(f"tampering with {name} rejected", not ok)

        ok, msg = try_decrypt(original[:-1], DEMO_MASTER)
        print(f"  file truncated by 1 byte{'':<17} -> {msg}")
        check("truncated file rejected", not ok)
    print("  Result: Tampering detected / decryption rejected")
    print("  (Temp folder deleted automatically.)")


# ---------------------------------------------------------------- 3
def demo_plaintext_leak(blob, real_blob):
    header("3. PLAINTEXT LEAKAGE CHECK (practical check, not a mathematical proof)")
    plain = json.dumps(DEMO_DATA).encode()
    needles = [DEMO_SITE, DEMO_USER, '"user"', '"password"']

    check("control: the same strings ARE found in the unencrypted JSON",
          all(n.encode() in plain for n in needles))
    for n in needles:
        found = n.encode() in blob
        print(f"  search encrypted demo vault for {n!r:<20} -> found: {found}")
        check(f"{n!r} not visible in encrypted demo vault", not found)

    try:
        json.loads(blob)
        is_json = True
    except ValueError:
        is_json = False
    check("encrypted file does not parse as plain JSON", not is_json)

    if real_blob is not None:
        found = DEMO_SITE.encode() in real_blob
        print(f"  search real vault.bin for {DEMO_SITE!r} -> found: {found}")
        check("test string not visible in real vault.bin", not found)
    print("  Meaning: site names, usernames and passwords are inside the encrypted")
    print("  payload, so a simple search of the file does not reveal them.")


# ---------------------------------------------------------------- 4
def demo_format(blob, real_blob):
    header("4. VAULT HEADER / FORMAT VALIDATION")
    print("  Expected: MAGIC(4) | SALT(16) | NONCE(12) | CIPHERTEXT+TAG")
    check("demo vault matches the expected format", describe("demo vault", blob))
    if real_blob is not None:
        check("real vault.bin matches the expected format", describe("real vault.bin", real_blob))
    else:
        print("  real vault.bin not found - skipped.")


# ---------------------------------------------------------------- 5
def demo_fresh_randomness():
    header("5. FRESH SALT AND NONCE ON EVERY ENCRYPTION")
    blobs = [encrypt_vault(DEMO_DATA, DEMO_MASTER) for _ in range(5)]   # same data, same password
    salts = [b[4:20] for b in blobs]
    nonces = [b[20:32] for b in blobs]
    for i, (s, n) in enumerate(zip(salts, nonces), 1):
        print(f"  save {i}: salt={s.hex()[:16]}...  nonce={n.hex()}")
    check("all 5 salts are different", len(set(salts)) == 5)
    check("all 5 nonces are different", len(set(nonces)) == 5)
    check("all 5 ciphertexts are different (same input data)", len({b[32:] for b in blobs}) == 5)
    print("  (Salts and nonces are not secret. Keys are never printed.)")


# ---------------------------------------------------------------- 6
def demo_hash(blob, real_blob):
    header("6. SHA-256 FILE FINGERPRINT")
    h1 = sha256_hex(blob)
    bad = bytearray(blob)
    bad[-1] ^= 1
    h2 = sha256_hex(bytes(bad))
    print(f"  demo vault           : {h1}")
    print(f"  same, 1 bit changed  : {h2}")
    check("a changed file gives a different hash", h1 != h2)
    if real_blob is not None:
        print(f"  real vault.bin       : {sha256_hex(real_blob)}")
        print("  (compare with: Get-FileHash .\\vault.bin)")
    print("  SHA-256 is a HASH, not encryption: it cannot decrypt the vault and does")
    print("  not protect the passwords. It only fingerprints the file's exact bytes.")
    print("  Protection comes from Argon2id + AES-GCM.")


# ---------------------------------------------------------------- 7
def demo_real_vault_untouched(before):
    header("7. REAL vault.bin WAS NOT MODIFIED")
    after = read_real_vault()
    if before is None and after is None:
        print("  no real vault.bin present - nothing to compare.")
        return
    print(f"  hash before: {sha256_hex(before)}")
    print(f"  hash after : {sha256_hex(after)}")
    check("real vault.bin is byte-for-byte unchanged", before == after)


# ---------------------------------------------------------------- 8 (original demo, kept)
def demo_slow_kdf():
    header("8. WHY A SLOW KDF MATTERS (offline guessing speed)")
    N = 200_000
    t = time.perf_counter()
    for i in range(N):
        hashlib.sha256(f"guess{i}".encode()).digest()
    sha_rate = N / (time.perf_counter() - t)

    salt = os.urandom(16)
    t = time.perf_counter()
    for i in range(5):
        derive_key(f"guess{i}", salt)
    argon_rate = 5 / (time.perf_counter() - t)

    print(f"  SHA-256 : {sha_rate:,.0f} guesses/sec on this laptop")
    print(f"  Argon2id: {argon_rate:,.1f} guesses/sec on this laptop")
    print(f"  Argon2 is ~{sha_rate / argon_rate:,.0f}x slower for the attacker")

    space = 26 ** 8   # 8-char lowercase password
    print(f"\n  8-char lowercase space = {space:,}")
    print(f"  Worst case with SHA-256 : {space / sha_rate / 3600:,.1f} hours")
    print(f"  Worst case with Argon2id: {space / argon_rate / 86400 / 365:,.0f} years")


def main():
    real_before = read_real_vault()
    demo_blob = encrypt_vault(DEMO_DATA, DEMO_MASTER)

    demo_wrong_password(demo_blob)
    demo_tampering(demo_blob)
    demo_plaintext_leak(demo_blob, real_before)
    demo_format(demo_blob, real_before)
    demo_fresh_randomness()
    demo_hash(demo_blob, real_before)
    demo_real_vault_untouched(real_before)
    demo_slow_kdf()

    header("SUMMARY")
    print(f"  Checks passed: {sum(results)}/{len(results)}")
    if all(results):
        print("  ALL SECURITY CHECKS PASSED")
    else:
        print("  SOME CHECKS FAILED - review the [FAIL] lines above")
        sys.exit(1)


if __name__ == "__main__":
    main()