import base64
import hashlib
import hmac

from pwdlib import PasswordHash
from pwdlib.exceptions import UnknownHashError

password_hash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        return password_hash.verify(password, stored_hash)
    except UnknownHashError:
        return verify_legacy_password(password, stored_hash)


def verify_legacy_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations, encoded_salt, encoded_hash = stored_hash.split("$", 3)
    except ValueError:
        return False

    if algorithm != "pbkdf2_sha256":
        return False

    salt = base64.b64decode(encoded_salt.encode("ascii"))
    expected_hash = base64.b64decode(encoded_hash.encode("ascii"))
    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        int(iterations),
    )
    return hmac.compare_digest(derived_key, expected_hash)


def needs_rehash(stored_hash: str) -> bool:
    return stored_hash.startswith("pbkdf2_sha256$")
