#!/usr/bin/env python3

import hashlib
from pysqlcipher3 import dbapi2 as sqlite
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Sources:
# https://www.enpass.io/docs/security-whitepaper-enpass/vault.html
# https://discussion.enpass.io/index.php?/topic/4446-enpass-6-encryption-details/
# https://www.zetetic.net/sqlcipher/sqlcipher-api/
# https://cryptography.io/en/latest/hazmat/primitives/aead.html
# https://github.com/hazcod/enpass-cli/issues/16#issuecomment-735114305

enpass_db_file = "vault/vault.enpassdb"
enpass_master_password = b"secretmasterpassword"

# The first 16 bytes of the database file are used as salt
enpass_db_salt = open(enpass_db_file, "rb").read(16)

# The database key is derived from the master password
# and the database salt with 100k iterations of PBKDF2-HMAC-SHA512
enpass_db_key = hashlib.pbkdf2_hmac("sha512", enpass_master_password, enpass_db_salt, 100000)

# The raw key for the sqlcipher database is given
# by the first 64 characters of the hex-encoded key
enpass_db_hex_key = enpass_db_key.hex()[:64]

# Open DB with hex key and sqlcipher v3 compatibility mode
conn = sqlite.connect(enpass_db_file)
c = conn.cursor()
c.row_factory = sqlite.Row
c.execute("PRAGMA key=\"x'" + enpass_db_hex_key + "'\";")
c.execute("PRAGMA cipher_compatibility = 3;")

# Loop over joined item and itemfield rows
c.execute(
    "SELECT item.uuid, item.title, item.key, itemfield.value, itemfield.hash "
    "FROM item, itemfield "
    "WHERE itemfield.type = 'password' AND item.uuid = itemfield.item_uuid;"
)
for row in c:
    # The binary item.key field contains the AES key (32 bytes)
    # concatenated with a nonce (12 bytes) for AESGCM.
    key = row["key"][:32]
    nonce = row["key"][-12:]

    # The hex itemfield.value field contains the ciphertext
    # concatenated with a tag (16 bytes = 32 hex) for authentication.
    ciphertext = bytes.fromhex(row["value"][:-32])
    tag = bytes.fromhex(row["value"][-32:])

    # The UUID without dashes is used as additional authenticated data (AAD).
    aad = bytes.fromhex(row["uuid"].replace("-", ""))

    # Decrypt the AES Galois/counter mode authenticated encryption with associated data (AEAD).
    aesgcm = AESGCM(key)
    password = aesgcm.decrypt(nonce=nonce, data=ciphertext + tag, associated_data=aad)
    print("title: {}, password: {}".format(row["title"], password.decode("utf-8")))

    # Compare with the unsalted SHA1 hash of the password stored in the itemfield.hash field.
    password_hash = hashlib.sha1(password).hexdigest()
    if password_hash != row["hash"]:
        print("Hash mismatch:" + password_hash + " VS " + row["hash"])

c.close()
