#!/usr/bin/env python3

import hashlib
from pysqlcipher3 import dbapi2 as sqlite
from Crypto.Cipher import AES

# https://www.enpass.io/docs/security-whitepaper-enpass/vault.html
# https://discussion.enpass.io/index.php?/topic/4446-enpass-6-encryption-details/
# https://www.zetetic.net/sqlcipher/sqlcipher-api/
# https://www.dlitz.net/software/pycrypto/api/current/

enpass_db_file = 'vault/vault.enpassdb'
enpass_master_password = b'secretmasterpassword'

# The first 16 bytes of the database file are used as salt
enpass_db_salt = open(enpass_db_file, 'rb').read(16)

# The database key is derived from the master password
# and the database salt with 100k iterations of PBKDF2-HMAC-SHA512
enpass_db_key = hashlib.pbkdf2_hmac('sha512', enpass_master_password, enpass_db_salt, 100000)

# The raw key for the sqlcipher database is given
# by the first 64 characters of the hex-encoded key
enpass_db_hex_key = enpass_db_key.hex()[:64]

print('--- db hex key [64 hex = 32 bytes] ---')
print(enpass_db_hex_key)

# Open DB with hex key and sqlcipher v3 compatibility mode
conn = sqlite.connect(enpass_db_file)
c = conn.cursor()
c.row_factory = sqlite.Row
c.execute('PRAGMA key="x\'' + enpass_db_hex_key + '\'";')
c.execute('PRAGMA cipher_compatibility = 3;')

# Identity.Info
c.execute("SELECT * FROM Identity;")
identity = c.fetchone()

print('--- Identity.Info [88 hex = 44 bytes] ---')
print(identity['Info'])
print(identity['Info'].hex())

# vault_info.mp & vault_info.key
c.execute("SELECT * FROM vault_info WHERE vault_uuid = 'primary';")
vault_info = c.fetchone()

print('--- vault_info.mp [72 hex = 36 bytes] ---')
print(vault_info['mp'])
print(vault_info['mp'].hex())
print('--- vault_info.key [230 hex = 115 bytes] ---')
print(vault_info['key'])
print(vault_info['key'].hex())

# preferences(key=secure_settings)
c.execute("SELECT * FROM preferences where key = 'secure_settings';")
secure_settings = c.fetchone()

print('--- preferences(key=secure_settings).value [160 hex = 80 bytes] ---')
print(secure_settings['value'])
print(secure_settings['value'].hex())

# preferences(key=dirty)
c.execute("SELECT * FROM preferences where key = 'dirty';")
preferences = c.fetchone()

print('--- preferences(key=dirty).value [34 hex = 17 bytes] ---')
print(preferences['value'])
print(preferences['value'].hex())

# item(id=1).key
c.execute("SELECT * FROM item WHERE id = 8;")
item = c.fetchone()
item_uuid = item['uuid']

print('--- item(id=1).key [88 hex = 44 bytes] ---')
print(item['key'])
print(item['key'].hex())

# itemfield(type=password).value
c.execute("SELECT * FROM itemfield WHERE type='password' and item_uuid=?;", (item_uuid,))
itemfield = c.fetchone()

print('--- itemfield(type=password).value [60 hex = 30 bytes] ---')
print(itemfield['value'])

c.close()

# hex <-> byte conversion:
#  1 hex  = 4 bits (2^4 = 16)
#  1 byte = 8 bits (2^8 = 256)
#  2 hex  = 1 byte (16 x 16 = 256)

# The encryption algorithm is 256-bit AES in CBC mode.
# CBC = Cipher-Block-Chaining (=> IV = Initialization Vector)
# 256 bit (= 32 bytes = 64 hex) key
# 128 bit (= 16 bytes = 32 hex) initialization vector
# salt 16 hex = 8 bytes not used and can be discarded
# 16 bytes = 32 hex = AES block size

# HMAC-SHA1 = 20 bytes = 40 hex

print('=========================')

# The 72 hex long vault_info['mp'] could consist
# of the 32 hex initialization vector for AES
# and the 40 hex HMAC-SHA1 checksum.
# The candidates for the IV are therefore the
# first or last 32 hex of vault_info['mp']
iv_candidates = []
iv_candidates.append(vault_info['mp'].hex()[:32])
iv_candidates.append(vault_info['mp'].hex()[-32:])
iv_candidates.append(vault_info['mp'].hex()[:32][::-1])
iv_candidates.append(vault_info['mp'].hex()[-32:][::-1])
print(' iv_candidates = ' + str(iv_candidates))

# The most obvious candidate for the encrypted password
# is the itemfield['value']. In addition to the 32 hex
# block size, its length seems to encode the padding
# info (2 hex) to recover the initial plaintext password.
# The candidates for the encoded bytes are thus the
# first, last or middle 32 hex of itemfield['value']
enc_candidates = []
enc_candidates.append(itemfield['value'][:32])
enc_candidates.append(itemfield['value'][-32:])
enc_candidates.append(itemfield['value'][16:48])
enc_candidates.append(itemfield['value'][:32][::-1])
enc_candidates.append(itemfield['value'][-32:][::-1])
enc_candidates.append(itemfield['value'][16:48][::-1])
print('enc_candidates = ' + str(enc_candidates))

# The tricky part is to identify the 64 hex AES key.
key_candidates = []
key_candidates.append(enpass_db_hex_key)
key_candidates.append(item['key'].hex()[:64])
key_candidates.append(item['key'].hex()[-64:])
key_candidates.append(vault_info['key'].hex()[:64])
key_candidates.append(vault_info['key'].hex()[-64:])
key_candidates.append(identity['Info'].hex()[:64])
key_candidates.append(identity['Info'].hex()[-64:])
key_candidates.append(item['key'].hex()[:64][::-1])
key_candidates.append(item['key'].hex()[-64:][::-1])
key_candidates.append(vault_info['key'].hex()[:64][::-1])
key_candidates.append(vault_info['key'].hex()[-64:][::-1])
key_candidates.append(identity['Info'].hex()[:64][::-1])
key_candidates.append(identity['Info'].hex()[-64:][::-1])
print('key_candidates = ' + str(key_candidates))

print('=========================')

# Let's encode the plaintext password substring
# as bytearray with utf-8 encoding, then convert it
# to a list with the corresponding character codes.
# This is the sequence we are trying to find in the
# decryption candidates below.
print(list('1234567890'.encode(encoding="utf-8")))

print('=========================')

# Loop over all candidates and try to decrypt the cipher.
for iv in iv_candidates:
    for enc in enc_candidates:
        for key in key_candidates:
            cipher = AES.new(bytes.fromhex(key), AES.MODE_CBC, bytes.fromhex(iv))
            dec = cipher.decrypt(bytes.fromhex(enc))
            print(list(dec))
