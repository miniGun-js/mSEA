# Minimal GunDB SEA clone

Usage (console example)
```
sea = SEA()

// create users
user1 = await sea.pair()
user2 = await sea.pair()

// encrypt & decrypt
secret_user1 = await sea.secret(user2.epub, user1.epriv)
enc = await sea.encrypt("Test...", secret_user1)

secret_user2 = await sea.secret(user1.epub, user2.epriv)
await = sea.decrypt(enc, secret_user2

// sign &  verify
msg = "Data to sign"
sig = await sea.sign(msg, user1.priv)
await sea.verify(msg, sig, user1.pub)

// backup and restore pair
backup = await sea.backup(user1)
restoredPair = await sea.restore(backup)
```
