# Minimal GunDB SEA clone

Usage (console example)
```
// create key pairs and export / import
p1 = await mSEA.pair();
p2 = await mSEA.pair();
bkp = await mSEA.backup(p1);
restored = await mSEA.restore(bkp);
console.log("BACKUP KEYPAIR", bkp);

// plain text to sign / crypt
text = " Message to secure...";

// password based CryptoKey (1:n base...)
shared1 = await mSEA.secret("mySavePassword"); // password based secret with string input
sharedEnc = await mSEA.encrypt(text, shared1);
shared2 = await mSEA.secret("mySavePassword"); // password based secret with string input
sharedDec = await mSEA.decrypt(sharedEnc, shared2);
console.log("ENCRYPTION SHARED SECRET", sharedEnc, sharedDec);

// pub / priv crypto 1:1
secret1 = await mSEA.secret(p2.epub, p1.epriv);
secret2 = await mSEA.secret(p1.epub, p2.epriv);
enc = await mSEA.encrypt(text, secret1);
dec = await mSEA.decrypt(enc, secret2);
console.log("ENCRYPTION 1:1 SECRET", enc, dec);

// Sign & verify
sig = await mSEA.sign(text, p1.priv);
verified = await mSEA.verify(text, sig, p1.pub)
console.log("SIGNING", sig, `\nSignature matching: ${verified}`);
```
