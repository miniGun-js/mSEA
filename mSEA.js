/**
 * Minimal Web Crypto API wrapper inspirend by GunDB SEA
 * 
 */
const 
mSEA = (() => {
    const
    // crypto api settings for sign / verify, deriveKey and de-/encrypt  
    signKeyParams = { 
        name: 'RSASSA-PKCS1-v1_5', 
        modulusLength: 2048, 
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256", 
    },
    signAlgorithm = signKeyParams.name,
    //signAlgorithm = { name: signKeyParams.name, hash: { name: "SHA-512" }},
    /*
    signKeyParams = { name: 'ECDSA', namedCurve: `P-${length}` },
    signAlgorithm = { name: signKeyParams.name, hash: { name: "SHA-1" }},   // PHP fails with SHA-256 !!!   
    */
    // https://www.php.net/manual/en/function.openssl-get-md-methods.php
    // https://stackoverflow.com/questions/32991501/how-to-verify-ecdsa-with-sha256-signature-with-php
    usage_sign = ['sign', 'verify'],
    deriveKeyParams = { name: 'ECDH', namedCurve: "P-256" },
    usage_derive = ['deriveKey'],
    cryptAlgorithm = { name: 'AES-GCM', length: '256' },
    usage_crypt = ['encrypt', 'decrypt'],
    keyExtractable = true,
    // shorthand
    cryptoSubtle = crypto.subtle,
    // convert helpers    
    StringToUint8Array = (string) => Uint8Array.from([...string].map(ch => ch.charCodeAt())),
    Uint8ToArrayBuffer = (uint8array) => uint8array.buffer,
    StringToArrayBuffer = (string) => Uint8ToArrayBuffer(StringToUint8Array(string)),
    ArrayBufferToUint8Array = (arrayBuff) => new Uint8Array(arrayBuff),
    ArrayBufferToString = (arrayBuff) => Uint8ToString(ArrayBufferToUint8Array(arrayBuff)),
    Uint8ToString = (uint8array) => String.fromCharCode.apply(null, uint8array),
    ObjectToJson = (object) => JSON.stringify(object),
    JsonToObject = (string) => JSON.parse(string),
    StringToBase64 = (string) => btoa(string),
    Base64ToString = (base64) => atob(base64),
    ArrayBufferToBase64 = (arrayBuff) => StringToBase64(ArrayBufferToString(arrayBuff)),
    Base64ToArrayBuffer = (base64) => StringToArrayBuffer(Base64ToString(base64)),
    ObjectToBase64 = (object) => StringToBase64(ObjectToJson(object)),
    Base64ToObject = (base64) => JsonToObject(Base64ToString(base64)),
    // import and export options
    tranferKeyParams = { 
        pub: { type: 'spki', exp: ArrayBufferToBase64, imp: Base64ToArrayBuffer, opt: [ signKeyParams, keyExtractable, [usage_sign[1]] ] },
        priv: { type: 'jwk', exp: ObjectToBase64, imp: Base64ToObject, opt: [ signKeyParams, keyExtractable, [usage_sign[0]] ] },
        epub: { type: 'spki', exp: ArrayBufferToBase64, imp: Base64ToArrayBuffer, opt: [ deriveKeyParams, keyExtractable, [] ] },
        epriv: { type: 'jwk', exp: ObjectToBase64, imp: Base64ToObject, opt: [ deriveKeyParams, keyExtractable, usage_derive ] }
    },
    // Passphrase based CryptoKey
    passphraseKeyParams = {
        name: "PBKDF2",
        salt: StringToUint8Array("SaltString..."),
        iterations: 1000,
        hash: "SHA-256"
    },
    passphraseKeyParamName = { name: "PBKDF2" },
    
    /**
     * Generate sea user key pairs
     * { pub, priv, epub, epriv }
     * 
     * @return {Object} sea user key pairs 
     */
    pair = async () => {
        let 
        signPair = await cryptoSubtle.generateKey(signKeyParams, keyExtractable, usage_sign),
        derivePair = await cryptoSubtle.generateKey(deriveKeyParams, keyExtractable, usage_derive)
        return { 
            pub: signPair.publicKey, 
            priv: signPair.privateKey, 
            epub: derivePair.publicKey, 
            epriv: derivePair.privateKey 
        }
    },

    /**
     * Signing data
     * 
     * @param {String} data - Message to sign
     * @param {CryptoKey} priv - Private key to use for signing
     * @return {String} Base64 encoded signature
     */
    sign = async (data, priv) => {
        return StringToBase64(ArrayBufferToString(await cryptoSubtle.sign(
            signAlgorithm, 
            priv, 
            StringToArrayBuffer(data)
        )))
    },

    /**
     * Verify data with signature
     * 
     * @param {String} data - Message to check
     * @param {String} signedData - Signature to match
     * @param {CryptoKey} pub - Public sign key to use
     * @return {Boolean} Signature verification result
     */
    verify = async (data, signedData, pub) => {
        return await cryptoSubtle.verify(
            signAlgorithm, 
            pub, 
            StringToArrayBuffer(Base64ToString(signedData)), 
            StringToArrayBuffer(data)
        )
    },

    /**
     * Create a password based CryptoKey for 1:n encryption
     * 
     * @param {String} password Password String
     * @return {CryptoKey} Password based secret for de-/encryption
     * 
     * @todo Remove hardcoded params (salt, iterations, ...)
     * 
     * shared secret from password:
     * - https://medium.com/@lina.cloud/password-based-client-side-crypto-6fbe4b389bac
     */
    passphraseBasedSecret = async (password) => {
        return await cryptoSubtle.deriveKey(
            passphraseKeyParams,
            await cryptoSubtle.importKey(
                'raw',
                StringToUint8Array(password),
                passphraseKeyParamName,
                false, // not extractable...
                usage_derive
            ),
            cryptAlgorithm,
            keyExtractable,
            usage_crypt
        )
    },

    /**
     * Create a secret for de-/encryption
     * 
     * @param {CryptoKey|String} foreignPub - Public encryption key of recipient OR password string
     * @param {CryptoKey} ownPriv - Private encryption key of sender
     * @return {yptoKey} Secret to use for de-/encryption
     */
    secret = async (foreignPub, ownPriv) => {
        //console.log("SECRET", deriveKeyParams.name)
        if(!ownPriv, typeof foreignPub === 'string') {
            return await passphraseBasedSecret(foreignPub)
        }
        return await cryptoSubtle.deriveKey(
            { name: deriveKeyParams.name, public: foreignPub }, 
            ownPriv, 
            cryptAlgorithm, 
            keyExtractable, 
            usage_crypt
        )
    },

    /**
     * Encrypt with derivedKey / Secret
     * 
     * @param {String} data - Message to encrypt
     * @param {CryptoKey} derivedKey - Secret to use for encryption
     * @return {String} Stringified encData + iv
     * 
     * @todo Object instead of stringified?
     */
    encrypt = async (data, derivedKey) => {
        let 
        iv = crypto.getRandomValues(new Uint8Array(12)),
        encData = await cryptoSubtle.encrypt(
            { ...cryptAlgorithm, iv }, 
            derivedKey, 
            StringToUint8Array(data)
        ),
        package = ObjectToJson({
            enc: ArrayBufferToBase64(encData),  
            iv: StringToBase64(Uint8ToString(iv))
        })
        return package
    },

    /**
     * Decrypt with derivedKey / Secret
     * 
     * @param {String} encDataIn - Stringified encData + iv
     * @param {CryptoKey} derivedKey - Secret to use for decryption
     * @return {String} Decrypted message
     */
    decrypt = async (encDataIn, derivedKey) => {
        let 
        parsedData = JsonToObject(encDataIn),
        decodedIV = StringToUint8Array(Base64ToString(parsedData.iv)),
        decrytedData = await cryptoSubtle.decrypt(
            { ...cryptAlgorithm, iv: decodedIV }, 
            derivedKey, 
            Base64ToArrayBuffer(parsedData.enc)
        )
        return ArrayBufferToString(decrytedData)
    },

    /**
     * Export CryptoKey to base64
     * 
     * @param {cryptoKey} cryptoKey - Key to export to base64
     * @param {String} seaUse - One of pub, priv, epub or epriv
     * @return {String} Base64 encoded and exported CryptoKey
     */
    exportKey = async (cryptoKey, seaUse = 'pub') => tranferKeyParams[seaUse].exp(
        await cryptoSubtle.exportKey(
            tranferKeyParams[seaUse].type, 
            cryptoKey
        )
    ),
   
    /**
     * Import CryptoKey
     * 
     * @param {String} base64key - Base64 key to import
     * @param {String} seaUse - One of pub, priv, epub or epriv
     * @return {CryptoKey} Imported CryptoKey
     */
    importKey = async (base64key, seaUse = 'pub') => await cryptoSubtle.importKey(
        tranferKeyParams[seaUse].type, 
        tranferKeyParams[seaUse].imp(base64key), 
        ...tranferKeyParams[seaUse].opt
    ),

    /**
     * Backup full sea user pairs
     * 
     * @param {Object} pairs - sea pair object
     * @return {Object} Stringified exported CryptoKeys 
     */
    backup = async (pairs) => {
        let exportedPairs = {}
        for (const [seaUse, cryptoKey] of Object.entries(pairs)) {
            //console.log('BACKUP', seaUse, cryptoKey)
            exportedPairs[seaUse] = await exportKey(cryptoKey, seaUse)
        }
        return exportedPairs
    },

    /**
     * Restore full sea user pairs from backup
     * 
     * @param {Object} exportedPairs - Object with exported CryptoKeys
     * @return {Object} Imported sea user pair CryptoKeys
     */
    restore = async (exportedPairs) => {
        let importedPairs = {}
        for (const [seaUse, exportedKey] of Object.entries(exportedPairs)) {
            //console.log('RESTORE', seaUse, exportedKey)
            importedPairs[seaUse] = await importKey(exportedKey, seaUse)
        }
        return importedPairs
    }

    // expose public methods
    return { pair, sign, verify, secret, encrypt, decrypt, exportKey, importKey, backup, restore }
})()
