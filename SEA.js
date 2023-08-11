const 
SEA = (length = 256, derivedCryptKeyAlgorithm = 'AES-GCM') => {
    const
    // crypto api settings for sign / verify, deriveKey and de-/encrypt  
    signKeyParams = { name: 'ECDSA', namedCurve: `P-${length}` },
    signAlgorithm = { name: signKeyParams.name, hash: { name: `SHA-${length}` }},
    usage_sign = ['sign', 'verify'],
    deriveKeyParams = { name: 'ECDH', namedCurve: `P-${length}` },
    usage_derive = ['deriveKey'],
    cryptAlgorithm = { name: derivedCryptKeyAlgorithm },
    usage_crypt = ['encrypt', 'decrypt'],
    keyExtractable = true,
    importKeyParams = { 
        pub: ['raw', signKeyParams, keyExtractable, [usage_sign[1]]],
        priv: ['jwk', signKeyParams, keyExtractable, [usage_sign[0]]],
        epub: ['raw', deriveKeyParams, keyExtractable, []],
        epriv: ['jwk', deriveKeyParams, keyExtractable, usage_derive]
    },
    // shorthands
    cryptoSubtle = crypto.subtle,
    // convert Object <=> Base64
    objToBase64 = (obj) => btoa(JSON.stringify(obj)),
    base64ToObj = (base64obj) => JSON.parse(atob(base64obj)),
    // convert Uint8Array <=> Base64
    uint8ArrayToBase64 = (uint8ArrayInput) => btoa(String.fromCharCode.apply(null, uint8ArrayInput)),
    base64ToUint8Array = (base64String) => new Uint8Array([...atob(base64String)].map(c=>c.charCodeAt())),
    // convert ArrayBuffer <=> Base64
    arrayBufferToBase64 = (buffer) => uint8ArrayToBase64(new Uint8Array(buffer)),
    base64ToArrayBuffer = (base64String) => base64ToUint8Array(base64String).buffer,
    // Text De-/Encoder
    textEncode = (data) => new TextEncoder().encode(data),
    textDecode = (data) => new TextDecoder().decode(data),

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
        //_soul = '~' + await exportKey(signPair.publicKey)
        return { 
            //soul: '~' + await exportKey(signPair.publicKey), 
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
        return arrayBufferToBase64(await cryptoSubtle.sign(
            signAlgorithm, 
            priv, 
            textEncode(data)
        ))
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
            base64ToArrayBuffer(signedData), 
            textEncode(data)
        )
    },

    /**
     * Create a secret for de-/encryption
     * 
     * @param {CryptoKey} foreignPub - Public encryption key of recipient
     * @param {CryptoKey} ownPriv - Private encryption key of sender
     * @return {yptoKey} Secret to use for de-/encryption
     * 
     * @todo Passphrase based encryption? https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey#pbkdf2_2
     */
    secret = async (foreignPub, ownPriv) => {
        //console.log("SECRET", deriveKeyParams.name)
        return await cryptoSubtle.deriveKey(
            { name: deriveKeyParams.name, public: foreignPub }, 
            ownPriv, 
            { ...cryptAlgorithm, length: length }, 
            true, 
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
     * @todo 1:n encryption with password based shared secret key?
     */
    encrypt = async (data, derivedKey) => {
        let 
        iv = crypto.getRandomValues(new Uint8Array(12)),
        preparedData = textEncode(data),
        encData = await cryptoSubtle.encrypt(
            { ...cryptAlgorithm, iv }, 
            derivedKey, 
            preparedData
        ),
        package = JSON.stringify({
            enc: arrayBufferToBase64(encData), 
            iv: uint8ArrayToBase64(iv)
        })
        //console.log("package stringify", package)
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
        parsedData = JSON.parse(encDataIn),
        decodedData = base64ToArrayBuffer(parsedData.enc),
        decodedIV = base64ToUint8Array(parsedData.iv),
        decrytedData = await cryptoSubtle.decrypt(
            { ...cryptAlgorithm, iv: decodedIV }, 
            derivedKey, 
            decodedData
        )
        return textDecode(decrytedData)
    },

    /**
     * Export CryptoKey to base64
     * 
     * @param {cryptoKey} cryptoKey - Key to export to base64
     * @param {String} seaUse - One of pub, priv, epub or epriv
     * @return {String} Base64 encoded and exported CryptoKey
     */
    exportKey = async (cryptoKey, seaUse = 'pub') => {
        let 
        type = importKeyParams[seaUse][0],
        convertMethod = (type == 'raw') ? arrayBufferToBase64 : objToBase64
        return convertMethod(await cryptoSubtle.exportKey(type, cryptoKey))
    },
   
    /**
     * Import CryptoKey
     * 
     * @param {String} base64key - Base64 key to import
     * @param {String} seaUse - One of pub, priv, epub or epriv
     * @return {CryptoKey} Imported CryptoKey
     */
    importKey = async (base64key, seaUse = 'pub') => {
        let 
        type = importKeyParams[seaUse][0],
        convertMethod = (type == 'raw') ? base64ToArrayBuffer : base64ToObj
        return await cryptoSubtle.importKey(
        type, 
        convertMethod(base64key), 
        ...importKeyParams[seaUse].slice(1)
    )}, 

    /**
     * Backup full sea user pairs
     * 
     * @param {Object} pairs - sea pair object
     * @return {Object} Stringified exported CryptoKeys 
     */
    backup = async (pairs) => {
        let exportedPairs = {}
        //delete pairs.soul
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
            /*if(seaUse == 'pub') {
                importedPairs.soul = '~' + exportedKey
            }*/
            importedPairs[seaUse] = await importKey(exportedKey, seaUse)
        }
        return importedPairs
    }
    // expose public methods
    return { pair, sign, verify, secret, encrypt, decrypt, exportKey, importKey, backup, restore }
}
