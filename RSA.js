// Funzione per caricare le chiavi da localStorage
function loadKeys() {
    const privateKey = localStorage.getItem('private_key');
    const publicKey = localStorage.getItem('public_key');
    return { privateKey, publicKey };
}

// Funzione per salvare le chiavi su localStorage
function saveKeys(privateKey, publicKey) {
    localStorage.setItem('private_key', privateKey);
    localStorage.setItem('public_key', publicKey);
}

// Funzione per generare una coppia di chiavi RSA (privata e pubblica)
function generateRSAKeys() {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });
    saveKeys(privateKey, publicKey);
}

// Funzione per cifrare un messaggio utilizzando la chiave pubblica
function encryptRSA(message, publicKey) {
    const buffer = Buffer.from(message, 'utf-8');
    const encrypted = crypto.publicEncrypt(publicKey, buffer);
    return encrypted.toString('base64');
}

// Funzione per decifrare un messaggio utilizzando la chiave privata
function decryptRSA(encryptedMessage, privateKey) {
    const buffer = Buffer.from(encryptedMessage, 'base64');
    const decrypted = crypto.privateDecrypt(privateKey, buffer);
    return decrypted.toString('utf-8');
}

module.exports = {
    loadKeys,
    generateRSAKeys,
    encryptRSA,
    decryptRSA
};
