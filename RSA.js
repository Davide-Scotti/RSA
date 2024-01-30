const fs = require('fs')
const crypto = require('crypto')

// Funzione per caricare le chiavi da file
function loadKeys() {
    const privateKey = fs.readFileSync('private_key.pem', 'utf-8')
    const publicKey = fs.readFileSync('public_key.pem', 'utf-8')
    return { privateKey, publicKey }
}

// Funzione per salvare le chiavi su file
function saveKeys(privateKey, publicKey) {
    fs.writeFileSync('private_key.pem', privateKey, 'utf-8')
    fs.writeFileSync('public_key.pem', publicKey, 'utf-8')
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
