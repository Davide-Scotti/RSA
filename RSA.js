const crypto = require('crypto');

// Funzione per generare una coppia di chiavi RSA (privata e pubblica)
function generateRSAKeys() {
    return crypto.generateKeyPairSync('rsa', {
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

// Esempio di utilizzo
const { publicKey, privateKey } = generateRSAKeys();
const message = "Hello, this is a secret message!";

// Cifra il messaggio utilizzando la chiave pubblica
const encryptedMessage = encryptRSA(message, publicKey);
console.log("Messaggio cifrato:", encryptedMessage);

// Decifra il messaggio utilizzando la chiave privata
const decryptedMessage = decryptRSA(encryptedMessage, privateKey);
console.log("Messaggio decifrato:", decryptedMessage);
