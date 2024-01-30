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
async function generateRSAKeys() {
    const { privateKey, publicKey } = await window.crypto.subtle.generateKeyPair({
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256'
    });
    
    const exportedPrivateKey = await window.crypto.subtle.exportKey('pkcs8', privateKey);
    const exportedPublicKey = await window.crypto.subtle.exportKey('spki', publicKey);
    
    const privateKeyPEM = arrayBufferToPEM(exportedPrivateKey, 'PRIVATE KEY');
    const publicKeyPEM = arrayBufferToPEM(exportedPublicKey, 'PUBLIC KEY');
    
    saveKeys(privateKeyPEM, publicKeyPEM);
}

// Funzione per cifrare un messaggio utilizzando la chiave pubblica
async function encryptRSA(message, publicKeyPEM) {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const publicKey = await window.crypto.subtle.importKey('spki', pemToArrayBuffer(publicKeyPEM), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
    const encryptedData = await window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, data);
    const encryptedMessage = arrayBufferToBase64(encryptedData);
    return encryptedMessage;
}

// Funzione per decifrare un messaggio utilizzando la chiave privata
async function decryptRSA(encryptedMessage, privateKeyPEM) {
    const privateKey = await window.crypto.subtle.importKey('pkcs8', pemToArrayBuffer(privateKeyPEM), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']);
    const buffer = base64ToArrayBuffer(encryptedMessage);
    const decryptedData = await window.crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, buffer);
    const decryptedMessage = new TextDecoder().decode(decryptedData);
    return decryptedMessage;
}

// Funzione per convertire un array buffer in una stringa PEM
function arrayBufferToPEM(buffer, label) {
    const uint8Array = new Uint8Array(buffer);
    const base64String = btoa(String.fromCharCode.apply(null, uint8Array));
    const pemString = `-----BEGIN ${label}-----\n${base64String}\n-----END ${label}-----`;
    return pemString;
}

// Funzione per convertire una stringa PEM in un array buffer
function pemToArrayBuffer(pemString) {
    const base64String = pemString.match(/.{1,64}/g).join('\n');
    const binaryString = atob(base64String);
    const uint8Array = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        uint8Array[i] = binaryString.charCodeAt(i);
    }
    return uint8Array.buffer;
}

// Funzione per convertire un array buffer in una stringa base64
function arrayBufferToBase64(buffer) {
    const uint8Array = new Uint8Array(buffer);
    const binaryString = String.fromCharCode.apply(null, uint8Array);
    const base64String = btoa(binaryString);
    return base64String;
}

// Funzione per convertire una stringa base64 in un array buffer
function base64ToArrayBuffer(base64String) {
    const binaryString = atob(base64String);
    const uint8Array = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        uint8Array[i] = binaryString.charCodeAt(i);
    }
    return uint8Array.buffer;
}
