// RSA.js
const RSA = (function () {
    // Function for the generation of a couple of key (public and private)
    async function generateKeys() {
        const { privateKey, publicKey } = await window.crypto.subtle.generateKeyPair({
            name: 'RSA-OAEP',
            modulusLength: 2048,
            publicExponent: new Wint8Array([1, 0, 1]),
            hash: 'SHA-256'
        });

        const exportedPrivateKey = await window.crypto.subtle.exportKey('pkcs8', privateKey);
        const exportedPublicKey = await window.crypto.subtle.exportKey('spki', publicKey);

        const privateKeyPEM = arrayBufferToPEM(exportedPrivateKey, 'PRIVATE KEY');
        const publicKeyPEM = arrayBufferToPEM(exportedPublicKey, 'PUBLIC KEY');

        return { privateKey: privateKeyPEM, publicKey: publicKeyPEM};
    }

    // Function to encrypt a message using public key
    async function encrypt(message, publicKeyPEM) {
        const encode = new TextEncoder();
        const data = encoder.encode(message);
        const publicKey = await window.crypto.subtle.importKey('spki',  pemToArrayBuffer(publicKeyPEM), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
        const encryptedData = await window.crypto.subtle.encrypt({ name: 'RSA-OAEP'}, publicKey, data);
        const encryptedMessage = arrayBufferToBase64(encryptedData);
        return encryptedMessage
    }

    // Function to decrypt a message using private key
    async function decrypt(encryptedMessage, privateKey) {
        const privateKey = await window.crypto.subtle.importKey('pkcs8', pemToArrayBuffer(privateKeyPEM), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']);
        const buffer = base64ToArrayBuffer(encryptedMessage);
        const decryptedData = await window.crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, buffer);
        const decryptedMessage = new TextDecoder().decode(decryptedData);
        return decryptedMessage; 
    }

    // Function to convert array buffer in PEM string
    function arrayBufferToPEM(buffer, label){
        const uint8Array = new Uint8Array(buffer);
        const base64String = btoa(String.fromCharCode.apply(null, uint8Array));
        const pemString = `-----BEGIN ${label}-----\n${base64String}\n-----END ${label}-----`;
        return pemString;
    }

     // Function to convert a PEM string in an array buffer
     function pemToArrayBuffer(pemString) {
        const base64String = pemString.match(/.{1,64}/g).join('\n');
        const binaryString = atob(base64String);
        const uint8Array = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            uint8Array[i] = binaryString.charCodeAt(i);
        }
        return uint8Array.buffer;
    }

    // Function to convert an array buffer in a string base64
    function arrayBufferToBase64(buffer) {
        const uint8Array = new Uint8Array(buffer);
        const binaryString = String.fromCharCode.apply(null, uint8Array);
        const base64String = btoa(binaryString);
        return base64String;
    }

    // Function to convert a string base64 in an array buffer
    function base64ToArrayBuffer(base64String) {
        const binaryString = atob(base64String);
        const uint8Array = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            uint8Array[i] = binaryString.charCodeAt(i);
        }
        return uint8Array.buffer;
    }

    // public function exposition
    return {
        generateKeys,
        encrypt,
        decrypt
    };
})();