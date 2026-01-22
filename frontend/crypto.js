// crypto.js - All cryptographic operations

/**
 * Generate random AES-256 key in Base64
 */
function generateAESKey() {
    return CryptoJS.lib.WordArray.random(32).toString(CryptoJS.enc.Base64);
}

/**
 * Encrypt plaintext with AES-256 in ECB mode
 */
function encryptAES(plaintext, aesKeyB64) {
    try {
        const encrypted = CryptoJS.AES.encrypt(plaintext, CryptoJS.enc.Base64.parse(aesKeyB64), {
            mode: CryptoJS.mode.ECB,
            padding: CryptoJS.pad.Pkcs7
        });
        return encrypted.toString();
    } catch (error) {
        console.error('AES encryption error:', error);
        return null;
    }
}

/**
 * Decrypt AES-256 encrypted content
 */
function decryptAES(encryptedContent, aesKeyB64) {
    try {
        const decrypted = CryptoJS.AES.decrypt(encryptedContent, CryptoJS.enc.Base64.parse(aesKeyB64), {
            mode: CryptoJS.mode.ECB,
            padding: CryptoJS.pad.Pkcs7
        });
        return decrypted.toString(CryptoJS.enc.Utf8);
    } catch (error) {
        console.error('AES decryption error:', error);
        return null;
    }
}

/**
 * Encrypt AES key with RSA public key
 */
async function encryptAESKeyWithPublicKey(aesKeyB64, recipientPublicKeyPEM) {
    try {
        const encrypt = new JSEncrypt();
        encrypt.setPublicKey(recipientPublicKeyPEM);
        const encryptedKey = encrypt.encrypt(aesKeyB64);
        return encryptedKey;
    } catch (error) {
        console.error('RSA encryption error:', error);
        return null;
    }
}

/**
 * Decrypt AES key using private key
 * Supports both new format (JSON) and old format (string)
 */
async function decryptAESKey(encryptedAESKeyOrJson, privateKey) {
    try {
        let encryptedAESKeyB64 = encryptedAESKeyOrJson;
        
        if (typeof encryptedAESKeyOrJson === 'string' && encryptedAESKeyOrJson.startsWith('{')) {
            try {
                const data = JSON.parse(encryptedAESKeyOrJson);
                // First try decrypting with sender key (for sent messages)
                if (data.s) {
                    const decrypt = new JSEncrypt();
                    decrypt.setPrivateKey(privateKey);
                    const aesKeyB64 = decrypt.decrypt(data.s);
                    if (aesKeyB64) return aesKeyB64;
                }
                // Then try with recipient key (for received messages)
                if (data.r) {
                    encryptedAESKeyB64 = data.r;
                }
            } catch (e) {
                console.error('JSON parse error:', e);
            }
        }
        
        // Decrypt AES key using private key
        const decrypt = new JSEncrypt();
        decrypt.setPrivateKey(privateKey);
        const aesKeyB64 = decrypt.decrypt(encryptedAESKeyB64);
        return aesKeyB64 || null;
    } catch (error) {
        console.error('AES key decryption error:', error);
        return null;
    }
}

/**
 * Sign encrypted content with RSA private key
 */
async function signMessage(encryptedContent, privateKey) {
    try {
        if (!privateKey) {
            console.error('Private key not available');
            return null;
        }
        
        // Use JSEncrypt to sign - it does hashing internally
        const sign = new JSEncrypt();
        sign.setPrivateKey(privateKey);
        const signature = sign.sign(encryptedContent, CryptoJS.SHA256, 'sha256');
        
        return signature || null;
    } catch (error) {
        console.error('Signing error:', error);
        return null;
    }
}

/**
 * Verify signature with RSA public key
 */
async function verifySignature(plaintext, signature, senderPublicKeyPEM) {
    try {
        const verify = new JSEncrypt();
        verify.setPublicKey(senderPublicKeyPEM);
        const isValid = verify.verify(plaintext, signature, CryptoJS.SHA256);
        
        return isValid;
    } catch (error) {
        console.error('Signature verification error:', error);
        return false;
    }
}

/**
 * Encrypt file binary data using AES-256
 * fileData is ArrayBuffer or Uint8Array
 */
async function encryptFileBinary(fileData, aesKeyB64) {
    try {
        // Convert ArrayBuffer to base64 string (like text for messages)
        const uint8Array = new Uint8Array(fileData);
        let binaryString = '';
        for (let i = 0; i < uint8Array.length; i++) {
            binaryString += String.fromCharCode(uint8Array[i]);
        }
        const base64Data = btoa(binaryString);
        
        // Encrypt using same method as messages
        const encrypted = CryptoJS.AES.encrypt(base64Data, CryptoJS.enc.Base64.parse(aesKeyB64), {
            mode: CryptoJS.mode.ECB,
            padding: CryptoJS.pad.Pkcs7
        });
        
        // Return as base64 (encrypted.toString() without OpenSSL header)
        // encrypted.toString() returns "U2FsdGVk..." which IS base64
        return encrypted.toString();
    } catch (error) {
        console.error('File encryption error:', error);
        return null;
    }
}

/**
 * Decrypt file from encrypted base64 string
 */
function decryptFileBinary(encryptedData, aesKeyB64) {
    try {
        // Decrypt using same method as messages
        const decrypted = CryptoJS.AES.decrypt(encryptedData, CryptoJS.enc.Base64.parse(aesKeyB64), {
            mode: CryptoJS.mode.ECB,
            padding: CryptoJS.pad.Pkcs7
        });
        
        // Get the base64 string back
        const base64Data = decrypted.toString(CryptoJS.enc.Utf8);
        
        // Decode base64 to binary
        const binaryString = atob(base64Data);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    } catch (error) {
        console.error('File decryption error:', error);
        return null;
    }
}

/**
 * Get sender's public key from API
 */
async function getSenderPublicKey(senderId) {
    try {
        const res = await fetch(`/api/users/${senderId}/public-key`, {
            credentials: 'same-origin'
        });
        if (!res.ok) return null;
        const data = await res.json();
        return data.public_key;
    } catch (error) {
        console.error('Error fetching sender public key:', error);
        return null;
    }
}
