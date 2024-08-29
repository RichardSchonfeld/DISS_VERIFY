
async function encryptPrivateKey(privateKey, password) {
            const encoder = new TextEncoder();
            const keyMaterial = await crypto.subtle.importKey(
                'raw',
                encoder.encode(password),
                'PBKDF2',
                false,
                ['deriveKey']
            );

            const salt = crypto.getRandomValues(new Uint8Array(16));
            const key = await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: 100000,
                    hash: 'SHA-256',
                },
                keyMaterial,
                { name: 'AES-CBC', length: 256 },
                false,
                ['encrypt']
            );

            const iv = crypto.getRandomValues(new Uint8Array(16));
            const encryptedPrivateKey = await crypto.subtle.encrypt(
                { name: 'AES-CBC', iv: iv },
                key,
                encoder.encode(privateKey)
            );

            return btoa(String.fromCharCode(...new Uint8Array(salt.buffer)) + String.fromCharCode(...new Uint8Array(iv.buffer)) + String.fromCharCode(...new Uint8Array(encryptedPrivateKey)));
        }

async function decryptPrivateKey(encryptedPrivateKey, password) {
        try {
            // Ensure the encryptedPrivateKey is properly decoded from base64
            const decodedData = Uint8Array.from(atob(encryptedPrivateKey), c => c.charCodeAt(0));
            const salt = decodedData.slice(0, 16);
            const iv = decodedData.slice(16, 32);
            const encryptedData = decodedData.slice(32);

            console.log("IV Length:", iv.length);  // This should print 16

            const encoder = new TextEncoder();
            const keyMaterial = await crypto.subtle.importKey(
                'raw',
                encoder.encode(password),
                'PBKDF2',
                false,
                ['deriveKey']
            );

            const key = await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: 100000,
                    hash: 'SHA-256',
                },
                keyMaterial,
                { name: 'AES-CBC', length: 256 },
                false,
                ['decrypt']
            );

            const decryptedPrivateKey = await crypto.subtle.decrypt(
                { name: 'AES-CBC', iv: iv },
                key,
                encryptedData
            );

            return new TextDecoder().decode(decryptedPrivateKey);
        } catch (error) {
            console.error('Error in decryptPrivateKey:', error);
            throw error;
        }
    }

/*
async function decryptFragment(encryptedFragment, privateKey, password) {
    try {
        const decryptedPrivateKey = await decryptPrivateKey(privateKey, password);

        // Now decrypt the fragment with the user's decrypted private key
        const cryptoKey = await window.crypto.subtle.importKey(
            "pkcs8",
            new Uint8Array(decryptedPrivateKey),  // Your decrypted private key as Uint8Array
            { name: "RSA-OAEP", hash: "SHA-256" },
            true,
            ["decrypt"]
        );

        const decryptedFragment = await window.crypto.subtle.decrypt(
            {
                name: "RSA-OAEP"
            },
            cryptoKey,
            encryptedFragment
        );

        return new TextDecoder().decode(decryptedFragment);
    } catch (error) {
        console.error('Error decrypting fragment:', error);
        throw error;
    }
}

// Usage example in your existing workflow:
const decryptedFragment = await decryptFragment(encryptedFragmentFromBackend, userEncryptedPrivateKey, userPassword);

 */