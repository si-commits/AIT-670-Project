// script.js

document.addEventListener('DOMContentLoaded', () => {
    const encryptionMethod = document.getElementById('encryptionMethod');
    const keyContainer = document.getElementById('keyContainer');
    const inputText = document.getElementById('inputText');
    const encryptionKey = document.getElementById('encryptionKey');
    const generateKeyButton = document.getElementById('generateKeyButton');
    const outputText = document.getElementById('outputText');
    const encryptButton = document.getElementById('encryptButton');
    const decryptButton = document.getElementById('decryptButton');
    const textError = document.getElementById('textError');
    const keyError = document.getElementById('keyError');
    const backendUrl = 'http://127.0.0.1:5000';

    // Hide key input if RSA is selected
    encryptionMethod.addEventListener('change', () => {
        if (encryptionMethod.value === 'RSA') {
            keyContainer.style.display = 'none';
            encryptionKey.value = '';
            clearError(encryptionKey, keyError);
        } else {
            keyContainer.style.display = 'block';
        }
    });

    // Generate Key button event
    generateKeyButton.addEventListener('click', () => {
        const method = encryptionMethod.value;
        let generatedKey = '';

        if (method === 'AES') {
            // Generate a random key of 16, 24, or 32 bytes
            const keyLengths = [16, 24, 32];
            const keyLength = keyLengths[Math.floor(Math.random() * keyLengths.length)];
            generatedKey = generateRandomKey(keyLength);
        } else if (method === 'DES') {
            // Generate a random key of 8 bytes
            generatedKey = generateRandomKey(8);
        } else {
            // For RSA, key is not required
            generatedKey = '';
        }

        encryptionKey.value = generatedKey;
        clearError(encryptionKey, keyError);
    });

    // Encrypt button event
    encryptButton.addEventListener('click', async () => {
        clearErrors();

        const text = inputText.value.trim();
        const method = encryptionMethod.value;
        const key = encryptionKey.value.trim();

        // Input validation
        let valid = true;

        if (!text) {
            showError(inputText, textError, 'Please enter text to encrypt.');
            valid = false;
        }

        if (method !== 'RSA' && !key) {
            showError(encryptionKey, keyError, 'Encryption key is required for this method.');
            valid = false;
        }

        if (!valid) return;

        setProcessing(true, 'encrypt');

        try {
            // Make a POST request to the /encrypt endpoint
            const response = await fetch(`${backendUrl}/encrypt`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    text: text,
                    method: method,
                    key: key
                })
            });

            const result = await response.json();

            if (response.ok) {
                outputText.value = result.encryptedText;
            } else {
                alert(result.message || 'Encryption failed.');
            }
        } catch (error) {
            console.error('Error:', error);
            alert('An error occurred during encryption.');
        } finally {
            setProcessing(false, 'encrypt');
        }
    });

    // Decrypt button event
    decryptButton.addEventListener('click', async () => {
        clearErrors();

        const text = inputText.value.trim();
        const method = encryptionMethod.value;
        const key = encryptionKey.value.trim();

        // Input validation
        let valid = true;

        if (!text) {
            showError(inputText, textError, 'Please enter text to decrypt.');
            valid = false;
        }

        if (method !== 'RSA' && !key) {
            showError(encryptionKey, keyError, 'Decryption key is required for this method.');
            valid = false;
        }

        if (!valid) return;

        setProcessing(true, 'decrypt');

        try {
            // Make a POST request to the /decrypt endpoint
            const response = await fetch(`${backendUrl}/decrypt`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    text: text,
                    method: method,
                    key: key
                })
            });

            const result = await response.json();

            if (response.ok) {
                outputText.value = result.decryptedText;
            } else {
                alert(result.message || 'Decryption failed.');
            }
        } catch (error) {
            console.error('Error:', error);
            alert('An error occurred during decryption.');
        } finally {
            setProcessing(false, 'decrypt');
        }
    });

    function generateRandomKey(length) {
        const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let key = '';
        for (let i = 0; i < length; i++) {
            key += charset.charAt(Math.floor(Math.random() * charset.length));
        }
        return key;
    }

    function showError(inputElement, errorElement, message) {
        inputElement.classList.add('error');
        errorElement.textContent = message;
    }

    function clearError(inputElement, errorElement) {
        inputElement.classList.remove('error');
        errorElement.textContent = '';
    }

    function clearErrors() {
        clearError(inputText, textError);
        clearError(encryptionKey, keyError);
    }

    function setProcessing(isProcessing, action) {
        if (isProcessing) {
            if (action === 'encrypt') {
                encryptButton.disabled = true;
                encryptButton.textContent = 'Encrypting...';
            } else {
                decryptButton.disabled = true;
                decryptButton.textContent = 'Decrypting...';
            }
            // Disable the other button
            encryptButton.disabled = true;
            decryptButton.disabled = true;
        } else {
            encryptButton.disabled = false;
            decryptButton.disabled = false;
            encryptButton.textContent = 'Encrypt';
            decryptButton.textContent = 'Decrypt';
        }
    }
});
