/**
 * SHA-256 Hash Implementation
 * ============================
 * Used by the module loader to compute SHA1-like hashes of module paths
 * for cache-busting and module identification.
 *
 * This is a standard SHA-256 implementation embedded inline in the exploit kit.
 * It's used by the async module loader (ZKvD0e/loadModuleAsync) to generate
 * the filename hash: SHA256(salt + moduleId).substring(0, 40)
 *
 * Part of the Coruna exploit kit (group.html).
 */

/**
 * Compute SHA-256 hash of input string
 * @param {string} message - Input string to hash
 * @returns {string} Hex-encoded SHA-256 hash
 */
function sha256(message) {
    let hexResult = "";

    function rightRotate(value, amount) {
        return value >>> amount | value << 32 - amount;
    }

    const pow = Math.pow;
    const maxWord = pow(2, 32);
    const lengthProperty = "length";

    let i, j;
    const words = [];
    const messageBitLength = 8 * message[lengthProperty];

    // Initialize hash values (first 32 bits of fractional parts of square roots of first 8 primes)
    let hash = sha256.h = sha256.h || [];
    // Initialize round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
    const roundConstants = sha256.k = sha256.k || [];
    let numPrimes = roundConstants[lengthProperty];

    // Pre-compute prime-derived constants
    const composites = {};
    for (let prime = 2; numPrimes < 64; prime++) {
        if (!composites[prime]) {
            for (i = 0; i < 313; i += prime) {
                composites[i] = prime;
            }
            hash[numPrimes] = pow(prime, 0.5) * maxWord | 0;
            roundConstants[numPrimes++] = pow(prime, 1 / 3) * maxWord | 0;
        }
    }

    // Pad message
    message += "\x80";
    while (message[lengthProperty] % 64 - 56) {
        message += "\0";
    }

    // Parse message into 32-bit words
    for (i = 0; i < message[lengthProperty]; i++) {
        j = message.charCodeAt(i);
        if (j >> 8) return; // Only supports ASCII
        words[i >> 2] |= j << (3 - i) % 4 * 8;
    }

    // Append bit length
    words[words[lengthProperty]] = messageBitLength / maxWord | 0;
    words[words[lengthProperty]] = messageBitLength;

    // Process each 512-bit block
    for (j = 0; j < words[lengthProperty];) {
        const block = words.slice(j, j += 16);
        const previousHash = hash;

        hash = hash.slice(0, 8);

        for (i = 0; i < 64; i++) {
            const w15 = block[i - 15];
            const w2 = block[i - 2];
            const a = hash[0];
            const e = hash[4];

            // Extend message schedule + compression
            j = hash[7]
                + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25))
                + (e & hash[5] ^ ~e & hash[6])
                + roundConstants[i]
                + (block[i] = i < 16
                    ? block[i]
                    : block[i - 16]
                        + (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ w15 >>> 3)
                        + block[i - 7]
                        + (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ w2 >>> 10)
                    | 0);

            hash = [
                j + ((rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22))
                    + (a & hash[1] ^ a & hash[2] ^ hash[1] & hash[2])) | 0
            ].concat(hash);

            hash[4] = hash[4] + j | 0;
        }

        // Add compressed chunk to current hash value
        for (i = 0; i < 8; i++) {
            hash[i] = hash[i] + previousHash[i] | 0;
        }
    }

    // Produce final hex string
    for (i = 0; i < 8; i++) {
        for (j = 3; j + 1; j--) {
            const byte = hash[i] >> 8 * j & 255;
            hexResult += (byte < 16 ? 0 : "") + byte.toString(16);
        }
    }

    return hexResult;
}
