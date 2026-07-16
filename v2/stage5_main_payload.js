/**
 * Stage 5 - Main Post-Exploitation Payload (PLASMAGRID Stager)
 * =============================================================
 * SHA1: 377bed7460f7538f96bbad7bdc2b8294bdc54599
 *
 * This is the main post-exploitation payload, delivered as an encrypted
 * base64 string (~292KB). It calls the `qbrdr` function registered by
 * earlier stages (stage2/stage3) to decrypt and execute the payload.
 *
 * The encrypted data is AES-encrypted using a key derived during the
 * exploit chain execution. Without the runtime-derived key, this payload
 * cannot be decrypted statically.
 *
 * This payload is believed to be the PLASMAGRID stager - a sophisticated
 * implant that:
 *   - Establishes persistence on the compromised iOS device
 *   - Exfiltrates sensitive data (contacts, messages, photos, location)
 *   - Provides remote access capabilities
 *   - Communicates with C2 infrastructure
 *
 * Part of the Coruna exploit kit targeting CVE-2024-23222.
 */

// The encrypted payload data is ~292KB of base64-encoded, AES-encrypted content.
// It is passed to the qbrdr() decryption handler registered by stage2/stage3.
//
// The payload is too large to include inline with comments - see the original
// file stage5_377bed7460f7538f96bbad7bdc2b8294bdc54599.js for the raw data.
//
// Structure: window["qbrdr"]("<~292KB of encrypted base64 data>")
//
// The original file is preserved as-is since the encrypted content cannot
// be meaningfully deobfuscated without the runtime decryption key.

// NOTE: For the actual encrypted data, refer to the original file:
// WebKitChainReverse/stage5_377bed7460f7538f96bbad7bdc2b8294bdc54599.js
