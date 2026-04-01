(function (root, factory) {
    var api = factory(root);

    if (typeof module !== "undefined" && module.exports) {
        module.exports = api;
    }

    if (typeof window !== "undefined") {
        window.PayloadGenCrypto = api;
    }
}(typeof globalThis !== "undefined" ? globalThis : this, function (root) {
    "use strict";

    // RFC 9001 - QUIC Initial Secrets
    // Salt for QUIC v1 (version 0x00000001)
    var QUIC_V1_INITIAL_SALT = new Uint8Array([
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
        0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
        0xcc, 0xbb, 0x7f, 0x0a
    ]);

    function getCrypto() {
        if (root.crypto && root.crypto.subtle) {
            return root.crypto;
        }

        if (typeof require === "function") {
            try {
                return require("node:crypto").webcrypto;
            } catch (e) {
                // Fallback for older Node versions
                return require("crypto").webcrypto;
            }
        }

        throw new Error("WebCrypto API is not available in this environment.");
    }

    // HKDF-Extract as per RFC 5869
    async function hkdfExtract(salt, ikm) {
        var crypto = getCrypto();
        var key = await crypto.subtle.importKey(
            "raw",
            ikm,
            { name: "HMAC", hash: "SHA-256" },
            false,
            ["sign"]
        );

        var prk = await crypto.subtle.sign("HMAC", key, salt);
        return new Uint8Array(prk);
    }

    // HKDF-Expand-Label as per RFC 8446 (TLS 1.3) Section 7.1
    async function hkdfExpandLabel(secret, label, context, length) {
        var hkdfLabel = buildHkdfLabel(length, label, context);
        return await hkdfExpand(secret, hkdfLabel, length);
    }

    function buildHkdfLabel(length, label, context) {
        var labelBytes = encodeText("tls13 " + label);
        var hkdfLabel = new Uint8Array(2 + 1 + labelBytes.length + 1 + context.length);
        var offset = 0;

        // Length (2 bytes)
        hkdfLabel[offset++] = (length >>> 8) & 0xFF;
        hkdfLabel[offset++] = length & 0xFF;

        // Label length + label
        hkdfLabel[offset++] = labelBytes.length;
        hkdfLabel.set(labelBytes, offset);
        offset += labelBytes.length;

        // Context length + context
        hkdfLabel[offset++] = context.length;
        if (context.length > 0) {
            hkdfLabel.set(context, offset);
        }

        return hkdfLabel;
    }

    // HKDF-Expand as per RFC 5869
    async function hkdfExpand(prk, info, length) {
        var crypto = getCrypto();
        var key = await crypto.subtle.importKey(
            "raw",
            prk,
            { name: "HMAC", hash: "SHA-256" },
            false,
            ["sign"]
        );

        var output = new Uint8Array(length);
        var t = new Uint8Array(0);
        var offset = 0;
        var counter = 1;

        while (offset < length) {
            var data = new Uint8Array(t.length + info.length + 1);
            data.set(t, 0);
            data.set(info, t.length);
            data[t.length + info.length] = counter;

            t = new Uint8Array(await crypto.subtle.sign("HMAC", key, data));

            var copyLength = Math.min(t.length, length - offset);
            output.set(t.subarray(0, copyLength), offset);
            offset += copyLength;
            counter++;
        }

        return output;
    }

    // Derive QUIC Initial secrets from Destination Connection ID
    async function deriveInitialSecrets(dcid) {
        // HKDF-Extract with QUIC v1 salt and DCID
        var initialSecret = await hkdfExtract(QUIC_V1_INITIAL_SALT, dcid);

        // Derive client and server initial secrets
        var clientInitialSecret = await hkdfExpandLabel(
            initialSecret,
            "client in",
            new Uint8Array(0),
            32
        );

        var serverInitialSecret = await hkdfExpandLabel(
            initialSecret,
            "server in",
            new Uint8Array(0),
            32
        );

        return {
            client: clientInitialSecret,
            server: serverInitialSecret
        };
    }

    // Derive packet protection keys from secret
    async function derivePacketProtectionKeys(secret) {
        var key = await hkdfExpandLabel(secret, "quic key", new Uint8Array(0), 16); // AES-128
        var iv = await hkdfExpandLabel(secret, "quic iv", new Uint8Array(0), 12);   // 12 bytes for GCM
        var hp = await hkdfExpandLabel(secret, "quic hp", new Uint8Array(0), 16);   // Header protection

        return { key: key, iv: iv, hp: hp };
    }

    // AES-128-GCM encryption for QUIC payload
    async function aesGcmEncrypt(key, nonce, plaintext, additionalData) {
        var crypto = getCrypto();
        var cryptoKey = await crypto.subtle.importKey(
            "raw",
            key,
            { name: "AES-GCM" },
            false,
            ["encrypt"]
        );

        var ciphertext = await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: nonce,
                additionalData: additionalData,
                tagLength: 128 // 16 bytes
            },
            cryptoKey,
            plaintext
        );

        return new Uint8Array(ciphertext);
    }

    // AES-ECB for header protection (used in QUIC)
    async function aesEcbEncrypt(key, plaintext) {
        var crypto = getCrypto();
        
        // WebCrypto doesn't support ECB directly, so we use CTR with zero counter
        // For header protection, we only need one block
        var cryptoKey = await crypto.subtle.importKey(
            "raw",
            key,
            { name: "AES-CTR" },
            false,
            ["encrypt"]
        );

        // Use a zero counter for ECB-like behavior on a single block
        var counter = new Uint8Array(16);
        var ciphertext = await crypto.subtle.encrypt(
            {
                name: "AES-CTR",
                counter: counter,
                length: 128
            },
            cryptoKey,
            plaintext
        );

        return new Uint8Array(ciphertext).subarray(0, 16);
    }

    // Apply QUIC header protection
    async function applyHeaderProtection(headerProtectionKey, sample, firstByte, packetNumber) {
        // Encrypt the sample to get the mask
        var mask = await aesEcbEncrypt(headerProtectionKey, sample);

        // Apply mask to first byte (only lower 4 bits for long header)
        var protectedFirstByte = firstByte ^ (mask[0] & 0x0F);

        // Apply mask to packet number bytes
        var pnLength = packetNumber.length;
        var protectedPn = new Uint8Array(pnLength);
        for (var i = 0; i < pnLength; i++) {
            protectedPn[i] = packetNumber[i] ^ mask[i + 1];
        }

        return {
            firstByte: protectedFirstByte,
            packetNumber: protectedPn
        };
    }

    // Construct nonce for AEAD from IV and packet number
    function constructNonce(iv, packetNumber) {
        var nonce = new Uint8Array(iv);
        var pnLength = packetNumber.length;
        
        // XOR packet number into the end of the IV
        for (var i = 0; i < pnLength; i++) {
            nonce[nonce.length - pnLength + i] ^= packetNumber[i];
        }
        
        return nonce;
    }

    // Encrypt QUIC Initial packet payload
    async function encryptQuicInitialPayload(dcid, packetNumber, payload) {
        // Derive initial secrets
        var secrets = await deriveInitialSecrets(dcid);
        var keys = await derivePacketProtectionKeys(secrets.client);

        // Construct nonce
        var nonce = constructNonce(keys.iv, packetNumber);

        // The authenticated additional data (AAD) is the QUIC header
        // For simplicity in this implementation, we'll use a minimal AAD
        // In a full implementation, this would be the complete unprotected header
        var aad = new Uint8Array(0);

        // Encrypt the payload
        var ciphertext = await aesGcmEncrypt(keys.key, nonce, payload, aad);

        return {
            ciphertext: ciphertext,
            keys: keys
        };
    }

    // Full QUIC Initial packet encryption with header protection
    async function encryptQuicInitialPacket(dcid, scid, packetNumber, payload) {
        // Derive initial secrets and keys
        var secrets = await deriveInitialSecrets(dcid);
        var keys = await derivePacketProtectionKeys(secrets.client);

        // Construct nonce
        var nonce = constructNonce(keys.iv, packetNumber);

        // Build the unprotected header (simplified - without length field for now)
        var header = new Uint8Array(1 + 4 + 1 + dcid.length + 1 + scid.length);
        var offset = 0;
        
        // First byte: Long header, Initial packet (0xC0 | 0x00)
        header[offset++] = 0xC0;
        
        // Version (4 bytes) - QUIC v1
        header[offset++] = 0x00;
        header[offset++] = 0x00;
        header[offset++] = 0x00;
        header[offset++] = 0x01;
        
        // DCID length + DCID
        header[offset++] = dcid.length;
        header.set(dcid, offset);
        offset += dcid.length;
        
        // SCID length + SCID
        header[offset++] = scid.length;
        header.set(scid, offset);

        // Encrypt payload with header as AAD
        var ciphertext = await aesGcmEncrypt(keys.key, nonce, payload, header);

        // For header protection, we need a sample from the ciphertext
        // Sample starts 4 bytes into the packet number field
        if (ciphertext.length < 16) {
            // Not enough data for header protection, return without it
            return {
                header: header,
                packetNumber: packetNumber,
                ciphertext: ciphertext
            };
        }

        var sample = ciphertext.subarray(0, 16);
        var headerProtection = await applyHeaderProtection(keys.hp, sample, header[0], packetNumber);

        return {
            header: header,
            protectedFirstByte: headerProtection.firstByte,
            protectedPacketNumber: headerProtection.packetNumber,
            ciphertext: ciphertext,
            keys: keys
        };
    }

    function encodeText(value) {
        if (typeof TextEncoder !== "undefined") {
            return new TextEncoder().encode(String(value));
        }

        if (typeof require === "function") {
            return new (require("node:util").TextEncoder)().encode(String(value));
        }

        throw new Error("TextEncoder is not available in this environment.");
    }

    return {
        deriveInitialSecrets: deriveInitialSecrets,
        derivePacketProtectionKeys: derivePacketProtectionKeys,
        encryptQuicInitialPayload: encryptQuicInitialPayload,
        encryptQuicInitialPacket: encryptQuicInitialPacket,
        aesGcmEncrypt: aesGcmEncrypt,
        hkdfExtract: hkdfExtract,
        hkdfExpandLabel: hkdfExpandLabel,
        constructNonce: constructNonce,
        applyHeaderProtection: applyHeaderProtection
    };
}));
