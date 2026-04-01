(function (root, factory) {
    var data = root.PayloadGenData || (typeof require === "function" ? require("./data.js") : null);
    var crypto = root.PayloadGenCrypto || (typeof require === "function" ? require("./crypto.js") : null);
    var api = factory(root, data, crypto);

    if (typeof module !== "undefined" && module.exports) {
        module.exports = api;
    }

    if (typeof window !== "undefined") {
        window.PayloadGenGenerators = api;
    }
}(typeof globalThis !== "undefined" ? globalThis : this, function (root, Data, Crypto) {
    "use strict";

    if (!Data) {
        throw new Error("PayloadGenData is required before PayloadGenGenerators.");
    }

    var CONFIG = Data.CONFIG;
    var BROWSER_PROFILES = Data.BROWSER_PROFILES;
    var BROWSER_USER_AGENTS = Data.BROWSER_USER_AGENTS;
    var CURL_USER_AGENTS = Data.CURL_USER_AGENTS;
    var SSDP_SEARCH_TARGETS = Data.SSDP_SEARCH_TARGETS;
    var LATEST_QUIC_VERSION = Data.LATEST_QUIC_VERSION;
    var textEncoder = createTextEncoder();
    var hasCrypto = !!Crypto;

    function generatePayload(protocolId, options) {
        var generator = PROTOCOL_GENERATORS[protocolId];

        if (!generator) {
            throw new Error("Unknown protocol.");
        }

        return generator(options || {});
    }

    async function generatePayloadAsync(protocolId, options) {
        var generator = PROTOCOL_GENERATORS_ASYNC[protocolId] || PROTOCOL_GENERATORS[protocolId];

        if (!generator) {
            throw new Error("Unknown protocol.");
        }

        return await generator(options || {});
    }

    function generateDnsPayload(options) {
        return buildDnsQuestionPayload(randomIntExclusive(65535), 0x0100, encodeDnsName(options.host), 0x0001, 0x0001);
    }

    function generateMdnsPayload(options) {
        var queryClass = randomIntExclusive(2) === 0 ? 0x0001 : 0x8001;
        var randomizedHost = randomizeAsciiCase(options.host);
        return buildDnsQuestionPayload(0x0000, 0x0000, encodeDnsName(randomizedHost), 0x0001, queryClass);
    }

    function generateLlmnrPayload(options) {
        return buildDnsQuestionPayload(randomIntExclusive(65535), 0x0000, encodeDnsName(options.host), 0x0001, 0x0001);
    }

    function generateNbnsPayload(options) {
        return buildDnsQuestionPayload(randomIntExclusive(65535), 0x0000, encodeNbnsName(options.host), 0x0020, 0x0001);
    }

    function buildDnsQuestionPayload(id, flags, nameBytes, typeValue, classValue) {
        return concatBytes(
            u16(id),
            u16(flags),
            u16(1),
            u16(0),
            u16(0),
            u16(0),
            nameBytes,
            u16(typeValue),
            u16(classValue)
        );
    }

    function generateSsdpPayload() {
        var mx = 1 + randomIntExclusive(5);
        var searchTarget = randomItem(SSDP_SEARCH_TARGETS);
        var agentSuffix = bytesToHex(randomBytes(2));
        var ssdpMessage = "M-SEARCH * HTTP/1.1\r\n" +
            "Host: 239.255.255.250:1900\r\n" +
            "Man: \"ssdp:discover\"\r\n" +
            "ST: " + searchTarget + "\r\n" +
            "MX: " + mx + "\r\n" +
            "User-Agent: PayloadGen/" + agentSuffix + "\r\n\r\n";

        return encodeText(ssdpMessage);
    }

    // Synchronous QUIC payload (backward compatible, uses random masking)
    function generateQuicPayload(options) {
        var version = { value: "latest", wireValue: LATEST_QUIC_VERSION };
        var dcid = randomBytes(8);
        var scid = randomBytes(8);
        var packetNumber = randomBytes(4);
        var clientHello = buildClientHelloBody(options.host, {
            legacyVersion: 0x0303,
            withTls13: true,
            alpnProtocol: "h3"
        });
        var cryptoBody = options.quicEncrypt ? maskQuicCryptoBody(clientHello) : clientHello;
        var cryptoFrame = concatBytes(
            Uint8Array.from([0x06]),
            encodeQuicVarInt(0),
            encodeQuicVarInt(cryptoBody.length),
            cryptoBody
        );
        var packetLength = packetNumber.length + cryptoFrame.length;

        return concatBytes(
            Uint8Array.from([0xD3]),
            u32(version.wireValue),
            Uint8Array.from([dcid.length]),
            dcid,
            Uint8Array.from([scid.length]),
            scid,
            encodeQuicVarInt(0),
            encodeQuicVarInt(packetLength),
            packetNumber,
            cryptoFrame
        );
    }

    // Async QUIC payload with proper RFC 9001 encryption
    async function generateQuicPayloadAsync(options) {
        if (!hasCrypto) {
            // Fallback to sync version if crypto module not available
            return generateQuicPayload(options);
        }

        var version = { value: "latest", wireValue: LATEST_QUIC_VERSION };
        var dcid = randomBytes(8);
        var scid = randomBytes(8);
        
        // RFC 9001: Packet number should be derived properly, but for Initial we can use random
        // In real implementation, PKN starts from 0 or random value
        var packetNumber = randomBytes(4);
        
        var clientHello = buildClientHelloBody(options.host, {
            legacyVersion: 0x0303,
            withTls13: true,
            alpnProtocol: "h3"
        });

        if (!options.quicEncrypt) {
            // No encryption requested, use plaintext
            var cryptoFrame = concatBytes(
                Uint8Array.from([0x06]),
                encodeQuicVarInt(0),
                encodeQuicVarInt(clientHello.length),
                clientHello
            );
            var packetLength = packetNumber.length + cryptoFrame.length;

            return concatBytes(
                Uint8Array.from([0xD3]),
                u32(version.wireValue),
                Uint8Array.from([dcid.length]),
                dcid,
                Uint8Array.from([scid.length]),
                scid,
                encodeQuicVarInt(0),
                encodeQuicVarInt(packetLength),
                packetNumber,
                cryptoFrame
            );
        }

        // RFC 9001: Proper QUIC Initial packet encryption sequence:
        // 1. Derive keys from well-known salt and DCID
        // 2. Build payload (CRYPTO frame) and add padding BEFORE encryption
        // 3. XOR IV with PKN to create nonce
        // 4. Encrypt payload with AAD (unprotected header)
        // 5. Take sample from encrypted payload and derive header protection mask
        // 6. XOR first byte lower bits and PKN with the mask
        try {
            // Step 1: Derive initial secrets and keys from DCID
            var secrets = await Crypto.deriveInitialSecrets(dcid);
            var keys = await Crypto.derivePacketProtectionKeys(secrets.client);
            
            // Step 2: Build CRYPTO frame with ClientHello
            var cryptoFrame = concatBytes(
                Uint8Array.from([0x06]),  // Frame type: CRYPTO
                encodeQuicVarInt(0),       // Offset: 0
                encodeQuicVarInt(clientHello.length),
                clientHello
            );

            // Step 2a: Add padding to reach MTU BEFORE encryption (RFC 9001 Section 14.1)
            // Initial packets should be at least 1200 bytes to avoid amplification attacks
            var headerSize = 1 + 4 + 1 + dcid.length + 1 + scid.length + 1 + 2 + packetNumber.length + 16; // +16 for GCM tag
            var targetSize = 1200;
            var currentPayloadSize = cryptoFrame.length;
            var paddingNeeded = Math.max(0, targetSize - headerSize - currentPayloadSize);
            
            var payload;
            if (paddingNeeded > 0) {
                // Add PADDING frame (0x00 bytes)
                var paddingFrame = new Uint8Array(paddingNeeded);
                payload = concatBytes(cryptoFrame, paddingFrame);
            } else {
                payload = cryptoFrame;
            }

            // Step 3: Construct nonce by XORing IV with packet number
            var nonce = Crypto.constructNonce(keys.iv, packetNumber);

            // Build unprotected header for AAD (Additional Authenticated Data)
            var headerForAad = concatBytes(
                Uint8Array.from([0xC3]), // Long header, Initial, 4-byte PN (0xC0 | 0x03)
                u32(version.wireValue),
                Uint8Array.from([dcid.length]),
                dcid,
                Uint8Array.from([scid.length]),
                scid,
                encodeQuicVarInt(0) // Token length (0 for client Initial)
            );

            // Step 4: Encrypt the payload with AES-128-GCM
            var encrypted = await Crypto.aesGcmEncrypt(keys.key, nonce, payload, headerForAad);

            // Calculate packet length (PN + encrypted payload with GCM tag)
            var packetLength = packetNumber.length + encrypted.length;

            // Step 5 & 6: Apply header protection
            if (encrypted.length >= 20) {
                // Sample is 16 bytes starting 4 bytes after the start of packet number
                // Since we haven't added PN yet, sample starts at byte 4 of encrypted data
                var sample = encrypted.subarray(4, 20);
                var headerProtection = await Crypto.applyHeaderProtection(keys.hp, sample, 0xC3, packetNumber);

                return concatBytes(
                    Uint8Array.from([headerProtection.firstByte]),
                    u32(version.wireValue),
                    Uint8Array.from([dcid.length]),
                    dcid,
                    Uint8Array.from([scid.length]),
                    scid,
                    encodeQuicVarInt(0),
                    encodeQuicVarInt(packetLength),
                    headerProtection.packetNumber,
                    encrypted
                );
            } else {
                // Not enough data for header protection, return without it
                return concatBytes(
                    Uint8Array.from([0xC3]),
                    u32(version.wireValue),
                    Uint8Array.from([dcid.length]),
                    dcid,
                    Uint8Array.from([scid.length]),
                    scid,
                    encodeQuicVarInt(0),
                    encodeQuicVarInt(packetLength),
                    packetNumber,
                    encrypted
                );
            }
        } catch (error) {
            console.warn("QUIC encryption failed, falling back to masking:", error);
            // Fallback to random masking if encryption fails
            return generateQuicPayload(options);
        }
    }

    function generateTlsClientHelloPayload(options) {
        var handshake = buildClientHelloBody(options.host, {
            legacyVersion: 0x0303,
            withTls13: true,
            alpnProtocol: options.tlsAlpn
        });

        return concatBytes(
            Uint8Array.from([0x16]),
            u16(0x0301),
            u16(handshake.length),
            handshake
        );
    }

    function generateHttp2Payload() {
        var availableSettings = [
            { id: 0x0001, values: [4096, 8192, 16384] },
            { id: 0x0003, values: [100, 250, 1000] },
            { id: 0x0004, values: [65535, 98304, 131072] },
            { id: 0x0005, values: [16384, 32768] },
            { id: 0x0006, values: [65536, 262144, 1048576] }
        ];
        var selectedCount = 2 + randomIntExclusive(availableSettings.length - 1);
        var selected = shuffleItems(availableSettings).slice(0, selectedCount);
        var settingsBytes = concatBytes.apply(null, selected.map(function (setting) {
            return concatBytes(
                u16(setting.id),
                u32(randomItem(setting.values))
            );
        }));

        return concatBytes(
            encodeText("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
            u24(settingsBytes.length),
            Uint8Array.from([0x04, 0x00]),
            u32(0),
            settingsBytes
        );
    }

    function generateHttpBrowserPayload(options) {
        var target = withRandomQuery(options.path, options.randomQuery);
        var browserMessage = "GET " + target + " HTTP/1.1\r\n" +
            "Host: " + options.host + "\r\n" +
            "User-Agent: " + randomItem(BROWSER_USER_AGENTS) + "\r\n" +
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n" +
            "Accept-Language: en-US,en;q=0.9\r\n" +
            "Connection: keep-alive\r\n" +
            "Upgrade-Insecure-Requests: 1\r\n" +
            "Sec-Fetch-Site: none\r\n" +
            "Sec-Fetch-Mode: navigate\r\n" +
            "Sec-Fetch-Dest: document\r\n\r\n";

        return encodeText(browserMessage);
    }

    function generateWebsocketPayload(options) {
        var websocketMessage = "GET " + options.path + " HTTP/1.1\r\n" +
            "Host: " + options.host + "\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            "Sec-WebSocket-Key: " + base64EncodeBytes(randomBytes(16)) + "\r\n" +
            "Sec-WebSocket-Version: 13\r\n" +
            "Origin: https://" + options.host + "\r\n\r\n";

        return encodeText(websocketMessage);
    }

    function generateCurlPayload(options) {
        var target = withRandomQuery(options.path, options.randomQuery);
        var lines = [
            options.httpMethod + " " + target + " HTTP/1.1",
            "Host: " + options.host,
            "User-Agent: " + randomItem(CURL_USER_AGENTS),
            "Accept: */*",
            "Connection: close"
        ];

        if (options.httpMethod === "POST") {
            lines.push("Content-Length: 0");
        }

        return encodeText(lines.join("\r\n") + "\r\n\r\n");
    }

    function generateStunPayload(options) {
        var hostBytes = encodeText(options.host);
        var padding = (4 - (hostBytes.length % 4)) % 4;
        var attrValue = concatBytes(hostBytes, zeroBytes(padding));
        var attr = concatBytes(
            u16(0x8022),
            u16(hostBytes.length),
            attrValue
        );

        return concatBytes(
            u16(0x0001),
            u16(attr.length),
            u32(0x2112A442),
            randomBytes(12),
            attr
        );
    }

    function generateDtlsPayload(options) {
        var clientHelloBody = buildDtlsClientHelloBody(options.host);
        var handshake = concatBytes(
            Uint8Array.from([0x01]),
            u24(clientHelloBody.length),
            u16(0),
            u24(0),
            u24(clientHelloBody.length),
            clientHelloBody
        );

        return concatBytes(
            Uint8Array.from([0x16, 0xFE, 0xFD]),
            u16(0),
            randomBytes(6),
            u16(handshake.length),
            handshake
        );
    }

    function generateSipPayload(options) {
        var action = options.sipAction;
        var branch = randomInt31();
        var tag = randomInt31();
        var callId = randomInt31();
        var sipMessage = action + " sip:" + options.host + " SIP/2.0\r\n" +
            "Via: SIP/2.0/UDP " + options.host + ":5060;branch=z9hG4bK-" + branch + "\r\n" +
            "Max-Forwards: 70\r\n" +
            "From: <sip:user@" + options.host + ">;tag=" + tag + "\r\n" +
            "To: <sip:user@" + options.host + ">\r\n" +
            "Call-ID: " + callId + "@" + options.host + "\r\n" +
            "CSeq: 1 " + action + "\r\n" +
            "User-Agent: PayloadGen\r\n" +
            "Content-Length: 0\r\n\r\n";

        return encodeText(sipMessage);
    }

    function generateRtpPayload() {
        return concatBytes(
            Uint8Array.from([0x80, 0x60]),
            u16(randomIntExclusive(65535)),
            u32(randomUint32()),
            u32(randomUint32())
        );
    }

    function generateRtcpPayload() {
        return concatBytes(
            Uint8Array.from([0x80, 0xC9]),
            u16(0x0001),
            u32(randomUint32())
        );
    }

    function generateCoapPayload(options) {
        var token = randomBytes(4);
        var messageId = randomIntExclusive(65535);
        var code = options.coapMethod === "POST" ? 0x02 : 0x01;

        return concatBytes(
            Uint8Array.from([0x44, code]),
            u16(messageId),
            token,
            buildCoapOptions(options.host, options.path)
        );
    }

    function generateMqttPayload(options) {
        var clientId = String(options.clientId || "").trim() || ("payloadgen-" + bytesToHex(randomBytes(2)));
        var variableHeader = concatBytes(
            encodeLengthPrefixedText("MQTT"),
            Uint8Array.from([0x04, 0x02]),
            u16(60)
        );
        var payload = encodeLengthPrefixedText(clientId);

        return concatBytes(
            Uint8Array.from([0x10]),
            encodeMqttRemainingLength(variableHeader.length + payload.length),
            variableHeader,
            payload
        );
    }

    function generateNtpPayload() {
        var payload = zeroBytes(48);
        payload[0] = 0x23;
        payload.set(randomBytes(8), 40);
        return payload;
    }

    function generateDhcpDiscoverPayload() {
        var xid = randomBytes(4);
        var mac = randomMacAddress();
        var chaddr = concatBytes(mac, zeroBytes(10));
        var bootp = concatBytes(
            Uint8Array.from([0x01, 0x01, 0x06, 0x00]),
            xid,
            u16(0),
            u16(0x8000),
            zeroBytes(4),
            zeroBytes(4),
            zeroBytes(4),
            zeroBytes(4),
            chaddr,
            zeroBytes(64),
            zeroBytes(128)
        );
        var options = concatBytes(
            Uint8Array.from([0x35, 0x01, 0x01]),
            Uint8Array.from([0x37, 0x06, 0x01, 0x03, 0x06, 0x0F, 0x33, 0x36]),
            Uint8Array.from([0x3D, 0x07, 0x01]),
            mac,
            Uint8Array.from([0xFF])
        );

        return concatBytes(bootp, u32(0x63825363), options);
    }

    function generateSnmpPayload(options) {
        var requestId = randomInt31();
        var pdu = berTlv(0xA0, concatBytes(
            berInteger(requestId),
            berInteger(0),
            berInteger(0),
            berSequence([
                berSequence([
                    berOid(options.oid),
                    berNull()
                ])
            ])
        ));

        return berSequence([
            berInteger(0),
            berOctetString(encodeText(options.community)),
            pdu
        ]);
    }

    function generateSyslogPayload(options) {
        var facilityCode = getSyslogFacilityCode(options.syslogFacility);
        var severityCode = getSyslogSeverityCode(options.syslogSeverity);
        var pri = facilityCode * 8 + severityCode;
        return encodeText("<" + pri + ">" + formatSyslogTimestamp(new Date()) + " payloadgen payloadgen: " + options.message);
    }

    function generateTftpPayload(options) {
        var optionBytes = buildTftpOptionBytes();

        return concatBytes(
            u16(0x0001),
            encodeZeroTerminatedText(options.filename),
            encodeZeroTerminatedText("octet"),
            optionBytes
        );
    }

    function generateRadiusPayload(options) {
        var usernameBytes = encodeText(options.username || "user");
        var attributes = concatBytes(
            Uint8Array.from([0x01, usernameBytes.length + 2]),
            usernameBytes,
            Uint8Array.from([0x20, 0x0C]),
            encodeText("payloadgen")
        );

        return concatBytes(
            Uint8Array.from([0x01, randomIntExclusive(255)]),
            u16(20 + attributes.length),
            randomBytes(16),
            attributes
        );
    }

    function generateRedisPayload() {
        var token = "payloadgen-" + bytesToHex(randomBytes(3));

        if (randomIntExclusive(2) === 0) {
            return encodeText("*2\r\n$4\r\nPING\r\n$" + token.length + "\r\n" + token + "\r\n");
        }

        return encodeText("*2\r\n$4\r\nECHO\r\n$" + token.length + "\r\n" + token + "\r\n");
    }

    function generatePostgresqlPayload(options) {
        var applicationName = "payloadgen-" + bytesToHex(randomBytes(3));
        var body = concatBytes(
            u32(196608),
            encodeText("user"),
            Uint8Array.from([0x00]),
            encodeText(options.username),
            Uint8Array.from([0x00]),
            encodeText("database"),
            Uint8Array.from([0x00]),
            encodeText(options.database),
            Uint8Array.from([0x00]),
            encodeText("application_name"),
            Uint8Array.from([0x00]),
            encodeText(applicationName),
            Uint8Array.from([0x00, 0x00])
        );

        return concatBytes(u32(body.length + 4), body);
    }

    function generateMysqlPayload(options) {
        var usernameBytes = encodeText(options.username || "root");
        var maxPacket = 0x00100000 + randomIntExclusive(0x00100000);
        var collation = randomItem([0x08, 0x21, 0x2D]);
        var payload = concatBytes(
            u32le(0x0000A205),
            u32le(maxPacket),
            Uint8Array.from([collation]),
            zeroBytes(23),
            usernameBytes,
            Uint8Array.from([0x00, 0x00])
        );

        return concatBytes(
            u24le(payload.length),
            Uint8Array.from([0x01]),
            payload
        );
    }

    function generateUtpPayload() {
        return concatBytes(
            Uint8Array.from([0x41, 0x00]),
            u16(randomIntExclusive(65535)),
            u32(nowMicros32()),
            u32(0),
            u32(0),
            u16(0),
            u16(0)
        );
    }

    function generateBittorrentDhtPayload() {
        return concatBytes(
            encodeText("d1:ad2:id20:"),
            randomBytes(20),
            encodeText("e1:q4:ping1:t2:"),
            randomBytes(2),
            encodeText("1:y1:qe")
        );
    }

    function maskQuicCryptoBody(bytes) {
        return randomBytes(bytes.length);
    }

    function buildClientHelloBody(host, options) {
        var sessionId = randomBytes(32);
        var extensions = buildTlsExtensions(host, !!options.withTls13, options.alpnProtocol);
        
        // Expanded cipher suites to match real browsers (15 suites like Chrome)
        var cipherSuites = concatBytes(
            // TLS 1.3 cipher suites (required)
            u16(0x1301),  // TLS_AES_128_GCM_SHA256
            u16(0x1302),  // TLS_AES_256_GCM_SHA384
            u16(0x1303),  // TLS_CHACHA20_POLY1305_SHA256
            
            // ECDHE with ECDSA (common in modern browsers)
            u16(0xC02B),  // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            u16(0xC02C),  // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            u16(0xCCA9),  // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            
            // ECDHE with RSA (widely supported)
            u16(0xC02F),  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            u16(0xC030),  // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            u16(0xCCA8),  // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            
            // Legacy ECDHE (for compatibility)
            u16(0xC013),  // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            u16(0xC014),  // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
            
            // RSA (legacy but still common)
            u16(0x009C),  // TLS_RSA_WITH_AES_128_GCM_SHA256
            u16(0x009D),  // TLS_RSA_WITH_AES_256_GCM_SHA384
            u16(0x002F),  // TLS_RSA_WITH_AES_128_CBC_SHA
            u16(0x0035)   // TLS_RSA_WITH_AES_256_CBC_SHA
        );
        
        var body = concatBytes(
            u16(options.legacyVersion),
            randomBytes(32),
            Uint8Array.from([sessionId.length]),
            sessionId,
            u16(cipherSuites.length),
            cipherSuites,
            Uint8Array.from([0x01, 0x00]),
            u16(extensions.length),
            extensions
        );

        return concatBytes(
            Uint8Array.from([0x01]),
            u24(body.length),
            body
        );
    }

    function buildDtlsClientHelloBody(host) {
        var sessionId = randomBytes(32);
        var extensions = concatBytes(
            buildServerNameExtension(host),
            buildSupportedGroupsExtension(),
            buildEcPointFormatsExtension(),
            buildSignatureAlgorithmsExtension()
        );
        var cipherSuites = concatBytes(
            u16(0xC02B),
            u16(0xC02F),
            u16(0x009C),
            u16(0x009D)
        );

        return concatBytes(
            Uint8Array.from([0xFE, 0xFD]),
            randomBytes(32),
            Uint8Array.from([sessionId.length]),
            sessionId,
            Uint8Array.from([0x00]),
            u16(cipherSuites.length),
            cipherSuites,
            Uint8Array.from([0x01, 0x00]),
            u16(extensions.length),
            extensions
        );
    }

    function buildTlsExtensions(host, withTls13, alpnProtocol) {
        // Extension order matters for fingerprinting!
        // This order mimics Chrome/modern browsers
        var parts = [
            buildServerNameExtension(host),                    // 0 - server_name
            buildExtendedMasterSecretExtension(),              // 23 - extended_master_secret
            buildRenegotiationInfoExtension(),                 // 65281 - renegotiation_info
            buildSupportedGroupsExtension(),                   // 10 - supported_groups
            buildEcPointFormatsExtension(),                    // 11 - ec_point_formats
            buildSessionTicketExtension(),                     // 35 - session_ticket
            buildStatusRequestExtension(),                     // 5 - status_request (OCSP)
            buildSignatureAlgorithmsExtension(),               // 13 - signature_algorithms
            buildSignedCertificateTimestampExtension(),        // 18 - signed_certificate_timestamp
            buildKeyShareExtension(),                          // 51 - key_share
            buildPskModesExtension()                           // 45 - psk_key_exchange_modes
        ];

        // Insert ALPN if specified (position 6, after session_ticket)
        if (alpnProtocol) {
            parts.splice(6, 0, buildAlpnExtension(alpnProtocol));  // 16 - application_layer_protocol_negotiation
        }

        // Add TLS 1.3 specific extensions
        if (withTls13) {
            // Insert supported_versions before key_share
            var keyShareIndex = parts.length - 2;
            parts.splice(keyShareIndex, 0, buildSupportedVersionsExtension());  // 43 - supported_versions
            
            // Add compress_certificate after psk_modes
            parts.push(buildCompressCertificateExtension());   // 27 - compress_certificate
        }

        // Calculate total length for padding
        var currentLength = 0;
        parts.forEach(function(part) {
            currentLength += part.length;
        });

        // Add padding to reach typical ClientHello size (512+ bytes)
        // Chrome typically pads to avoid fingerprinting based on size
        var targetSize = 512;
        var headerSize = 4 + 2 + 32 + 1 + 32 + 2 + 30 + 2 + 2; // Approximate header size
        var paddingNeeded = Math.max(0, targetSize - headerSize - currentLength - 4);
        
        if (paddingNeeded > 0) {
            parts.push(buildPaddingExtension(paddingNeeded));  // 21 - padding
        }

        return concatBytes.apply(null, parts);
    }

    function buildServerNameExtension(host) {
        var hostBytes = encodeText(host);
        var serverName = concatBytes(Uint8Array.from([0x00]), u16(hostBytes.length), hostBytes);
        var data = concatBytes(u16(serverName.length), serverName);
        return concatBytes(u16(0x0000), u16(data.length), data);
    }

    function buildAlpnExtension(protocol) {
        var protocolBytes = encodeText(protocol);
        var entry = concatBytes(Uint8Array.from([protocolBytes.length]), protocolBytes);
        var data = concatBytes(u16(entry.length), entry);
        return concatBytes(u16(0x0010), u16(data.length), data);
    }

    function buildSupportedVersionsExtension() {
        return concatBytes(u16(0x002B), u16(5), Uint8Array.from([0x04, 0x03, 0x04, 0x03, 0x03]));
    }

    function buildSupportedGroupsExtension() {
        // Expanded to match Chrome/Firefox (4 curves)
        var groups = concatBytes(
            u16(0x001D),  // x25519 (most preferred)
            u16(0x0017),  // secp256r1 (P-256)
            u16(0x0018),  // secp384r1 (P-384)
            u16(0x0019)   // secp521r1 (P-521)
        );
        return concatBytes(u16(0x000A), u16(groups.length + 2), u16(groups.length), groups);
    }

    function buildSignatureAlgorithmsExtension() {
        // Expanded to match Chrome (8 algorithms)
        var algorithms = concatBytes(
            u16(0x0403),  // ecdsa_secp256r1_sha256
            u16(0x0804),  // rsa_pss_rsae_sha256
            u16(0x0401),  // rsa_pkcs1_sha256
            u16(0x0503),  // ecdsa_secp384r1_sha384
            u16(0x0805),  // rsa_pss_rsae_sha384
            u16(0x0501),  // rsa_pkcs1_sha384
            u16(0x0806),  // rsa_pss_rsae_sha512
            u16(0x0601)   // rsa_pkcs1_sha512
        );
        return concatBytes(u16(0x000D), u16(algorithms.length + 2), u16(algorithms.length), algorithms);
    }

    function buildEcPointFormatsExtension() {
        return concatBytes(u16(0x000B), u16(2), Uint8Array.from([0x01, 0x00]));
    }

    function buildPskModesExtension() {
        return concatBytes(u16(0x002D), u16(2), Uint8Array.from([0x01, 0x01]));
    }

    function buildKeyShareExtension() {
        var keyBytes = randomBytes(32);
        var entry = concatBytes(u16(0x001D), u16(keyBytes.length), keyBytes);
        return concatBytes(u16(0x0033), u16(entry.length + 2), u16(entry.length), entry);
    }

    // Additional extensions for better browser mimicry
    function buildExtendedMasterSecretExtension() {
        // Extension 23 - Extended Master Secret (RFC 7627)
        return concatBytes(u16(0x0017), u16(0));
    }

    function buildRenegotiationInfoExtension() {
        // Extension 65281 (0xFF01) - Renegotiation Info (RFC 5746)
        return concatBytes(u16(0xFF01), u16(1), Uint8Array.from([0x00]));
    }

    function buildSessionTicketExtension() {
        // Extension 35 - Session Ticket (RFC 5077)
        return concatBytes(u16(0x0023), u16(0));
    }

    function buildStatusRequestExtension() {
        // Extension 5 - Status Request (OCSP stapling)
        var data = concatBytes(
            Uint8Array.from([0x01]),  // status_type: ocsp
            u16(0),                    // responder_id_list length
            u16(0)                     // request_extensions length
        );
        return concatBytes(u16(0x0005), u16(data.length), data);
    }

    function buildSignedCertificateTimestampExtension() {
        // Extension 18 - Signed Certificate Timestamp
        return concatBytes(u16(0x0012), u16(0));
    }

    function buildCompressCertificateExtension() {
        // Extension 27 - Compress Certificate
        var algorithms = concatBytes(
            Uint8Array.from([0x02]),  // length
            u16(0x0002)               // brotli
        );
        return concatBytes(u16(0x001B), u16(algorithms.length), algorithms);
    }

    function buildPaddingExtension(paddingLength) {
        // Extension 21 - Padding
        if (paddingLength <= 0) {
            return new Uint8Array(0);
        }
        var padding = new Uint8Array(paddingLength);
        return concatBytes(u16(0x0015), u16(paddingLength), padding);
    }

    function buildCoapOptions(host, path) {
        var currentOptionNumber = 0;
        var parts = [];

        if (host) {
            parts.push(encodeCoapOption(3 - currentOptionNumber, encodeText(host)));
            currentOptionNumber = 3;
        }

        splitPathSegments(path).forEach(function (segment) {
            parts.push(encodeCoapOption(11 - currentOptionNumber, encodeText(segment)));
            currentOptionNumber = 11;
        });

        return concatBytes.apply(null, parts);
    }

    function encodeCoapOption(delta, valueBytes) {
        var deltaParts = encodeCoapExtended(delta);
        var lengthParts = encodeCoapExtended(valueBytes.length);

        return concatBytes(
            Uint8Array.from([(deltaParts.nibble << 4) | lengthParts.nibble]),
            deltaParts.extBytes,
            lengthParts.extBytes,
            valueBytes
        );
    }

    function encodeCoapExtended(value) {
        if (value < 13) {
            return { nibble: value, extBytes: zeroBytes(0) };
        }

        if (value < 269) {
            return { nibble: 13, extBytes: Uint8Array.from([value - 13]) };
        }

        return { nibble: 14, extBytes: u16(value - 269) };
    }

    function resolveQuicVersion() {
        return { value: "latest", wireValue: LATEST_QUIC_VERSION };
    }

    function normalizeHost(rawValue) {
        var host = String(rawValue || "").trim();
        return host || CONFIG.defaultHost;
    }

    function normalizePath(rawValue) {
        var path = String(rawValue || "").trim();

        if (!path) {
            return "/";
        }

        if (path.charAt(0) !== "/") {
            return "/" + path;
        }

        return path;
    }

    function withRandomQuery(path, enabled) {
        if (!enabled) {
            return path;
        }

        return path + (path.indexOf("?") === -1 ? "?id=" : "&id=") + bytesToHex(randomBytes(4));
    }

    function randomizeAsciiCase(value) {
        return String(value || "").replace(/[a-z]/gi, function (character) {
            if (!/[a-z]/i.test(character) || randomIntExclusive(2) === 0) {
                return character.toLowerCase();
            }

            return character.toUpperCase();
        });
    }

    function splitPathSegments(path) {
        return normalizePath(path).split("/").filter(function (segment) {
            return segment.length > 0;
        });
    }

    function encodeLengthPrefixedText(text) {
        var bytes = encodeText(text);
        return concatBytes(u16(bytes.length), bytes);
    }

    function encodeZeroTerminatedText(text) {
        return concatBytes(encodeText(String(text || "")), Uint8Array.from([0x00]));
    }

    function encodeDnsName(name) {
        var trimmed = normalizeHost(name).replace(/\.+$/, "");
        var labels = trimmed.split(".");
        var bytes = [];

        if (!labels.length) {
            throw new Error("DNS payload requires a valid hostname.");
        }

        labels.forEach(function (label) {
            var labelBytes = encodeText(label);
            var index;

            if (!labelBytes.length || labelBytes.length > 63) {
                throw new Error("Each DNS label must be between 1 and 63 bytes.");
            }

            bytes.push(labelBytes.length);

            for (index = 0; index < labelBytes.length; index += 1) {
                bytes.push(labelBytes[index]);
            }
        });

        bytes.push(0x00);

        if (bytes.length > 255) {
            throw new Error("DNS name is too long to encode.");
        }

        return Uint8Array.from(bytes);
    }

    function encodeNbnsName(host) {
        var label = normalizeHost(host).split(".")[0].toUpperCase().replace(/[^A-Z0-9!@#$%^&()\-_'{}.~]/g, "");
        var sixteenByteName = (label.slice(0, 15) + "               ").slice(0, 15) + "\u0000";
        var bytes = [32];
        var index;

        for (index = 0; index < sixteenByteName.length; index += 1) {
            var code = sixteenByteName.charCodeAt(index);
            bytes.push(0x41 + ((code >> 4) & 0x0F));
            bytes.push(0x41 + (code & 0x0F));
        }

        bytes.push(0x00);
        return Uint8Array.from(bytes);
    }

    function encodeMqttRemainingLength(length) {
        var bytes = [];
        var value = length;

        do {
            var encodedByte = value % 128;
            value = Math.floor(value / 128);

            if (value > 0) {
                encodedByte |= 0x80;
            }

            bytes.push(encodedByte);
        } while (value > 0);

        return Uint8Array.from(bytes);
    }

    function buildTftpOptionBytes() {
        var extensions = [];

        if (randomIntExclusive(2) === 0) {
            extensions.push(["blksize", String(randomItem([512, 1024, 1428, 1468]))]);
        }

        if (randomIntExclusive(2) === 0) {
            extensions.push(["timeout", String(randomItem([3, 5, 8, 10]))]);
        }

        if (extensions.length === 0 || randomIntExclusive(2) === 0) {
            extensions.push(["tsize", "0"]);
        }

        return concatBytes.apply(null, extensions.map(function (pair) {
            return concatBytes(
                encodeZeroTerminatedText(pair[0]),
                encodeZeroTerminatedText(pair[1])
            );
        }));
    }

    function berSequence(children) {
        return berTlv(0x30, concatBytes.apply(null, children));
    }

    function berTlv(tag, valueBytes) {
        return concatBytes(Uint8Array.from([tag]), berLength(valueBytes.length), valueBytes);
    }

    function berLength(length) {
        if (length < 0x80) {
            return Uint8Array.from([length]);
        }

        if (length < 0x100) {
            return Uint8Array.from([0x81, length]);
        }

        return Uint8Array.from([0x82, (length >> 8) & 0xFF, length & 0xFF]);
    }

    function berInteger(value) {
        var bytes = [];
        var working = value >>> 0;

        do {
            bytes.unshift(working & 0xFF);
            working = working >>> 8;
        } while (working > 0);

        if (bytes[0] & 0x80) {
            bytes.unshift(0x00);
        }

        return berTlv(0x02, Uint8Array.from(bytes));
    }

    function berOctetString(bytes) {
        return berTlv(0x04, bytes);
    }

    function berNull() {
        return berTlv(0x05, zeroBytes(0));
    }

    function berOid(oidText) {
        var parts = String(oidText || "").split(".").map(function (part) {
            return parseInt(part, 10);
        });
        var bytes = [];

        if (parts.length < 2 || parts.some(function (part) { return !Number.isFinite(part) || part < 0; })) {
            throw new Error("OID must be a dotted numeric string.");
        }

        bytes.push((parts[0] * 40) + parts[1]);

        parts.slice(2).forEach(function (part) {
            var stack = [part & 0x7F];
            var value = part >>> 7;

            while (value > 0) {
                stack.unshift((value & 0x7F) | 0x80);
                value = value >>> 7;
            }

            Array.prototype.push.apply(bytes, stack);
        });

        return berTlv(0x06, Uint8Array.from(bytes));
    }

    function getSyslogFacilityCode(facility) {
        if (facility === "daemon") {
            return 3;
        }

        if (facility === "local0") {
            return 16;
        }

        return 1;
    }

    function getSyslogSeverityCode(severity) {
        if (severity === "notice") {
            return 5;
        }

        if (severity === "warning") {
            return 4;
        }

        return 6;
    }

    function formatSyslogTimestamp(date) {
        var months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
        var day = date.getDate();

        return months[date.getMonth()] + " " +
            (day < 10 ? " " + day : String(day)) + " " +
            pad2(date.getHours()) + ":" +
            pad2(date.getMinutes()) + ":" +
            pad2(date.getSeconds());
    }

    function pad2(value) {
        return value < 10 ? "0" + value : String(value);
    }

    function randomMacAddress() {
        var mac = randomBytes(6);
        mac[0] = (mac[0] & 0xFE) | 0x02;
        return mac;
    }

    function randomItem(items) {
        return items[randomIntExclusive(items.length)];
    }

    function shuffleItems(items) {
        var copy = items.slice();
        var index;

        for (index = copy.length - 1; index > 0; index -= 1) {
            var swapIndex = randomIntExclusive(index + 1);
            var temp = copy[index];
            copy[index] = copy[swapIndex];
            copy[swapIndex] = temp;
        }

        return copy;
    }

    function createMapById(items) {
        return items.reduce(function (map, item) {
            map[item.id] = item;
            return map;
        }, {});
    }

    function getRequiredElement(id) {
        var element = document.getElementById(id);

        if (!element) {
            throw new Error("PayloadGen failed to initialize because #" + id + " is missing.");
        }

        return element;
    }

    function setElementText(element, text) {
        element.textContent = text;
    }

    function setElementHtml(element, html) {
        element.innerHTML = html;
    }

    function clearElement(element) {
        while (element.firstChild) {
            element.removeChild(element.firstChild);
        }
    }

    function createElement(tagName, options) {
        var element = document.createElement(tagName);
        var key;

        options = options || {};

        for (key in options) {
            if (!Object.prototype.hasOwnProperty.call(options, key) || key === "children") {
                continue;
            }

            if (key in element) {
                element[key] = options[key];
            } else {
                element.setAttribute(key, options[key]);
            }
        }

        if (options.children) {
            options.children.forEach(function (child) {
                element.appendChild(child);
            });
        }

        return element;
    }

    function chunkPayload(payloadBytes, mtu, padMtu) {
        var chunks = [];
        var offset = 0;

        if (payloadBytes.length === 0) {
            if (padMtu) {
                return [new Uint8Array(mtu)];
            }
            return [payloadBytes];
        }

        while (offset < payloadBytes.length) {
            var slice = payloadBytes.slice(offset, Math.min(offset + mtu, payloadBytes.length));
            if (padMtu && slice.length < mtu) {
                var padded = new Uint8Array(mtu);
                padded.set(slice);
                slice = padded;
            }
            chunks.push(slice);
            offset += mtu;
        }

        return chunks;
    }

    function bytesToHex(bytes) {
        var hex = "";
        var index;

        for (index = 0; index < bytes.length; index += 1) {
            var value = bytes[index].toString(16);
            hex += value.length === 1 ? "0" + value : value;
        }

        return hex;
    }

    function encodeText(value) {
        return textEncoder.encode(String(value));
    }

    function createTextEncoder() {
        if (typeof TextEncoder !== "undefined") {
            return new TextEncoder();
        }

        if (typeof require === "function") {
            return new (require("node:util").TextEncoder)();
        }

        throw new Error("TextEncoder is not available in this environment.");
    }

    function base64EncodeBytes(bytes) {
        if (typeof root.btoa === "function") {
            var binary = "";
            var index;

            for (index = 0; index < bytes.length; index += 1) {
                binary += String.fromCharCode(bytes[index]);
            }

            return root.btoa(binary);
        }

        if (typeof Buffer !== "undefined") {
            return Buffer.from(bytes).toString("base64");
        }

        if (typeof require === "function") {
            return require("node:buffer").Buffer.from(bytes).toString("base64");
        }

        throw new Error("Base64 encoding is not available in this environment.");
    }

    function getCrypto() {
        if (root.crypto && typeof root.crypto.getRandomValues === "function") {
            return root.crypto;
        }

        if (typeof require === "function") {
            return require("node:crypto").webcrypto;
        }

        throw new Error("Secure random values are not available in this environment.");
    }

    function randomBytes(length) {
        var bytes = new Uint8Array(length);
        getCrypto().getRandomValues(bytes);
        return bytes;
    }

    function zeroBytes(length) {
        return new Uint8Array(length);
    }

    function randomUint32() {
        var bytes = randomBytes(4);
        return ((bytes[0] * 0x1000000) + (bytes[1] << 16) + (bytes[2] << 8) + bytes[3]) >>> 0;
    }

    function randomIntExclusive(maxExclusive) {
        if (maxExclusive <= 1) {
            return 0;
        }

        return randomUint32() % maxExclusive;
    }

    function randomInt31() {
        return randomUint32() & 0x7FFFFFFF;
    }

    function nowMicros32() {
        var nowMicros;

        if (typeof performance !== "undefined" && typeof performance.now === "function" && typeof performance.timeOrigin === "number") {
            nowMicros = Math.floor((performance.timeOrigin + performance.now()) * 1000);
        } else {
            nowMicros = Date.now() * 1000;
        }

        return nowMicros % 0x100000000;
    }

    function concatBytes() {
        var totalLength = 0;
        var parts = [];
        var partIndex;
        var offset;
        var output;

        for (partIndex = 0; partIndex < arguments.length; partIndex += 1) {
            if (!arguments[partIndex] || !arguments[partIndex].length) {
                continue;
            }

            parts.push(arguments[partIndex]);
            totalLength += arguments[partIndex].length;
        }

        output = new Uint8Array(totalLength);
        offset = 0;

        for (partIndex = 0; partIndex < parts.length; partIndex += 1) {
            output.set(parts[partIndex], offset);
            offset += parts[partIndex].length;
        }

        return output;
    }

    function u16(value) {
        return Uint8Array.from([(value >>> 8) & 0xFF, value & 0xFF]);
    }

    function u24(value) {
        return Uint8Array.from([(value >>> 16) & 0xFF, (value >>> 8) & 0xFF, value & 0xFF]);
    }

    function u32(value) {
        var normalized = value >>> 0;
        return Uint8Array.from([
            (normalized >>> 24) & 0xFF,
            (normalized >>> 16) & 0xFF,
            (normalized >>> 8) & 0xFF,
            normalized & 0xFF
        ]);
    }

    function u24le(value) {
        var normalized = value >>> 0;
        return Uint8Array.from([normalized & 0xFF, (normalized >>> 8) & 0xFF, (normalized >>> 16) & 0xFF]);
    }

    function u32le(value) {
        var normalized = value >>> 0;
        return Uint8Array.from([
            normalized & 0xFF,
            (normalized >>> 8) & 0xFF,
            (normalized >>> 16) & 0xFF,
            (normalized >>> 24) & 0xFF
        ]);
    }

    function encodeQuicVarInt(value) {
        if (value < 0) {
            throw new Error("QUIC varint cannot encode a negative value.");
        }

        if (value < 64) {
            return Uint8Array.from([value]);
        }

        if (value < 16384) {
            return Uint8Array.from([0x40 | ((value >>> 8) & 0x3F), value & 0xFF]);
        }

        if (value < 1073741824) {
            return Uint8Array.from([
                0x80 | ((value >>> 24) & 0x3F),
                (value >>> 16) & 0xFF,
                (value >>> 8) & 0xFF,
                value & 0xFF
            ]);
        }

        throw new Error("QUIC value is too large to encode in this utility.");
    }


    var PROTOCOL_GENERATORS = {
        dns: generateDnsPayload,
        mdns: generateMdnsPayload,
        ssdp: generateSsdpPayload,
        llmnr: generateLlmnrPayload,
        nbns: generateNbnsPayload,
        quic: generateQuicPayload,
        tls_client_hello: generateTlsClientHelloPayload,
        http2: generateHttp2Payload,
        http_browser: generateHttpBrowserPayload,
        websocket: generateWebsocketPayload,
        curl: generateCurlPayload,
        stun: generateStunPayload,
        dtls: generateDtlsPayload,
        sip: generateSipPayload,
        rtp: generateRtpPayload,
        rtcp: generateRtcpPayload,
        coap: generateCoapPayload,
        mqtt: generateMqttPayload,
        ntp: generateNtpPayload,
        dhcp_discover: generateDhcpDiscoverPayload,
        snmp: generateSnmpPayload,
        syslog: generateSyslogPayload,
        tftp: generateTftpPayload,
        radius: generateRadiusPayload,
        redis: generateRedisPayload,
        postgresql: generatePostgresqlPayload,
        mysql: generateMysqlPayload,
        utp: generateUtpPayload,
        bittorrent_dht: generateBittorrentDhtPayload
    };

    var PROTOCOL_GENERATORS_ASYNC = {
        quic: generateQuicPayloadAsync
    };

    return {
        generatePayload: generatePayload,
        generatePayloadAsync: generatePayloadAsync,
        helpers: {
            bytesToHex: bytesToHex,
            chunkPayload: chunkPayload,
            clearElement: clearElement,
            concatBytes: concatBytes,
            createElement: createElement,
            createMapById: createMapById,
            getRequiredElement: getRequiredElement,
            randomIntExclusive: randomIntExclusive,
            setElementHtml: setElementHtml,
            setElementText: setElementText
        }
    };
}));
