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
    var QUIC_VERSION_DEFS = {
        v1: { value: "v1", wireValue: 0x00000001, initialHeaderBase: 0xC0 },
        v2: { value: "v2", wireValue: 0x6B3343CF, initialHeaderBase: 0xD0 }
    };
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

    function buildQuicClientHello(host, options, scid) {
        return buildClientHelloBody(host, {
            legacyVersion: 0x0303,
            withTls13: true,
            alpnProtocol: "h3",
            browserProfile: options.browserProfile,
            withQuicTransportParameters: true,
            quicSourceConnectionId: scid
        });
    }

    function buildQuicCryptoFrame(data, offset) {
        var frameOffset = Number.isFinite(offset) ? offset : 0;
        return concatBytes(
            Uint8Array.from([0x06]),
            encodeQuicVarInt(frameOffset),
            encodeQuicVarInt(data.length),
            data
        );
    }

    function buildPlainQuicInitialPacket(version, dcid, scid, packetNumber, payload) {
        var packetLength = packetNumber.length + payload.length;
        return concatBytes(
            Uint8Array.from([getQuicInitialFirstByte(version, packetNumber.length)]),
            u32(version.wireValue),
            Uint8Array.from([dcid.length]),
            dcid,
            Uint8Array.from([scid.length]),
            scid,
            encodeQuicVarInt(0),
            encodeQuicVarInt(packetLength),
            packetNumber,
            payload
        );
    }

    async function buildProtectedQuicInitialPacket(version, dcid, scid, packetNumber, payload) {
        var secrets = await Crypto.deriveInitialSecrets(dcid, version.value);
        var keys = await Crypto.derivePacketProtectionKeys(secrets.client, version.value);
        var firstByte = getQuicInitialFirstByte(version, packetNumber.length);
        var packetLength = packetNumber.length + payload.length + 16;
        var headerForAad = concatBytes(
            Uint8Array.from([firstByte]),
            u32(version.wireValue),
            Uint8Array.from([dcid.length]),
            dcid,
            Uint8Array.from([scid.length]),
            scid,
            encodeQuicVarInt(0),
            encodeQuicVarInt(packetLength),
            packetNumber
        );
        var nonce = Crypto.constructNonce(keys.iv, packetNumber);
        var encrypted = await Crypto.aesGcmEncrypt(keys.key, nonce, payload, headerForAad);
        var sampleOffset = 4 - packetNumber.length;

        if (sampleOffset >= 0 && encrypted.length >= sampleOffset + 16) {
            var sample = encrypted.subarray(sampleOffset, sampleOffset + 16);
            var headerProtection = await Crypto.applyHeaderProtection(keys.hp, sample, firstByte, packetNumber);
            var protectedHeader = new Uint8Array(headerForAad);
            protectedHeader[0] = headerProtection.firstByte;
            protectedHeader.set(headerProtection.packetNumber, protectedHeader.length - packetNumber.length);

            return concatBytes(protectedHeader, encrypted);
        }

        return concatBytes(headerForAad, encrypted);
    }

    function buildQuicAwgPayload(clientHello, level) {
        var cutLevel = parseInt(level, 10);
        var payload;
        var cutSettings;
        var clientHelloBytes = clientHello instanceof Uint8Array ? clientHello : new Uint8Array(clientHello);

        if (!cutLevel) {
            payload = buildQuicCryptoFrame(clientHelloBytes, 0);
            var dataOffset = payload.length - clientHelloBytes.length;
            cutSettings = [dataOffset + 6, 32, clientHelloBytes.length - 38, 16];
        } else {
            var cutPresets = {
                1: [38, Infinity, 0, 38, 32, false],
                2: [38, Infinity, 0, 38, 37, false],
                3: [0, 1, 38, Infinity, 0, false],
                4: [0, 1, 38, Infinity, 0, true]
            };
            var cutPreset = cutPresets[cutLevel] || cutPresets[1];
            var p1s = cutPreset[0];
            var p1e = cutPreset[1];
            var p2s = cutPreset[2];
            var p2e = cutPreset[3];
            var dropTail = cutPreset[4];
            var skipZeroes = cutPreset[5];

            if (skipZeroes) {
                while (p2s < clientHelloBytes.length && clientHelloBytes[p2s] === 0) {
                    p2s += 1;
                }
            }

            payload = concatBytes(
                buildQuicCryptoFrame(sliceBytes(clientHelloBytes, p1s, p1e), p1s),
                buildQuicCryptoFrame(sliceBytes(clientHelloBytes, p2s, p2e), p2s)
            );
            cutSettings = [payload.length - dropTail, 16 + dropTail];
        }

        return {
            payload: payload,
            cutSettings: cutSettings
        };
    }

    function fixQuicAwgCutSettings(cutSettings, packetLength, packetNumberLength, payloadLength) {
        if (cutSettings[0] < 20 - packetNumberLength) {
            var toAdd = 20 - packetNumberLength - cutSettings[0];
            cutSettings[0] += toAdd;
            cutSettings[1] -= toAdd;
        }

        cutSettings[0] += packetLength - payloadLength - 16;
    }

    function formatQuicAwg(buffer, parts, includeFirst) {
        var include = includeFirst !== false;
        var offset = 0;
        var index;
        var result = "";

        if (!parts || !parts.length) {
            return "<b 0x" + bytesToHex(buffer) + ">";
        }

        for (index = 0; index < parts.length; index += 1) {
            var part = parts[index];

            if (part > 0) {
                if (include) {
                    result += "<b 0x" + bytesToHex(sliceBytes(buffer, offset, offset + part)) + ">";
                } else {
                    result += "<r " + part + ">";
                }

                offset += part;
            }

            include = !include;
        }

        return result;
    }

    function sliceBytes(bytes, start, end) {
        return bytes.slice(start, end === Infinity ? bytes.length : end);
    }

    // Synchronous QUIC payload (backward compatible, uses random masking)
    function generateQuicPayload(options) {
        var version = resolveQuicVersion(options.quicVersion);
        var dcid = randomBytes(8);
        var scid = randomBytes(8);
        var packetNumber = randomBytes(4);
        var clientHello = buildQuicClientHello(options.host, options, scid);
        var cryptoBody = options.quicEncrypt ? maskQuicCryptoBody(clientHello) : clientHello;
        var cryptoFrame = buildQuicCryptoFrame(cryptoBody, 0);

        return buildPlainQuicInitialPacket(version, dcid, scid, packetNumber, cryptoFrame);
    }

    // Async QUIC payload with proper QUIC Initial encryption.
    // RFC 9001 applies to QUIC v1; RFC 9369 adjusts the v2 wire version,
    // Initial salt, HKDF labels, and long-header packet type bits.
    async function generateQuicPayloadAsync(options) {
        if (!hasCrypto) {
            return generateQuicPayload(options);
        }

        var version = resolveQuicVersion(options.quicVersion);
        var dcid = randomBytes(8);
        var scid = randomBytes(8);
        var packetNumber = randomBytes(4);
        var clientHello = buildQuicClientHello(options.host, options, scid);
        var cryptoFrame = buildQuicCryptoFrame(clientHello, 0);
        var payload = cryptoFrame;

        if (!options.quicEncrypt) {
            return buildPlainQuicInitialPacket(version, dcid, scid, packetNumber, cryptoFrame);
        }

        try {
            var headerSize = 1 + 4 + 1 + dcid.length + 1 + scid.length + 1 + 2 + packetNumber.length + 16;
            var targetSize = 1200;
            var currentPayloadSize = cryptoFrame.length;
            var paddingNeeded = Math.max(0, targetSize - headerSize - currentPayloadSize);

            if (paddingNeeded > 0) {
                payload = concatBytes(cryptoFrame, new Uint8Array(paddingNeeded));
            }

            return await buildProtectedQuicInitialPacket(version, dcid, scid, packetNumber, payload);
        } catch (error) {
            console.warn("QUIC encryption failed, falling back to masking:", error);
            return generateQuicPayload(options);
        }
    }

    async function generateQuicAwgSignaturePartsAsync(options) {
        if (!hasCrypto) {
            throw new Error("AWG segmented QUIC output requires WebCrypto support.");
        }

        var version = resolveQuicVersion(options.quicVersion);
        var dcid = randomBytes(8);
        var scid = randomBytes(8);
        var packetNumber = randomBytes(4);
        var clientHello = buildQuicClientHello(options.host, options, scid);
        var awgPayload = buildQuicAwgPayload(clientHello, options.quicAwgLevel);
        var packetBytes = await buildProtectedQuicInitialPacket(version, dcid, scid, packetNumber, awgPayload.payload);
        var cutSettings = awgPayload.cutSettings.slice();

        fixQuicAwgCutSettings(cutSettings, packetBytes.length, packetNumber.length, awgPayload.payload.length);

        return {
            expression: formatQuicAwg(packetBytes, cutSettings, true),
            packetLength: packetBytes.length
        };
    }

    async function generateQuicAwgSignatureAsync(options) {
        var parts = await generateQuicAwgSignaturePartsAsync(options);
        return parts.expression;
    }

    function generateTlsClientHelloPayload(options) {
        var handshake = buildClientHelloBody(options.host, {
            legacyVersion: 0x0303,
            withTls13: true,
            alpnProtocol: options.tlsAlpn,
            browserProfile: options.browserProfile,
            withQuicTransportParameters: false
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
        var greaseValue = selectGreaseValue();
        var secondaryGreaseValue = selectGreaseValue(greaseValue);
        var isQuic = !!options.withQuicTransportParameters;
        var sessionId = randomBytes(32);
        var extensions = buildTlsExtensions(host, {
            withTls13: !!options.withTls13,
            alpnProtocol: options.alpnProtocol,
            greaseValue: greaseValue,
            secondaryGreaseValue: secondaryGreaseValue,
            isQuic: isQuic,
            withQuicTransportParameters: !!options.withQuicTransportParameters,
            quicSourceConnectionId: options.quicSourceConnectionId || zeroBytes(0)
        });

        var cipherSuites = isQuic
            ? concatBytes(
                u16(greaseValue),
                u16(0x1301),
                u16(0x1302),
                u16(0x1303)
            )
            : concatBytes(
                u16(greaseValue),
                u16(0x1301),
                u16(0x1302),
                u16(0x1303),
                u16(0xC02B),
                u16(0xC02F),
                u16(0xC02C),
                u16(0xC030),
                u16(0xCCA9),
                u16(0xCCA8),
                u16(0xC013),
                u16(0xC014),
                u16(0x009C),
                u16(0x009D),
                u16(0x002F),
                u16(0x0035)
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

    function buildTlsExtensions(host, options) {
        // Extension order matters for fingerprinting. Use a browser-like TCP layout
        // and a separate leaner QUIC layout so the ClientHello matches its transport.
        var greaseValue = options.greaseValue;
        var isQuic = !!options.isQuic;
        var parts = isQuic
            ? [
                buildGreaseExtension(greaseValue),
                buildServerNameExtension(host),
                buildSupportedGroupsExtension(greaseValue),
                buildStatusRequestExtension(),
                buildSignatureAlgorithmsExtension(),
                buildSignedCertificateTimestampExtension(),
                buildKeyShareExtension(greaseValue),
                buildPskModesExtension()
            ]
            : [
                buildGreaseExtension(greaseValue),
                buildServerNameExtension(host),
                buildExtendedMasterSecretExtension(),
                buildRenegotiationInfoExtension(),
                buildSupportedGroupsExtension(greaseValue),
                buildEcPointFormatsExtension(),
                buildSessionTicketExtension(),
                buildStatusRequestExtension(),
                buildSignatureAlgorithmsExtension(),
                buildSignedCertificateTimestampExtension(),
                buildKeyShareExtension(greaseValue),
                buildPskModesExtension()
            ];

        if (options.alpnProtocol) {
            parts.splice(isQuic ? 3 : 7, 0, buildAlpnExtension(resolveAlpnProtocols(options.alpnProtocol, isQuic)));
        }

        if (options.withQuicTransportParameters) {
            parts.push(buildQuicTransportParametersExtension(options.quicSourceConnectionId));
        }

        if (options.withTls13) {
            var keyShareIndex = findExtensionInsertIndex(parts, 0x0033);
            parts.splice(keyShareIndex, 0, buildSupportedVersionsExtension(greaseValue, isQuic));
            parts.push(buildCompressCertificateExtension());
        }

        if (!isQuic && options.alpnProtocol === "h2") {
            parts.push(buildApplicationSettingsExtension(["h2"]));
        }

        parts.push(buildGreaseExtension(options.secondaryGreaseValue));

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

    function buildAlpnExtension(protocols) {
        var entries = concatBytes.apply(null, protocols.map(function (protocol) {
            var protocolBytes = encodeText(protocol);
            return concatBytes(Uint8Array.from([protocolBytes.length]), protocolBytes);
        }));
        var data = concatBytes(u16(entries.length), entries);
        return concatBytes(u16(0x0010), u16(data.length), data);
    }

    function buildSupportedVersionsExtension(greaseValue, isQuic) {
        var versions = concatBytes(
            u16(greaseValue),
            u16(0x0304),
            isQuic ? zeroBytes(0) : u16(0x0303)
        );
        if (isQuic) {
            versions = concatBytes(u16(greaseValue), u16(0x0304));
        }
        return concatBytes(u16(0x002B), u16(versions.length + 1), Uint8Array.from([versions.length]), versions);
    }

    function buildSupportedGroupsExtension(greaseValue) {
        var parts = [];

        if (Number.isFinite(greaseValue)) {
            parts.push(u16(greaseValue));
        }

        parts.push(
            u16(0x001D),  // x25519 (most preferred)
            u16(0x0017),  // secp256r1 (P-256)
            u16(0x0018)   // secp384r1 (P-384)
        );

        var groups = concatBytes.apply(null, parts);
        return concatBytes(u16(0x000A), u16(groups.length + 2), u16(groups.length), groups);
    }

    function buildSignatureAlgorithmsExtension() {
        var algorithms = concatBytes(
            u16(0x0403),  // ecdsa_secp256r1_sha256
            u16(0x0804),  // rsa_pss_rsae_sha256
            u16(0x0401),  // rsa_pkcs1_sha256
            u16(0x0503),  // ecdsa_secp384r1_sha384
            u16(0x0805),  // rsa_pss_rsae_sha384
            u16(0x0501),  // rsa_pkcs1_sha384
            u16(0x0806),  // rsa_pss_rsae_sha512
            u16(0x0601),  // rsa_pkcs1_sha512
            u16(0x0807)   // ed25519
        );
        return concatBytes(u16(0x000D), u16(algorithms.length + 2), u16(algorithms.length), algorithms);
    }

    function buildEcPointFormatsExtension() {
        return concatBytes(u16(0x000B), u16(2), Uint8Array.from([0x01, 0x00]));
    }

    function buildPskModesExtension() {
        return concatBytes(u16(0x002D), u16(2), Uint8Array.from([0x01, 0x01]));
    }

    function buildKeyShareExtension(greaseValue) {
        var keyBytes = randomBytes(32);
        var entries = concatBytes(
            u16(greaseValue),
            u16(1),
            Uint8Array.from([0x00]),
            u16(0x001D),
            u16(keyBytes.length),
            keyBytes
        );
        return concatBytes(u16(0x0033), u16(entries.length + 2), u16(entries.length), entries);
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

    function buildApplicationSettingsExtension(protocols) {
        var entries = concatBytes.apply(null, protocols.map(function (protocol) {
            var protocolBytes = encodeText(protocol);
            return concatBytes(Uint8Array.from([protocolBytes.length]), protocolBytes);
        }));
        return concatBytes(u16(0x4469), u16(entries.length + 2), u16(entries.length), entries);
    }

    function buildQuicTransportParametersExtension(sourceConnectionId) {
        var parameters = concatBytes(
            encodeTransportParameter(0x01, encodeQuicVarInt(30000)),
            encodeTransportParameter(0x03, encodeQuicVarInt(1472)),
            encodeTransportParameter(0x04, encodeQuicVarInt(15728640)),
            encodeTransportParameter(0x05, encodeQuicVarInt(6291456)),
            encodeTransportParameter(0x06, encodeQuicVarInt(6291456)),
            encodeTransportParameter(0x07, encodeQuicVarInt(6291456)),
            encodeTransportParameter(0x08, encodeQuicVarInt(100)),
            encodeTransportParameter(0x09, encodeQuicVarInt(100)),
            encodeTransportParameter(0x0a, encodeQuicVarInt(3)),
            encodeTransportParameter(0x0b, encodeQuicVarInt(25)),
            encodeTransportParameter(0x0c, zeroBytes(0)),
            encodeTransportParameter(0x0e, encodeQuicVarInt(8)),
            encodeTransportParameter(0x0f, sourceConnectionId)
        );
        return concatBytes(u16(0x0039), u16(parameters.length), parameters);
    }

    function encodeTransportParameter(id, valueBytes) {
        return concatBytes(
            encodeQuicVarInt(id),
            encodeQuicVarInt(valueBytes.length),
            valueBytes
        );
    }

    function buildPaddingExtension(paddingLength) {
        // Extension 21 - Padding
        if (paddingLength <= 0) {
            return new Uint8Array(0);
        }
        var padding = new Uint8Array(paddingLength);
        return concatBytes(u16(0x0015), u16(paddingLength), padding);
    }

    function buildGreaseExtension(greaseValue) {
        return concatBytes(u16(greaseValue), u16(0));
    }

    function selectGreaseValue(excluded) {
        var values = [
            0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A,
            0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
            0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
            0xCACA, 0xDADA, 0xEAEA, 0xFAFA
        ];
        var filtered = values.filter(function (value) {
            return value !== excluded;
        });
        return randomItem(filtered.length ? filtered : values);
    }

    function findExtensionInsertIndex(parts, extensionType) {
        var marker = u16(extensionType);
        var index;

        for (index = 0; index < parts.length; index += 1) {
            var part = parts[index];
            if (part.length >= 2 && part[0] === marker[0] && part[1] === marker[1]) {
                return index;
            }
        }

        return parts.length;
    }

    function resolveAlpnProtocols(protocol, isQuic) {
        if (isQuic) {
            return [protocol];
        }

        if (protocol === "h2") {
            return ["h2", "http/1.1"];
        }

        return [protocol];
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

    function resolveQuicVersion(value) {
        var normalized = String(value == null ? "" : value).trim().toLowerCase();

        if (!normalized || normalized === "latest" || normalized === "default") {
            normalized = LATEST_QUIC_VERSION === QUIC_VERSION_DEFS.v2.wireValue ? "v2" : "v1";
        } else if (normalized === "1" || normalized === "0x00000001") {
            normalized = "v1";
        } else if (normalized === "2" || normalized === "0x6b3343cf") {
            normalized = "v2";
        }

        return QUIC_VERSION_DEFS[normalized] || QUIC_VERSION_DEFS.v1;
    }

    function getQuicInitialFirstByte(version, packetNumberLength) {
        return version.initialHeaderBase | ((packetNumberLength - 1) & 0x03);
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
        generateQuicAwgSignaturePartsAsync: generateQuicAwgSignaturePartsAsync,
        generateQuicAwgSignatureAsync: generateQuicAwgSignatureAsync,
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
