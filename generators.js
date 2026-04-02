(function (root, factory) {
    var data = root.PayloadGenData;
    if (!data && typeof require === "function") {
        require("./app.js");
        data = root.PayloadGenData || null;
    }
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
    var CHROME_BROWSER_DATA = Data.CHROME_BROWSER_DATA;
    var SSDP_SEARCH_TARGETS = Data.SSDP_SEARCH_TARGETS;
    var LATEST_QUIC_VERSION = Data.LATEST_QUIC_VERSION;
    var DNS_QUERY_TYPES = [0x0001, 0x001C, 0x0041];
    var MDNS_DISCOVERY_NAMES = [
        "_services._dns-sd._udp.local",
        "_googlecast._tcp.local",
        "_airplay._tcp.local"
    ];
    var NBNS_SUFFIX_OPTIONS = [0x00, 0x20];
    var SSDP_USER_AGENTS = [
        "Microsoft-Windows/10.0 UPnP/1.0 SSDP-Discovery/1.0",
        "macOS/14.7.6 UPnP/1.1 ControlPoint/1.0",
        "Linux/6.8 UPnP/1.1 Portable SDK for UPnP devices/1.14.18"
    ];
    var STUN_SOFTWARE_NAMES = [
        "Chrome WebRTC ICE agent",
        "Firefox ICE stack",
        "Safari WebRTC networking"
    ];
    var DHCP_CLIENT_PROFILES = [
        { hostPrefix: "DESKTOP-", vendorClass: "MSFT 5.0", maxMessageSize: 1500, parameterRequestList: [0x01, 0x03, 0x06, 0x0F, 0x1F, 0x21, 0x2B, 0x2C, 0x2E, 0x2F, 0x79, 0xF9, 0xFC] },
        { hostPrefix: "android-", vendorClass: "android-dhcp-14", maxMessageSize: 1500, parameterRequestList: [0x01, 0x03, 0x06, 0x0F, 0x1A, 0x1C, 0x33, 0x3A, 0x3B, 0x79, 0xFC] },
        { hostPrefix: "ip-", vendorClass: "dhcpcd-10.0.6:Linux-6.8", maxMessageSize: 1500, parameterRequestList: [0x01, 0x03, 0x06, 0x0C, 0x0F, 0x1A, 0x1C, 0x2A, 0x2B, 0x79, 0xFC] }
    ];
    var COMMON_SNMP_OIDS = [
        "1.3.6.1.2.1.1.1.0",
        "1.3.6.1.2.1.1.3.0",
        "1.3.6.1.2.1.1.5.0",
        "1.3.6.1.2.1.25.1.1.0"
    ];
    var SYSLOG_APP_NAMES = ["systemd", "sshd", "NetworkManager", "dnsmasq"];
    var SYSLOG_HOST_NAMES = ["edge-gw-01", "core-sw-02", "media-host", "workstation-15"];
    var MQTT_CLIENT_ID_PREFIXES = ["mqttjs_", "paho-", "esp32-", "sensor-"];
    var SIP_USER_AGENT = "Linphone/5.2.5 (belle-sip/5.3.90)";
    var CHROME_RUNTIME_PROFILE = {
        platform: "Windows",
        userAgentTemplate: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{uaVersion} Safari/537.36",
        acceptLanguage: "en-US,en;q=0.9",
        acceptEncoding: "gzip, deflate, br, zstd",
        websocketExtensions: "permessage-deflate; client_max_window_bits",
        secChUaBrands: ["Not)A;Brand", "Chromium", "Google Chrome"],
        http2Settings: [
            { id: 0x0001, value: 65536 },
            { id: 0x0003, value: 1000 },
            { id: 0x0004, value: 6291456 },
            { id: 0x0006, value: 262144 }
        ]
    };
    var QUIC_VERSION_DEF = { wireValue: LATEST_QUIC_VERSION, initialHeaderBase: 0xC0 };
    var CURL_QUIC_PROFILE_ID = "curl_h3";
    var CURL_QUIC_ECH_DOH_URL = "https://dns.google/resolve";
    var ECH_CONFIG_CACHE = {};
    var textEncoder = createTextEncoder();
    var textDecoder = createTextDecoder();
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
        return buildDnsQuestionPayload(
            randomIntExclusive(65535),
            0x0100,
            encodeDnsName(options.host),
            randomItem(DNS_QUERY_TYPES),
            0x0001,
            buildDnsOptRecord(1232)
        );
    }

    function generateMdnsPayload(options) {
        var useServiceDiscovery = randomIntExclusive(3) === 0;
        var queryClass = randomIntExclusive(2) === 0 ? 0x0001 : 0x8001;
        var queryName = useServiceDiscovery ? randomItem(MDNS_DISCOVERY_NAMES) : randomizeAsciiCase(options.host);
        var queryType = useServiceDiscovery ? 0x000C : randomItem([0x0001, 0x001C]);
        return buildDnsQuestionPayload(0x0000, 0x0000, encodeDnsName(queryName), queryType, queryClass);
    }

    function generateLlmnrPayload(options) {
        return buildDnsQuestionPayload(randomIntExclusive(65535), 0x0000, encodeDnsName(options.host), randomItem([0x0001, 0x001C]), 0x0001);
    }

    function generateNbnsPayload(options) {
        var suffix = randomItem(NBNS_SUFFIX_OPTIONS);
        var queryType = suffix === 0x20 ? 0x0020 : 0x0021;
        return buildDnsQuestionPayload(randomIntExclusive(65535), 0x0000, encodeNbnsName(options.host, suffix), queryType, 0x0001);
    }

    function buildDnsQuestionPayload(id, flags, nameBytes, typeValue, classValue, additionalRecordBytes) {
        var additionalCount = additionalRecordBytes && additionalRecordBytes.length ? 1 : 0;
        return concatBytes(
            u16(id),
            u16(flags),
            u16(1),
            u16(0),
            u16(0),
            u16(additionalCount),
            nameBytes,
            u16(typeValue),
            u16(classValue),
            additionalRecordBytes || zeroBytes(0)
        );
    }

    function buildDnsOptRecord(udpPayloadSize) {
        return concatBytes(
            Uint8Array.from([0x00]),
            u16(0x0029),
            u16(udpPayloadSize || 1232),
            u32(0),
            u16(0)
        );
    }

    function generateSsdpPayload() {
        var mx = 1 + randomIntExclusive(5);
        var searchTarget = randomItem(SSDP_SEARCH_TARGETS);
        var ssdpMessage = [
            "M-SEARCH * HTTP/1.1",
            "HOST: 239.255.255.250:1900",
            "MAN: \"ssdp:discover\"",
            "ST: " + searchTarget,
            "MX: " + mx,
            "USER-AGENT: " + randomItem(SSDP_USER_AGENTS),
            "ACCEPT-LANGUAGE: en-US,en;q=0.9",
            "",
            ""
        ].join("\r\n");

        return encodeText(ssdpMessage);
    }

    function buildQuicClientHello(host, options, scid) {
        return buildClientHelloBody(host, {
            legacyVersion: 0x0303,
            withTls13: true,
            alpnProtocol: "h3",
            browserVersion: options.browserVersion,
            withQuicTransportParameters: true,
            quicSourceConnectionId: scid,
            tlsFingerprintProfile: options.tlsFingerprintProfile
        });
    }

    async function buildQuicClientHelloAsync(host, options, scid) {
        if (options && options.echConfig) {
            return await buildDynamicEchQuicClientHello(host, options, scid);
        }

        return buildQuicClientHello(host, options, scid);
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

    function resolveQuicTargetPacketSize(options) {
        var targetPacketSize = options ? Number(options.quicTargetPacketSize) : NaN;
        var mtu = options ? Number(options.quicMtu) : NaN;

        if (options && options.quicPadToMtu && Number.isFinite(mtu) && mtu > 0) {
            return Math.max(1200, Math.floor(mtu));
        }

        if (Number.isFinite(targetPacketSize) && targetPacketSize > 0) {
            return Math.max(1200, Math.floor(targetPacketSize));
        }

        return 1200;
    }

    function calculateQuicInitialPaddingLength(payloadLength, dcidLength, scidLength, packetNumberLength, targetPacketSize, authTagLength) {
        var normalizedTarget = Number.isFinite(targetPacketSize) && targetPacketSize > 0 ? Math.floor(targetPacketSize) : 1200;
        var packetTagLength = Number.isFinite(authTagLength) && authTagLength > 0 ? Math.floor(authTagLength) : 0;
        var headerPrefixLength = 1 + 4 + 1 + dcidLength + 1 + scidLength + 1;
        var payloadWithProtectionLength = packetNumberLength + payloadLength + packetTagLength;
        var lengthFieldSize = encodeQuicVarInt(payloadWithProtectionLength).length;
        var previousLengthFieldSize = -1;
        var paddingNeeded = 0;

        normalizedTarget = Math.max(1200, normalizedTarget);

        while (lengthFieldSize !== previousLengthFieldSize) {
            previousLengthFieldSize = lengthFieldSize;
            paddingNeeded = Math.max(0, normalizedTarget - (headerPrefixLength + lengthFieldSize + payloadWithProtectionLength));
            lengthFieldSize = encodeQuicVarInt(payloadWithProtectionLength + paddingNeeded).length;
        }

        return Math.max(0, normalizedTarget - (headerPrefixLength + lengthFieldSize + payloadWithProtectionLength));
    }

    function padQuicInitialPayload(payload, dcid, scid, packetNumber, options, authTagLength) {
        var paddingNeeded = calculateQuicInitialPaddingLength(
            payload.length,
            dcid.length,
            scid.length,
            packetNumber.length,
            resolveQuicTargetPacketSize(options),
            authTagLength
        );

        if (paddingNeeded > 0) {
            return concatBytes(payload, zeroBytes(paddingNeeded));
        }

        return payload;
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

    function withCapturedCurlQuicProfile(options) {
        var merged = cloneOptions(options);

        if (!merged.tlsFingerprintProfile) {
            merged.tlsFingerprintProfile = CURL_QUIC_PROFILE_ID;
        }

        if (!Number.isFinite(Number(merged.quicScidLength))) {
            merged.quicScidLength = 0;
        }

        if (!Number.isFinite(Number(merged.quicTargetPacketSize))) {
            merged.quicTargetPacketSize = 1250;
        }

        if (!merged.quicPacketNumber) {
            merged.quicPacketNumber = Uint8Array.from([0x00]);
        }

        return merged;
    }

    async function resolveCurlQuicOptionsAsync(options) {
        var merged = withCapturedCurlQuicProfile(options);

        if (!hasCrypto ||
            !Crypto ||
            typeof Crypto.hpkeSetupBaseSender !== "function" ||
            typeof Crypto.hpkeSeal !== "function" ||
            typeof Crypto.generateX25519PublicKey !== "function") {
            return merged;
        }

        merged.echConfig = await resolveEchConfigForHost(normalizeHost(merged.host));
        return merged;
    }

    async function resolveEchConfigForHost(host) {
        var normalizedHost = normalizeHost(host).toLowerCase();

        if (!ECH_CONFIG_CACHE[normalizedHost]) {
            ECH_CONFIG_CACHE[normalizedHost] = loadEchConfigForHost(normalizedHost).catch(function (error) {
                delete ECH_CONFIG_CACHE[normalizedHost];
                throw error;
            });
        }

        return await ECH_CONFIG_CACHE[normalizedHost];
    }

    async function loadEchConfigForHost(host) {
        if (typeof fetch === "function") {
            try {
                var publishedConfig = await fetchPublishedEchConfig(host);

                if (publishedConfig) {
                    return publishedConfig;
                }
            } catch (error) {
                console.warn("ECH config lookup failed for", host, error);
            }
        }

        return await createSyntheticEchConfig(host);
    }

    async function fetchPublishedEchConfig(host) {
        var response = await fetch(
            CURL_QUIC_ECH_DOH_URL + "?name=" + encodeURIComponent(host) + "&type=HTTPS",
            {
                cache: "no-store",
                headers: { accept: "application/dns-json" }
            }
        );
        var payload;

        if (!response || !response.ok) {
            return null;
        }

        payload = await response.json();
        return extractPublishedEchConfig(payload);
    }

    function extractPublishedEchConfig(payload) {
        var answers = payload && payload.Answer ? payload.Answer : [];
        var index;

        for (index = 0; index < answers.length; index += 1) {
            var echBase64 = extractEchParamValue(answers[index] && answers[index].data);
            var configList;
            var config;

            if (!echBase64) {
                continue;
            }

            configList = parseEchConfigList(base64DecodeBytes(echBase64));
            config = selectSupportedEchConfig(configList);

            if (config) {
                return config;
            }
        }

        return null;
    }

    function extractEchParamValue(recordData) {
        var match = /\bech="?([^"\s]+)"?/i.exec(String(recordData || ""));
        return match ? match[1] : "";
    }

    function parseEchConfigList(configListBytes) {
        var bytes = Uint8Array.from(configListBytes || []);
        var totalLength;
        var end;
        var offset = 2;
        var configs = [];

        if (bytes.length < 2) {
            return configs;
        }

        totalLength = readU16(bytes, 0);
        end = Math.min(bytes.length, 2 + totalLength);

        while (offset + 4 <= end) {
            var configStart = offset;
            var version = readU16(bytes, offset);
            var contentLength = readU16(bytes, offset + 2);
            var contentStart = offset + 4;
            var contentEnd = contentStart + contentLength;

            if (contentEnd > end) {
                break;
            }

            if (version === 0xFE0D) {
                var config = parseEchConfig(bytes, configStart, contentStart, contentEnd);

                if (config) {
                    configs.push(config);
                }
            }

            offset = contentEnd;
        }

        return configs;
    }

    function parseEchConfig(bytes, configStart, contentStart, contentEnd) {
        var offset = contentStart;
        var publicKeyLength;
        var publicKey;
        var cipherSuitesLength;
        var suiteEnd;
        var cipherSuites = [];
        var maximumNameLength;
        var publicNameLength;
        var publicName;
        var selectedCipherSuite;

        if (offset + 1 + 2 + 2 > contentEnd) {
            return null;
        }

        var configId = bytes[offset];
        offset += 1;
        var kemId = readU16(bytes, offset);
        offset += 2;
        publicKeyLength = readU16(bytes, offset);
        offset += 2;

        if (offset + publicKeyLength > contentEnd) {
            return null;
        }

        publicKey = bytes.slice(offset, offset + publicKeyLength);
        offset += publicKeyLength;
        cipherSuitesLength = readU16(bytes, offset);
        offset += 2;
        suiteEnd = offset + cipherSuitesLength;

        if (suiteEnd > contentEnd) {
            return null;
        }

        while (offset + 4 <= suiteEnd) {
            cipherSuites.push({
                kdfId: readU16(bytes, offset),
                aeadId: readU16(bytes, offset + 2)
            });
            offset += 4;
        }

        if (offset + 2 > contentEnd) {
            return null;
        }

        maximumNameLength = bytes[offset];
        offset += 1;
        publicNameLength = bytes[offset];
        offset += 1;

        if (offset + publicNameLength > contentEnd) {
            return null;
        }

        publicName = decodeText(bytes.slice(offset, offset + publicNameLength));
        selectedCipherSuite = selectSupportedCipherSuite(cipherSuites);

        if (!selectedCipherSuite) {
            return null;
        }

        return {
            configId: configId,
            kemId: kemId,
            kdfId: selectedCipherSuite.kdfId,
            aeadId: selectedCipherSuite.aeadId,
            publicKey: publicKey,
            maximumNameLength: maximumNameLength,
            publicName: publicName || "",
            rawBytes: bytes.slice(configStart, contentEnd)
        };
    }

    function selectSupportedEchConfig(configs) {
        return (configs || []).find(function (config) {
            return config &&
                config.kemId === 0x0020 &&
                config.kdfId === 0x0001 &&
                (config.aeadId === 0x0001 || config.aeadId === 0x0002);
        }) || null;
    }

    function selectSupportedCipherSuite(cipherSuites) {
        return (cipherSuites || []).find(function (cipherSuite) {
            return cipherSuite &&
                cipherSuite.kdfId === 0x0001 &&
                (cipherSuite.aeadId === 0x0001 || cipherSuite.aeadId === 0x0002);
        }) || null;
    }

    async function createSyntheticEchConfig(host) {
        var normalizedHost = normalizeHost(host);
        var publicKey = await Crypto.generateX25519PublicKey();
        return buildEchConfigDescriptor({
            configId: randomBytes(1)[0],
            kemId: 0x0020,
            publicKey: publicKey,
            maximumNameLength: Math.min(255, normalizedHost.length),
            publicName: normalizedHost,
            cipherSuites: [{ kdfId: 0x0001, aeadId: 0x0001 }]
        });
    }

    function buildEchConfigDescriptor(definition) {
        var normalizedPublicKey = Uint8Array.from(definition.publicKey || []);
        var normalizedPublicName = normalizeHost(definition.publicName || "");
        var cipherSuites = (definition.cipherSuites || [{ kdfId: 0x0001, aeadId: 0x0001 }]).map(function (cipherSuite) {
            return { kdfId: cipherSuite.kdfId, aeadId: cipherSuite.aeadId };
        });
        var selectedCipherSuite = selectSupportedCipherSuite(cipherSuites) || { kdfId: 0x0001, aeadId: 0x0001 };
        var rawBytes = serializeEchConfig({
            configId: definition.configId,
            kemId: definition.kemId,
            publicKey: normalizedPublicKey,
            maximumNameLength: definition.maximumNameLength,
            publicName: normalizedPublicName,
            cipherSuites: cipherSuites
        });

        return {
            configId: definition.configId,
            kemId: definition.kemId,
            kdfId: selectedCipherSuite.kdfId,
            aeadId: selectedCipherSuite.aeadId,
            publicKey: normalizedPublicKey,
            maximumNameLength: definition.maximumNameLength,
            publicName: normalizedPublicName,
            rawBytes: rawBytes
        };
    }

    function serializeEchConfig(definition) {
        var publicKey = Uint8Array.from(definition.publicKey || []);
        var publicNameBytes = encodeText(normalizeHost(definition.publicName || ""));
        var cipherSuites = concatBytes.apply(null, (definition.cipherSuites || []).map(function (cipherSuite) {
            return concatBytes(u16(cipherSuite.kdfId), u16(cipherSuite.aeadId));
        }));
        var contents = concatBytes(
            Uint8Array.from([definition.configId & 0xFF]),
            u16(definition.kemId),
            u16(publicKey.length),
            publicKey,
            u16(cipherSuites.length),
            cipherSuites,
            Uint8Array.from([Math.min(255, definition.maximumNameLength || publicNameBytes.length)]),
            Uint8Array.from([publicNameBytes.length]),
            publicNameBytes,
            u16(0)
        );

        return concatBytes(u16(0xFE0D), u16(contents.length), contents);
    }

    function resolveQuicConnectionId(lengthOption, defaultLength) {
        var length = Number(lengthOption);

        if (!Number.isFinite(length)) {
            length = defaultLength;
        }

        return randomBytes(Math.max(0, Math.floor(length)));
    }

    function resolveQuicPacketNumber(options) {
        var explicitPacketNumber = options && options.quicPacketNumber;
        var packetNumberLength = options ? Number(options.quicPacketNumberLength) : NaN;

        if (explicitPacketNumber && typeof explicitPacketNumber.length === "number") {
            return Uint8Array.from(explicitPacketNumber);
        }

        if (!Number.isFinite(packetNumberLength)) {
            packetNumberLength = 4;
        }

        return randomBytes(Math.max(1, Math.floor(packetNumberLength)));
    }

    // Synchronous QUIC payload fallback when authenticated QUIC protection is unavailable.
    function generateQuicPayload(options) {
        var version = QUIC_VERSION_DEF;
        var dcid = resolveQuicConnectionId(options && options.quicDcidLength, 8);
        var scid = resolveQuicConnectionId(options && options.quicScidLength, 8);
        var packetNumber = resolveQuicPacketNumber(options);
        var clientHello = buildQuicClientHello(options.host, options, scid);
        var cryptoFrame = buildQuicCryptoFrame(clientHello, 0);
        var payload = cryptoFrame;

        if (options.quicEncrypt) {
            payload = padQuicInitialPayload(cryptoFrame, dcid, scid, packetNumber, options, 0);
        }

        return buildPlainQuicInitialPacket(version, dcid, scid, packetNumber, payload);
    }

    // Async QUIC payload with proper QUIC Initial encryption.
    async function generateQuicPayloadAsync(options) {
        if (!hasCrypto) {
            return generateQuicPayload(options);
        }

        var version = QUIC_VERSION_DEF;
        var dcid = resolveQuicConnectionId(options && options.quicDcidLength, 8);
        var scid = resolveQuicConnectionId(options && options.quicScidLength, 8);
        var packetNumber = resolveQuicPacketNumber(options);
        var clientHello = await buildQuicClientHelloAsync(options.host, options, scid);
        var cryptoFrame = buildQuicCryptoFrame(clientHello, 0);
        var payload = cryptoFrame;

        if (!options.quicEncrypt) {
            return buildPlainQuicInitialPacket(version, dcid, scid, packetNumber, cryptoFrame);
        }

        try {
            payload = padQuicInitialPayload(cryptoFrame, dcid, scid, packetNumber, options, 16);

            return await buildProtectedQuicInitialPacket(version, dcid, scid, packetNumber, payload);
        } catch (error) {
            console.warn("QUIC encryption failed, falling back to masking:", error);
            return generateQuicPayload(options);
        }
    }

    function generateCapturedCurlQuicPayload(options) {
        return generateQuicPayload(withCapturedCurlQuicProfile(options));
    }

    async function generateCapturedCurlQuicPayloadAsync(options) {
        try {
            var resolvedOptions = await resolveCurlQuicOptionsAsync(options);
            return await generateQuicPayloadAsync(resolvedOptions);
        } catch (error) {
            console.warn("curl_quic ECH resolution failed, falling back to standard QUIC payload:", error && error.message ? error.message : error);
            return await generateQuicPayloadAsync(withCapturedCurlQuicProfile(options));
        }
    }

    function generateTlsClientHelloPayload(options) {
        var handshake = buildClientHelloBody(options.host, {
            legacyVersion: 0x0303,
            withTls13: true,
            alpnProtocol: options.tlsAlpn,
            browserVersion: options.browserVersion,
            withQuicTransportParameters: false
        });

        return concatBytes(
            Uint8Array.from([0x16]),
            u16(0x0301),
            u16(handshake.length),
            handshake
        );
    }

    function generateHttp2Payload(options) {
        var browser = resolveBrowserProfile(options.browserVersion);
        var settingsBytes = concatBytes.apply(null, browser.http2Settings.map(function (setting) {
            return concatBytes(u16(setting.id), u32(setting.value));
        }));

        return concatBytes(
            encodeText("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
            buildHttp2Frame(0x04, 0x00, 0, settingsBytes),
            buildHttp2Frame(0x08, 0x00, 0, u32(15663105)),
            buildHttp2HeadersFrame(options.host || CONFIG.defaultHost, options.path || "/", browser)
        );
    }

    function generateHttpBrowserPayload(options) {
        var browser = resolveBrowserProfile(options.browserVersion);
        var target = withRandomQuery(options.path, options.randomQuery);
        var headers = buildBrowserRequestHeaders(browser, options.host, target, false);
        var browserMessage = headers.join("\r\n") + "\r\n\r\n";

        return encodeText(browserMessage);
    }

    function generateWebsocketPayload(options) {
        var browser = resolveBrowserProfile(options.browserVersion);
        var websocketMessage = buildBrowserWebsocketRequest(browser, options.host, options.path).join("\r\n") + "\r\n\r\n";

        return encodeText(websocketMessage);
    }

    function generateStunPayload(options) {
        var softwareAttr = buildStunAttribute(0x8022, encodeText(randomItem(STUN_SOFTWARE_NAMES)));
        var priorityAttr = buildStunAttribute(0x0024, u32(randomUint32() | 0x40000000));
        var controlAttr = buildStunAttribute(randomIntExclusive(2) === 0 ? 0x8029 : 0x802A, concatBytes(u32(randomUint32()), u32(randomUint32())));
        var usernameBytes = encodeText(bytesToHex(randomBytes(4)) + ":" + normalizeHost(options.host));
        var usernameAttr = buildStunAttribute(0x0006, usernameBytes);
        var transactionId = randomBytes(12);
        var messageWithoutFingerprint = concatBytes(
            u16(0x0001),
            u16(softwareAttr.length + priorityAttr.length + controlAttr.length + usernameAttr.length),
            u32(0x2112A442),
            transactionId,
            softwareAttr,
            priorityAttr,
            controlAttr,
            usernameAttr
        );
        var fingerprintValue = u32((crc32(messageWithoutFingerprint) ^ 0x5354554E) >>> 0);
        var fingerprintAttr = buildStunAttribute(0x8028, fingerprintValue);

        return concatBytes(
            u16(0x0001),
            u16(softwareAttr.length + priorityAttr.length + controlAttr.length + usernameAttr.length + fingerprintAttr.length),
            u32(0x2112A442),
            transactionId,
            softwareAttr,
            priorityAttr,
            controlAttr,
            usernameAttr,
            fingerprintAttr
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
            zeroBytes(6),
            u16(handshake.length),
            handshake
        );
    }

    function generateSipPayload(options) {
        var host = normalizeHost(options.host);
        var action = options.sipAction === "REGISTER" ? "REGISTER" : "OPTIONS";
        var localIp = randomPrivateIpv4();
        var localPort = 5060;
        var sipUser = String(1000 + randomIntExclusive(9000));
        var branch = "z9hG4bK" + bytesToHex(randomBytes(7));
        var tag = bytesToHex(randomBytes(5));
        var callId = bytesToHex(randomBytes(10)) + "@" + localIp;
        var toUri = "<sip:" + sipUser + "@" + host + ">";
        var requestUri = action === "REGISTER" ? "sip:" + host : "sip:" + sipUser + "@" + host;
        var lines = [
            action + " " + requestUri + " SIP/2.0",
            "Via: SIP/2.0/UDP " + localIp + ":" + localPort + ";branch=" + branch + ";rport",
            "Max-Forwards: 70",
            "From: <sip:" + sipUser + "@" + host + ">;tag=" + tag,
            "To: " + toUri,
            "Call-ID: " + callId,
            "CSeq: 1 " + action,
            "Contact: <sip:" + sipUser + "@" + localIp + ":" + localPort + ";transport=udp>",
            "User-Agent: " + SIP_USER_AGENT,
            "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, INFO, MESSAGE, SUBSCRIBE",
            action === "REGISTER"
                ? "Supported: replaces, outbound, gruu, path"
                : "Supported: replaces, outbound, path, timer",
            action === "REGISTER" ? "Allow-Events: presence, message-summary, refer" : "Accept: application/sdp",
            action === "REGISTER" ? "Expires: 600" : "Accept-Language: en",
            "Content-Length: 0",
            "",
            ""
        ];

        return encodeText(lines.join("\r\n"));
    }

    function generateRtpPayload() {
        var payloadType = randomItem([0x00, 0x08, 0x60]);
        var sequenceNumber = randomIntExclusive(65535);
        var timestamp = randomUint32();
        var ssrc = randomUint32();
        var payload = payloadType === 0x60 ? randomBytes(96) : randomBytes(160);
        return concatBytes(
            Uint8Array.from([0x80, payloadType]),
            u16(sequenceNumber),
            u32(timestamp),
            u32(ssrc),
            payload
        );
    }

    function generateRtcpPayload() {
        var ssrc = randomUint32();
        var ntpTimestamp = encodeNtpTimestamp(new Date());
        var senderReport = concatBytes(
            Uint8Array.from([0x80, 0xC8]),
            u16(0x0006),
            u32(ssrc),
            ntpTimestamp,
            u32(randomUint32()),
            u32(1 + randomIntExclusive(64)),
            u32(160 + randomIntExclusive(4096))
        );
        var cname = encodeText("webrtc@" + CONFIG.defaultHost);
        var sdesValue = concatBytes(
            u32(ssrc),
            Uint8Array.from([0x01, cname.length]),
            cname,
            Uint8Array.from([0x00]),
            zeroBytes((4 - ((4 + 2 + cname.length + 1) % 4)) % 4)
        );
        var sdes = concatBytes(
            Uint8Array.from([0x81, 0xCA]),
            u16(((4 + sdesValue.length) / 4) - 1),
            sdesValue
        );
        return concatBytes(senderReport, sdes);
    }

    function generateCoapPayload(options) {
        var token = randomBytes(2 + randomIntExclusive(7));
        var messageId = randomIntExclusive(65535);
        var isPost = options.coapMethod === "POST";
        var code = isPost ? 0x02 : 0x01;
        var requestOptions = buildCoapOptions(options.host, options.path, isPost);
        var payload = isPost ? concatBytes(Uint8Array.from([0xFF]), encodeText("{\"status\":\"ok\"}")) : zeroBytes(0);

        return concatBytes(
            Uint8Array.from([(randomIntExclusive(2) === 0 ? 0x40 : 0x50) | token.length, code]),
            u16(messageId),
            token,
            requestOptions,
            payload
        );
    }

    function generateMqttPayload(options) {
        var clientId = String(options.clientId || "").trim() || (randomItem(MQTT_CLIENT_ID_PREFIXES) + bytesToHex(randomBytes(3)));
        var protocolLevel = randomItem([0x04, 0x05]);
        var connectFlags = 0x02;
        var properties = protocolLevel === 0x05 ? concatBytes(
            Uint8Array.from([0x21]), u16(100),
            Uint8Array.from([0x27]), u32(1048576)
        ) : zeroBytes(0);
        var variableHeader = concatBytes(
            encodeLengthPrefixedText("MQTT"),
            Uint8Array.from([protocolLevel, connectFlags]),
            u16(60),
            protocolLevel === 0x05 ? concatBytes(encodeMqttRemainingLength(properties.length), properties) : zeroBytes(0)
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
        var now = new Date();
        var payload = zeroBytes(48);
        payload[0] = 0x23;
        payload[1] = 0x00;
        payload[2] = 0x06;
        payload[3] = 0xEC;
        payload.set(u32(0x00000100), 4);
        payload.set(u32(0x00000100), 8);
        payload.set(encodeText("INIT"), 12);
        payload.set(encodeNtpTimestamp(new Date(now.getTime() - 1000)), 16);
        payload.set(encodeNtpTimestamp(now), 40);
        return payload;
    }

    function generateDhcpDiscoverPayload() {
        var xid = randomBytes(4);
        var mac = randomMacAddress();
        var clientProfile = randomItem(DHCP_CLIENT_PROFILES);
        var hostname = clientProfile.hostPrefix + bytesToHex(randomBytes(3)).toUpperCase();
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
            buildDhcpOption(0x35, Uint8Array.from([0x01])),
            buildDhcpOption(0x3D, concatBytes(Uint8Array.from([0x01]), mac)),
            buildDhcpOption(0x0C, encodeText(hostname)),
            buildDhcpOption(0x37, Uint8Array.from(clientProfile.parameterRequestList)),
            buildDhcpOption(0x39, u16(clientProfile.maxMessageSize)),
            buildDhcpOption(0x3C, encodeText(clientProfile.vendorClass)),
            Uint8Array.from([0xFF])
        );

        return concatBytes(bootp, u32(0x63825363), options);
    }

    function generateSnmpPayload(options) {
        var requestId = randomInt31();
        var pduTag = randomIntExclusive(2) === 0 ? 0xA0 : 0xA1;
        var oid = options.oid || randomItem(COMMON_SNMP_OIDS);
        var pdu = berTlv(pduTag, concatBytes(
            berInteger(requestId),
            berInteger(0),
            berInteger(0),
            berSequence([
                berSequence([
                    berOid(oid),
                    berNull()
                ])
            ])
        ));

        return berSequence([
            berInteger(randomIntExclusive(2)),
            berOctetString(encodeText(options.community)),
            pdu
        ]);
    }

    function generateSyslogPayload(options) {
        var facilityCode = getSyslogFacilityCode(options.syslogFacility);
        var severityCode = getSyslogSeverityCode(options.syslogSeverity);
        var pri = facilityCode * 8 + severityCode;
        var appName = randomItem(SYSLOG_APP_NAMES);
        var hostName = randomItem(SYSLOG_HOST_NAMES);

        if (randomIntExclusive(2) === 0) {
            return encodeText("<" + pri + ">1 " + new Date().toISOString() + " " + hostName + " " + appName + " " + (100 + randomIntExclusive(900)) + " MSG" + randomIntExclusive(1000) + " - " + options.message);
        }

        return encodeText("<" + pri + ">" + formatSyslogTimestamp(new Date()) + " " + hostName + " " + appName + ": " + options.message);
    }

    function generateTftpPayload(options) {
        var optionBytes = buildTftpOptionBytes();
        var opcode = randomIntExclusive(4) === 0 ? 0x0002 : 0x0001;
        var mode = randomIntExclusive(4) === 0 ? "netascii" : "octet";

        return concatBytes(
            u16(opcode),
            encodeZeroTerminatedText(options.filename),
            encodeZeroTerminatedText(mode),
            optionBytes
        );
    }

    function generateRadiusPayload(options) {
        var usernameBytes = encodeText(options.username || "user");
        var nasIp = Uint8Array.from([192, 0, 2, 20 + randomIntExclusive(50)]);
        var nasIdentifier = "edge-ap-" + (10 + randomIntExclusive(90));
        var attributes = concatBytes(
            buildRadiusAttribute(0x01, usernameBytes),
            buildRadiusAttribute(0x04, nasIp),
            buildRadiusAttribute(0x05, u32(1 + randomIntExclusive(16))),
            buildRadiusAttribute(0x06, u32(2)),
            buildRadiusAttribute(0x20, encodeText(nasIdentifier)),
            buildRadiusAttribute(0x1E, encodeText("wlan"))
        );

        return concatBytes(
            Uint8Array.from([0x01, randomIntExclusive(255)]),
            u16(20 + attributes.length),
            randomBytes(16),
            attributes
        );
    }

    function generateRedisPayload() {
        var token = "client-" + bytesToHex(randomBytes(3));

        if (randomIntExclusive(2) === 0) {
            return encodeText(
                "*2\r\n$5\r\nHELLO\r\n$1\r\n3\r\n" +
                "*4\r\n$6\r\nCLIENT\r\n$7\r\nSETINFO\r\n$8\r\nLIB-NAME\r\n$9\r\nredis-cli\r\n" +
                "*2\r\n$4\r\nPING\r\n$" + token.length + "\r\n" + token + "\r\n"
            );
        }

        return encodeText("*3\r\n$6\r\nCLIENT\r\n$7\r\nSETNAME\r\n$" + token.length + "\r\n" + token + "\r\n");
    }

    function generatePostgresqlPayload(options) {
        var applicationName = "psql";
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
            Uint8Array.from([0x00]),
            encodeText("client_encoding"),
            Uint8Array.from([0x00]),
            encodeText("UTF8"),
            Uint8Array.from([0x00, 0x00])
        );

        return concatBytes(
            u32(8),
            u32(80877103),
            u32(body.length + 4),
            body
        );
    }

    function generateMysqlPayload(options) {
        var sql = "SELECT @@version_comment, CURRENT_USER()";
        var payload = concatBytes(Uint8Array.from([0x03]), encodeText(sql));
        return concatBytes(u24le(payload.length), Uint8Array.from([0x00]), payload);
    }

    function generateUtpPayload() {
        var connectionId = randomIntExclusive(65535);
        var sequenceNumber = 1 + randomIntExclusive(65534);
        return concatBytes(
            Uint8Array.from([0x41, 0x00]),
            u16(connectionId),
            u32(nowMicros32()),
            u32(0),
            u32(randomItem([65536, 131072, 1048576])),
            u16(sequenceNumber),
            u16(0)
        );
    }

    function generateBittorrentDhtPayload() {
        var transactionId = bytesToHex(randomBytes(1));
        var nodeId = randomBytes(20);

        if (randomIntExclusive(2) === 0) {
            return concatBytes(
                encodeText("d1:ad2:id20:"),
                nodeId,
                encodeText("2:roi1ee1:q4:ping1:t2:"),
                encodeText(transactionId),
                encodeText("1:v4:LT011:y1:qe")
            );
        }

        return concatBytes(
            encodeText("d1:ad2:id20:"),
            nodeId,
            encodeText("2:roi1e6:target20:"),
            randomBytes(20),
            encodeText("e1:q9:find_node1:t2:"),
            encodeText(transactionId),
            encodeText("1:v4:LT011:y1:qe")
        );
    }

    function buildClientHelloBody(host, options) {
        var browser = resolveBrowserProfile(options.browserVersion);
        var isQuic = !!options.withQuicTransportParameters;
        var fingerprint = cloneFingerprint(options.fingerprintOverride || resolveTlsFingerprint(browser, isQuic, options.tlsFingerprintProfile));
        var greaseValue = Object.prototype.hasOwnProperty.call(options, "greaseValue")
            ? options.greaseValue
            : (fingerprint.useGrease ? selectGreaseValue() : null);
        var secondaryGreaseValue = Object.prototype.hasOwnProperty.call(options, "secondaryGreaseValue")
            ? options.secondaryGreaseValue
            : (fingerprint.useSecondaryGrease ? selectGreaseValue(greaseValue) : null);
        var sessionId = options.sessionIdBytes ? Uint8Array.from(options.sessionIdBytes) : randomBytes(32);
        var clientRandom = options.clientRandom ? Uint8Array.from(options.clientRandom) : randomBytes(32);
        var extensions = buildTlsExtensions(host, {
            withTls13: !!options.withTls13,
            alpnProtocol: options.alpnProtocol,
            greaseValue: greaseValue,
            secondaryGreaseValue: secondaryGreaseValue,
            isQuic: isQuic,
            withQuicTransportParameters: !!options.withQuicTransportParameters,
            quicSourceConnectionId: options.quicSourceConnectionId || zeroBytes(0),
            fingerprint: fingerprint
        });
        var cipherSuites = encodeCipherSuites(fingerprint.cipherSuites, greaseValue);
        
        var body = concatBytes(
            u16(options.legacyVersion),
            clientRandom,
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

    async function buildDynamicEchQuicClientHello(host, options, scid) {
        var browser = resolveBrowserProfile(options.browserVersion);
        var baseFingerprint = resolveTlsFingerprint(browser, true, options.tlsFingerprintProfile);
        var echConfig = options.echConfig;
        var encodedInner = buildClientHelloBody(host, {
            legacyVersion: 0x0303,
            withTls13: true,
            alpnProtocol: "h3",
            browserVersion: options.browserVersion,
            withQuicTransportParameters: true,
            quicSourceConnectionId: scid,
            fingerprintOverride: createFingerprintWithEch(baseFingerprint, { clientHelloType: 0x01 }),
            sessionIdBytes: zeroBytes(0)
        }).subarray(4);
        var innerPaddingLength = calculateEncodedClientHelloInnerPadding(encodedInner, host, echConfig);
        var paddedEncodedInner = innerPaddingLength > 0 ? concatBytes(encodedInner, zeroBytes(innerPaddingLength)) : encodedInner;
        var hpkeContext = await Crypto.hpkeSetupBaseSender(
            echConfig.publicKey,
            buildEchInfo(echConfig),
            echConfig.kemId,
            echConfig.kdfId,
            echConfig.aeadId
        );
        var outerClientHello = buildClientHelloBody(echConfig.publicName || host, {
            legacyVersion: 0x0303,
            withTls13: true,
            alpnProtocol: "h3",
            browserVersion: options.browserVersion,
            withQuicTransportParameters: true,
            quicSourceConnectionId: scid,
            fingerprintOverride: createFingerprintWithEch(baseFingerprint, {
                clientHelloType: 0x00,
                kdfId: echConfig.kdfId,
                aeadId: echConfig.aeadId,
                configId: echConfig.configId,
                enc: hpkeContext.enc,
                payload: zeroBytes(paddedEncodedInner.length + getHpkeAeadTagLength(echConfig.aeadId))
            })
        });
        var echPayload = await Crypto.hpkeSeal(hpkeContext, outerClientHello.subarray(4), paddedEncodedInner);

        return replaceEchPayloadInClientHello(outerClientHello, echPayload);
    }

    function createFingerprintWithEch(baseFingerprint, echExtension) {
        var fingerprint = cloneFingerprint(baseFingerprint);

        if (fingerprint.extensionOrder.indexOf("encrypted_client_hello") === -1) {
            fingerprint.extensionOrder = fingerprint.extensionOrder.concat(["encrypted_client_hello"]);
        }

        fingerprint.encryptedClientHello = echExtension;
        return fingerprint;
    }

    function buildEchInfo(echConfig) {
        return concatBytes(encodeText("tls ech"), Uint8Array.from([0x00]), echConfig.rawBytes);
    }

    function calculateEncodedClientHelloInnerPadding(encodedInner, host, echConfig) {
        var hostnameLength = encodeText(normalizeHost(host)).length;
        var maxNameLength = echConfig && Number.isFinite(echConfig.maximumNameLength) && echConfig.maximumNameLength > 0
            ? echConfig.maximumNameLength
            : hostnameLength;
        var paddingLength = Math.max(0, maxNameLength - hostnameLength);
        var paddedLength = encodedInner.length + paddingLength;
        var blockPadding = (32 - (paddedLength % 32)) % 32;

        return paddingLength + blockPadding;
    }

    function getHpkeAeadTagLength(aeadId) {
        if (aeadId === 0x0002) {
            return 16;
        }

        return 16;
    }

    function replaceEchPayloadInClientHello(clientHelloBytes, echPayload) {
        var bytes = Uint8Array.from(clientHelloBytes);
        var payloadOffset = findEchPayloadOffset(bytes);

        if (payloadOffset.length !== echPayload.length) {
            throw new Error("ECH payload length mismatch.");
        }

        bytes.set(echPayload, payloadOffset.offset);
        return bytes;
    }

    function findEchPayloadOffset(clientHelloBytes) {
        var offset = 4 + 2 + 32;
        var sessionIdLength = clientHelloBytes[offset];
        var cipherSuitesLength;
        var compressionMethodsLength;
        var extensionsLength;
        var extensionsEnd;

        offset += 1 + sessionIdLength;
        cipherSuitesLength = readU16(clientHelloBytes, offset);
        offset += 2 + cipherSuitesLength;
        compressionMethodsLength = clientHelloBytes[offset];
        offset += 1 + compressionMethodsLength;
        extensionsLength = readU16(clientHelloBytes, offset);
        offset += 2;
        extensionsEnd = offset + extensionsLength;

        while (offset + 4 <= extensionsEnd) {
            var extensionType = readU16(clientHelloBytes, offset);
            var extensionLength = readU16(clientHelloBytes, offset + 2);
            var extensionDataOffset = offset + 4;

            if (extensionType === 0xFE0D) {
                var encLength = readU16(clientHelloBytes, extensionDataOffset + 1 + 2 + 2 + 1);
                var payloadLengthOffset = extensionDataOffset + 1 + 2 + 2 + 1 + 2 + encLength;
                var payloadLength = readU16(clientHelloBytes, payloadLengthOffset);

                return {
                    offset: payloadLengthOffset + 2,
                    length: payloadLength
                };
            }

            offset = extensionDataOffset + extensionLength;
        }

        throw new Error("ECH extension was not found in ClientHello.");
    }

    function buildDtlsClientHelloBody(host) {
        var sessionId = randomBytes(32);
        var extensions = concatBytes(
            buildServerNameExtension(host),
            buildSupportedGroupsExtension(null, [0x001D, 0x0017, 0x0018]),
            buildEcPointFormatsExtension(),
            buildSignatureAlgorithmsExtension(),
            buildUseSrtpExtension(),
            buildExtendedMasterSecretExtension()
        );
        var cipherSuites = concatBytes(
            u16(0xC02B),
            u16(0xC02F),
            u16(0xCCA9),
            u16(0xC02C),
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
        var isQuic = !!options.isQuic;
        var parts = [];

        options.fingerprint.extensionOrder.forEach(function (extensionName) {
            if (extensionName === "grease" && Number.isFinite(options.greaseValue)) {
                parts.push(buildGreaseExtension(options.greaseValue));
            } else if (extensionName === "sni") {
                parts.push(buildServerNameExtension(host));
            } else if (extensionName === "extended_master_secret") {
                parts.push(buildExtendedMasterSecretExtension());
            } else if (extensionName === "renegotiation_info") {
                parts.push(buildRenegotiationInfoExtension());
            } else if (extensionName === "supported_groups") {
                parts.push(buildSupportedGroupsExtension(options.greaseValue, options.fingerprint.supportedGroups));
            } else if (extensionName === "ec_point_formats") {
                parts.push(buildEcPointFormatsExtension());
            } else if (extensionName === "session_ticket") {
                parts.push(buildSessionTicketExtension());
            } else if (extensionName === "alpn" && options.alpnProtocol) {
                parts.push(buildAlpnExtension(resolveAlpnProtocols(options.alpnProtocol, isQuic)));
            } else if (extensionName === "status_request") {
                parts.push(buildStatusRequestExtension());
            } else if (extensionName === "signature_algorithms") {
                parts.push(buildSignatureAlgorithmsExtension(options.fingerprint.signatureAlgorithms));
            } else if (extensionName === "sct") {
                parts.push(buildSignedCertificateTimestampExtension());
            } else if (extensionName === "supported_versions" && options.withTls13) {
                parts.push(buildSupportedVersionsExtension(options.greaseValue, options.fingerprint.supportedVersions));
            } else if (extensionName === "key_share") {
                parts.push(buildKeyShareExtension(options.greaseValue, options.fingerprint.keyShares));
            } else if (extensionName === "psk_modes") {
                parts.push(buildPskModesExtension());
            } else if (extensionName === "quic_transport_parameters" && options.withQuicTransportParameters) {
                parts.push(buildQuicTransportParametersExtension(options.quicSourceConnectionId, options.fingerprint));
            } else if (extensionName === "compress_certificate" && options.withTls13 && options.fingerprint.compressCertificateAlgorithms.length) {
                parts.push(buildCompressCertificateExtension(options.fingerprint.compressCertificateAlgorithms));
            } else if (extensionName === "application_settings" && !isQuic && options.alpnProtocol === "h2" && options.fingerprint.includeApplicationSettings) {
                parts.push(buildApplicationSettingsExtension(["h2"]));
            } else if (extensionName === "encrypted_client_hello" && options.fingerprint.encryptedClientHello) {
                parts.push(buildEncryptedClientHelloExtension(options.fingerprint.encryptedClientHello));
            } else if (extensionName === "secondary_grease" && Number.isFinite(options.secondaryGreaseValue)) {
                parts.push(buildGreaseExtension(options.secondaryGreaseValue));
            } else if (extensionName === "padding") {
                var paddingLength = calculateTlsPaddingLength(parts, options.fingerprint.paddingTarget);
                if (paddingLength > 0) {
                    parts.push(buildPaddingExtension(paddingLength));
                }
            }
        });

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

    function buildSupportedVersionsExtension(greaseValue, versions) {
        var parts = [];

        if (Number.isFinite(greaseValue)) {
            parts.push(u16(greaseValue));
        }

        (versions || [0x0304, 0x0303]).forEach(function (version) {
            parts.push(u16(version));
        });

        var versionBytes = concatBytes.apply(null, parts);
        return concatBytes(u16(0x002B), u16(versionBytes.length + 1), Uint8Array.from([versionBytes.length]), versionBytes);
    }

    function buildSupportedGroupsExtension(greaseValue, groups) {
        var parts = [];

        if (Number.isFinite(greaseValue)) {
            parts.push(u16(greaseValue));
        }

        (groups || [0x001D, 0x0017, 0x0018]).forEach(function (group) {
            parts.push(u16(group));
        });

        var groups = concatBytes.apply(null, parts);
        return concatBytes(u16(0x000A), u16(groups.length + 2), u16(groups.length), groups);
    }

    function buildSignatureAlgorithmsExtension(signatureAlgorithms) {
        var algorithms = concatBytes.apply(null, (signatureAlgorithms || [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0807
        ]).map(function (algorithm) {
            return u16(algorithm);
        }));
        return concatBytes(u16(0x000D), u16(algorithms.length + 2), u16(algorithms.length), algorithms);
    }

    function buildEcPointFormatsExtension() {
        return concatBytes(u16(0x000B), u16(2), Uint8Array.from([0x01, 0x00]));
    }

    function buildPskModesExtension() {
        return concatBytes(u16(0x002D), u16(2), Uint8Array.from([0x01, 0x01]));
    }

    function buildKeyShareExtension(greaseValue, groups) {
        var entries = [];

        if (Number.isFinite(greaseValue)) {
            entries.push(u16(greaseValue), u16(1), Uint8Array.from([0x00]));
        }

        (groups || [0x001D]).forEach(function (group) {
            var keyBytes = buildKeyShareValue(group);
            entries.push(u16(group), u16(keyBytes.length), keyBytes);
        });

        entries = concatBytes.apply(null, entries);
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

    function buildCompressCertificateExtension(algorithms) {
        // Extension 27 - Compress Certificate
        var encodedAlgorithms = concatBytes.apply(null, (algorithms || [0x0002]).map(function (algorithm) {
            return u16(algorithm);
        }));
        var algorithmList = concatBytes(
            Uint8Array.from([encodedAlgorithms.length]),
            encodedAlgorithms
        );
        return concatBytes(u16(0x001B), u16(algorithmList.length), algorithmList);
    }

    function buildEncryptedClientHelloExtension(config) {
        if (config && config.clientHelloType === 0x01) {
            return concatBytes(u16(0xFE0D), u16(1), Uint8Array.from([0x01]));
        }

        var enc = config && config.enc ? config.enc : zeroBytes(0);
        var payload = config && config.payload ? config.payload : zeroBytes(0);
        var data = concatBytes(
            Uint8Array.from([config && Number.isFinite(config.clientHelloType) ? config.clientHelloType : 0x00]),
            u16(config && Number.isFinite(config.kdfId) ? config.kdfId : 0x0001),
            u16(config && Number.isFinite(config.aeadId) ? config.aeadId : 0x0001),
            Uint8Array.from([config && Number.isFinite(config.configId) ? config.configId : 0x00]),
            u16(enc.length),
            enc,
            u16(payload.length),
            payload
        );

        return concatBytes(u16(0xFE0D), u16(data.length), data);
    }

    function buildApplicationSettingsExtension(protocols) {
        var entries = concatBytes.apply(null, protocols.map(function (protocol) {
            var protocolBytes = encodeText(protocol);
            return concatBytes(Uint8Array.from([protocolBytes.length]), protocolBytes);
        }));
        return concatBytes(u16(0x4469), u16(entries.length + 2), u16(entries.length), entries);
    }

    function buildQuicTransportParametersExtension(sourceConnectionId, fingerprint) {
        var order = fingerprint && fingerprint.quicTransportParameterOrder
            ? fingerprint.quicTransportParameterOrder
            : [0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0e, 0x0f];
        var values = {
            0x01: encodeQuicVarInt(readFingerprintNumber(fingerprint, "maxIdleTimeout", 30000)),
            0x03: encodeQuicVarInt(readFingerprintNumber(fingerprint, "maxUdpPayloadSize", 1472)),
            0x04: encodeQuicVarInt(readFingerprintNumber(fingerprint, "initialMaxData", 15728640)),
            0x05: encodeQuicVarInt(readFingerprintNumber(fingerprint, "initialMaxStreamDataBidiLocal", 6291456)),
            0x06: encodeQuicVarInt(readFingerprintNumber(fingerprint, "initialMaxStreamDataBidiRemote", 6291456)),
            0x07: encodeQuicVarInt(readFingerprintNumber(fingerprint, "initialMaxStreamDataUni", 6291456)),
            0x08: encodeQuicVarInt(readFingerprintNumber(fingerprint, "initialMaxStreamsBidi", 100)),
            0x09: encodeQuicVarInt(readFingerprintNumber(fingerprint, "initialMaxStreamsUni", 100)),
            0x0a: encodeQuicVarInt(readFingerprintNumber(fingerprint, "ackDelayExponent", 3)),
            0x0b: encodeQuicVarInt(readFingerprintNumber(fingerprint, "maxAckDelay", 25)),
            0x0e: encodeQuicVarInt(readFingerprintNumber(fingerprint, "activeConnectionIdLimit", 8)),
            0x0f: sourceConnectionId
        };
        var parameters = concatBytes.apply(null, order.map(function (parameterId) {
            if (parameterId === 0x0c) {
                return encodeTransportParameter(parameterId, zeroBytes(0));
            }

            return encodeTransportParameter(parameterId, values[parameterId]);
        }));

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

    function buildCoapOptions(host, path, isPost) {
        var currentOptionNumber = 0;
        var parts = [];
        var pathParts = splitPathAndQuery(path);

        if (host) {
            parts.push(encodeCoapOption(3 - currentOptionNumber, encodeText(host)));
            currentOptionNumber = 3;
        }

        pathParts.segments.forEach(function (segment) {
            parts.push(encodeCoapOption(11 - currentOptionNumber, encodeText(segment)));
            currentOptionNumber = 11;
        });

        if (isPost) {
            parts.push(encodeCoapOption(12 - currentOptionNumber, Uint8Array.from([50])));
            currentOptionNumber = 12;
        }

        pathParts.query.forEach(function (querySegment) {
            parts.push(encodeCoapOption(15 - currentOptionNumber, encodeText(querySegment)));
            currentOptionNumber = 15;
        });

        parts.push(encodeCoapOption(17 - currentOptionNumber, Uint8Array.from([50])));

        return concatBytes.apply(null, parts);
    }

    function resolveBrowserProfile(browserVersion) {
        var browserDataProfile = CHROME_BROWSER_DATA || {};
        var runtime = CHROME_RUNTIME_PROFILE;
        var resolvedVersion = String(browserVersion || "").trim();

        if (!resolvedVersion || resolvedVersion.toLowerCase() === "auto") {
            resolvedVersion = browserDataProfile.defaultVersion;
        }

        return {
            id: "chrome",
            tlsStyle: "chromium",
            browserVersion: resolvedVersion,
            majorVersion: parseInt(resolvedVersion.split(".")[0], 10) || parseInt(browserDataProfile.defaultVersion, 10) || 0,
            platform: runtime.platform,
            acceptLanguage: runtime.acceptLanguage,
            acceptEncoding: runtime.acceptEncoding,
            websocketExtensions: runtime.websocketExtensions,
            http2Settings: runtime.http2Settings,
            includeSecChUa: runtime.secChUaBrands.length > 0,
            secChUa: buildSecChUa(runtime.secChUaBrands, parseInt(resolvedVersion.split(".")[0], 10) || 0),
            userAgent: formatBrowserUserAgent(runtime.userAgentTemplate, resolvedVersion, browserDataProfile),
            acceptHeader: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
        };
    }

    function getReducedChromiumVersion(version, fallback) {
        var majorVersion = parseInt(String(version || "").split(".")[0], 10);

        if (Number.isFinite(majorVersion) && majorVersion > 0) {
            return majorVersion + ".0.0.0";
        }

        return String(fallback || "0.0.0.0");
    }

    function formatBrowserUserAgent(template, version, browserDataProfile) {
        var fallbackUserAgent = CHROME_BROWSER_DATA ? CHROME_BROWSER_DATA.userAgent : "";
        var resolvedVersion = String(version || "").trim();
        var dataProfile = browserDataProfile || {};
        var defaultVersion = String(dataProfile.defaultVersion || "").trim();

        if (fallbackUserAgent && resolvedVersion && resolvedVersion === defaultVersion) {
            return fallbackUserAgent;
        }

        return String(template || "").replace(/\{uaVersion\}/g, getReducedChromiumVersion(resolvedVersion, dataProfile.uaVersion));
    }

    function buildSecChUa(brands, majorVersion) {
        return (brands || []).map(function (brand) {
            var version = /^Not/i.test(brand) ? 99 : (majorVersion || 0);
            return "\"" + brand + "\";v=\"" + version + "\"";
        }).join(", ");
    }

    function buildBrowserRequestHeaders(browser, host, target) {
        var lines = [
            "GET " + target + " HTTP/1.1",
            "Host: " + host
        ];

        if (browser.includeSecChUa) {
            lines.push(
                "Connection: keep-alive",
                "Cache-Control: max-age=0",
                "sec-ch-ua: " + browser.secChUa,
                "sec-ch-ua-mobile: ?0",
                "sec-ch-ua-platform: \"" + browser.platform + "\"",
                "Upgrade-Insecure-Requests: 1",
                "User-Agent: " + browser.userAgent,
                "Accept: " + browser.acceptHeader,
                "Sec-Fetch-Site: none",
                "Sec-Fetch-Mode: navigate",
                "Sec-Fetch-User: ?1",
                "Sec-Fetch-Dest: document",
                "Accept-Encoding: " + browser.acceptEncoding,
                "Accept-Language: " + browser.acceptLanguage
            );
            return lines;
        }

        lines.push(
            "User-Agent: " + browser.userAgent,
            "Accept: " + browser.acceptHeader,
            "Accept-Language: " + browser.acceptLanguage,
            "Accept-Encoding: " + browser.acceptEncoding,
            "Connection: keep-alive",
            "Upgrade-Insecure-Requests: 1",
            "Sec-Fetch-Dest: document",
            "Sec-Fetch-Mode: navigate",
            "Sec-Fetch-Site: none",
            "Sec-Fetch-User: ?1"
        );
        return lines;
    }

    function buildBrowserWebsocketRequest(browser, host, path) {
        var lines = [
            "GET " + normalizePath(path) + " HTTP/1.1",
            "Host: " + host,
            "Connection: Upgrade",
            "Pragma: no-cache",
            "Cache-Control: no-cache",
            "User-Agent: " + browser.userAgent,
            "Upgrade: websocket",
            "Origin: https://" + host,
            "Sec-WebSocket-Version: 13",
            "Accept-Encoding: " + browser.acceptEncoding,
            "Accept-Language: " + browser.acceptLanguage,
            "Sec-WebSocket-Key: " + base64EncodeBytes(randomBytes(16))
        ];

        if (browser.websocketExtensions) {
            lines.push("Sec-WebSocket-Extensions: " + browser.websocketExtensions);
        }

        return lines;
    }

    function buildHttp2Frame(frameType, flags, streamId, payload) {
        var body = payload || zeroBytes(0);
        return concatBytes(
            u24(body.length),
            Uint8Array.from([frameType & 0xFF, flags & 0xFF]),
            u32(streamId & 0x7FFFFFFF),
            body
        );
    }

    function buildHttp2HeadersFrame(host, path, browser) {
        return buildHttp2Frame(0x01, 0x05, 1, buildHttp2RequestHeaderBlock(host, path, browser));
    }

    function buildHttp2RequestHeaderBlock(host, path, browser) {
        var normalizedPath = normalizePath(path);
        return concatBytes(
            encodeHpackIndexedHeader(2),
            encodeHpackIndexedHeader(6),
            encodeHpackLiteralWithIndexedName(1, encodeText(host)),
            normalizedPath === "/" ? encodeHpackIndexedHeader(4) : encodeHpackLiteralWithIndexedName(4, encodeText(normalizedPath)),
            encodeHpackLiteralWithIndexedName(58, encodeText(browser.userAgent)),
            encodeHpackLiteralWithIndexedName(19, encodeText(browser.acceptHeader)),
            encodeHpackLiteralWithIndexedName(16, encodeText(browser.acceptEncoding)),
            encodeHpackLiteralHeader("accept-language", encodeText(browser.acceptLanguage))
        );
    }

    function encodeHpackIndexedHeader(index) {
        return encodeHpackInteger(index, 7, 0x80);
    }

    function encodeHpackLiteralWithIndexedName(index, valueBytes) {
        return concatBytes(
            encodeHpackInteger(index, 4, 0x00),
            encodeHpackString(valueBytes)
        );
    }

    function encodeHpackLiteralHeader(name, valueBytes) {
        return concatBytes(
            encodeHpackInteger(0, 4, 0x00),
            encodeHpackString(encodeText(name)),
            encodeHpackString(valueBytes)
        );
    }

    function encodeHpackInteger(value, prefixBits, prefixMask) {
        var maxPrefixValue = (1 << prefixBits) - 1;
        var bytes = [];
        var remaining = value;

        if (remaining < maxPrefixValue) {
            return Uint8Array.from([prefixMask | remaining]);
        }

        bytes.push(prefixMask | maxPrefixValue);
        remaining -= maxPrefixValue;

        while (remaining >= 128) {
            bytes.push((remaining % 128) | 0x80);
            remaining = Math.floor(remaining / 128);
        }

        bytes.push(remaining);
        return Uint8Array.from(bytes);
    }

    function encodeHpackString(valueBytes) {
        return concatBytes(encodeHpackInteger(valueBytes.length, 7, 0x00), valueBytes);
    }

    function buildStunAttribute(type, valueBytes) {
        var padding = (4 - (valueBytes.length % 4)) % 4;
        return concatBytes(
            u16(type),
            u16(valueBytes.length),
            valueBytes,
            zeroBytes(padding)
        );
    }

    function crc32(bytes) {
        var crc = 0xFFFFFFFF;
        var index;
        var bit;

        for (index = 0; index < bytes.length; index += 1) {
            crc ^= bytes[index];

            for (bit = 0; bit < 8; bit += 1) {
                if (crc & 1) {
                    crc = (crc >>> 1) ^ 0xEDB88320;
                } else {
                    crc = crc >>> 1;
                }
            }
        }

        return (~crc) >>> 0;
    }

    function buildDhcpOption(code, valueBytes) {
        return concatBytes(Uint8Array.from([code, valueBytes.length]), valueBytes);
    }

    function buildRadiusAttribute(type, valueBytes) {
        return concatBytes(Uint8Array.from([type, valueBytes.length + 2]), valueBytes);
    }

    function encodeNtpTimestamp(date) {
        var ms = date instanceof Date ? date.getTime() : Date.now();
        var seconds = Math.floor(ms / 1000) + 2208988800;
        var fraction = Math.floor(((ms % 1000) / 1000) * 0x100000000) >>> 0;
        return concatBytes(u32(seconds >>> 0), u32(fraction));
    }

    function buildKeyShareValue(group) {
        if (group === 0x0017) {
            return concatBytes(Uint8Array.from([0x04]), randomBytes(64));
        }

        if (group === 0x0018) {
            return concatBytes(Uint8Array.from([0x04]), randomBytes(96));
        }

        return randomBytes(32);
    }

    function calculateTlsPaddingLength(parts, targetSize) {
        var currentLength = 0;

        if (!targetSize) {
            return 0;
        }

        parts.forEach(function (part) {
            currentLength += part.length;
        });

        return Math.max(0, targetSize - (4 + 2 + 32 + 1 + 32 + 2 + 32 + 2 + 2) - currentLength - 4);
    }

    function encodeCipherSuites(cipherSuites, greaseValue) {
        var parts = [];

        if (Number.isFinite(greaseValue)) {
            parts.push(u16(greaseValue));
        }

        (cipherSuites || []).forEach(function (cipherSuite) {
            parts.push(u16(cipherSuite));
        });

        return concatBytes.apply(null, parts);
    }

    function resolveTlsFingerprint(browser, isQuic, profileId) {
        var defaultSignatureAlgorithms = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0807];

        if (isQuic && profileId === CURL_QUIC_PROFILE_ID) {
            return createCapturedCurlQuicFingerprint();
        }

        return {
            useGrease: true,
            useSecondaryGrease: true,
            cipherSuites: isQuic
                ? [0x1301, 0x1302, 0x1303]
                : [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035],
            extensionOrder: isQuic
                ? ["grease", "sni", "supported_groups", "alpn", "status_request", "signature_algorithms", "sct", "supported_versions", "key_share", "psk_modes", "quic_transport_parameters", "compress_certificate", "secondary_grease", "padding"]
                : ["grease", "sni", "extended_master_secret", "renegotiation_info", "supported_groups", "ec_point_formats", "session_ticket", "alpn", "status_request", "signature_algorithms", "sct", "supported_versions", "key_share", "psk_modes", "compress_certificate", "application_settings", "secondary_grease", "padding"],
            supportedGroups: [0x001D, 0x0017, 0x0018],
            signatureAlgorithms: defaultSignatureAlgorithms,
            supportedVersions: isQuic ? [0x0304] : [0x0304, 0x0303],
            keyShares: [0x001D],
            compressCertificateAlgorithms: [0x0002],
            includeApplicationSettings: true,
            paddingTarget: 512,
            maxUdpPayloadSize: 1472,
            activeConnectionIdLimit: 8
        };
    }

    function createCapturedCurlQuicFingerprint() {
        return {
            useGrease: false,
            useSecondaryGrease: false,
            cipherSuites: [0x1301],
            extensionOrder: ["sni", "supported_versions", "supported_groups", "signature_algorithms", "alpn", "key_share", "psk_modes", "quic_transport_parameters", "compress_certificate", "encrypted_client_hello"],
            supportedGroups: [0x001D, 0x0017, 0x0018],
            signatureAlgorithms: [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806],
            supportedVersions: [0x0304],
            keyShares: [0x001D],
            compressCertificateAlgorithms: [0x0002],
            includeApplicationSettings: false,
            paddingTarget: 0,
            encryptedClientHello: null,
            quicTransportParameterOrder: [0x03, 0x07, 0x05, 0x09, 0x01, 0x08, 0x0f, 0x0e, 0x06, 0x04],
            maxIdleTimeout: 30000,
            maxUdpPayloadSize: 1472,
            initialMaxData: 10485760,
            initialMaxStreamDataBidiLocal: 5242880,
            initialMaxStreamDataBidiRemote: 5242880,
            initialMaxStreamDataUni: 5242880,
            initialMaxStreamsBidi: 100,
            initialMaxStreamsUni: 100,
            activeConnectionIdLimit: 2
        };
    }

    function readFingerprintNumber(fingerprint, key, defaultValue) {
        var value = fingerprint && fingerprint[key];
        return Number.isFinite(value) ? value : defaultValue;
    }

    function buildUseSrtpExtension() {
        var profiles = concatBytes(u16(2), u16(0x0001), Uint8Array.from([0x00]));
        return concatBytes(u16(0x000E), u16(profiles.length), profiles);
    }

    function splitPathAndQuery(path) {
        var normalized = normalizePath(path);
        var queryIndex = normalized.indexOf("?");
        var pathname = queryIndex === -1 ? normalized : normalized.slice(0, queryIndex);
        var query = queryIndex === -1 ? "" : normalized.slice(queryIndex + 1);

        return {
            segments: pathname.split("/").filter(function (segment) {
                return segment.length > 0;
            }),
            query: query ? query.split("&").filter(function (segment) { return segment.length > 0; }) : []
        };
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

    function randomPrivateIpv4() {
        var pools = [
            [10, randomIntExclusive(256), randomIntExclusive(256), 10 + randomIntExclusive(200)],
            [172, 16 + randomIntExclusive(16), randomIntExclusive(256), 10 + randomIntExclusive(200)],
            [192, 168, randomIntExclusive(256), 10 + randomIntExclusive(200)]
        ];
        var octets = randomItem(pools);

        return octets.join(".");
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
        return splitPathAndQuery(path).segments;
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

    function encodeNbnsName(host, suffix) {
        var label = normalizeHost(host).split(".")[0].toUpperCase().replace(/[^A-Z0-9!@#$%^&()\-_'{}.~]/g, "");
        var sixteenByteName = (label.slice(0, 15) + "               ").slice(0, 15) + String.fromCharCode((suffix || 0) & 0xFF);
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

    function hexToBytes(value) {
        var normalized = String(value || "").replace(/[^0-9a-f]/ig, "");
        var bytes = new Uint8Array(Math.floor(normalized.length / 2));
        var index;

        for (index = 0; index < bytes.length; index += 1) {
            bytes[index] = parseInt(normalized.slice(index * 2, (index * 2) + 2), 16);
        }

        return bytes;
    }

    function cloneOptions(options) {
        var copy = {};
        var key;

        options = options || {};

        for (key in options) {
            if (Object.prototype.hasOwnProperty.call(options, key)) {
                copy[key] = options[key];
            }
        }

        return copy;
    }

    function cloneFingerprint(fingerprint) {
        var copy = {};
        var key;

        fingerprint = fingerprint || {};

        for (key in fingerprint) {
            if (!Object.prototype.hasOwnProperty.call(fingerprint, key)) {
                continue;
            }

            if (fingerprint[key] instanceof Uint8Array) {
                copy[key] = Uint8Array.from(fingerprint[key]);
            } else if (Array.isArray(fingerprint[key])) {
                copy[key] = fingerprint[key].map(function (item) {
                    return item && typeof item === "object" ? cloneOptions(item) : item;
                });
            } else if (fingerprint[key] && typeof fingerprint[key] === "object") {
                copy[key] = cloneOptions(fingerprint[key]);
            } else {
                copy[key] = fingerprint[key];
            }
        }

        return copy;
    }

    function encodeText(value) {
        return textEncoder.encode(String(value));
    }

    function decodeText(bytes) {
        return textDecoder.decode(Uint8Array.from(bytes || []));
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

    function createTextDecoder() {
        if (typeof TextDecoder !== "undefined") {
            return new TextDecoder();
        }

        if (typeof require === "function") {
            return new (require("node:util").TextDecoder)();
        }

        throw new Error("TextDecoder is not available in this environment.");
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

    function base64DecodeBytes(value) {
        if (typeof root.atob === "function") {
            var binary = root.atob(String(value || ""));
            var bytes = new Uint8Array(binary.length);
            var index;

            for (index = 0; index < binary.length; index += 1) {
                bytes[index] = binary.charCodeAt(index);
            }

            return bytes;
        }

        if (typeof Buffer !== "undefined") {
            return new Uint8Array(Buffer.from(String(value || ""), "base64"));
        }

        if (typeof require === "function") {
            return new Uint8Array(require("node:buffer").Buffer.from(String(value || ""), "base64"));
        }

        throw new Error("Base64 decoding is not available in this environment.");
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

    function readU16(bytes, offset) {
        return ((bytes[offset] << 8) | bytes[offset + 1]) >>> 0;
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
        curl_quic: generateCapturedCurlQuicPayload,
        stun: generateStunPayload,
        dtls: generateDtlsPayload,
        sip: generateSipPayload,
        rtp: generateRtpPayload,
        rtcp: generateRtcpPayload,
        coap: generateCoapPayload,
        ntp: generateNtpPayload,
        dhcp_discover: generateDhcpDiscoverPayload,
        utp: generateUtpPayload,
        bittorrent_dht: generateBittorrentDhtPayload
    };

    var PROTOCOL_GENERATORS_ASYNC = {
        quic: generateQuicPayloadAsync,
        curl_quic: generateCapturedCurlQuicPayloadAsync
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
