(function (root) {
    "use strict";

    function buildChromeUserAgent(uaVersion) {
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" +
            String(uaVersion || "0.0.0.0") +
            " Safari/537.36";
    }

    function isNonEmptyString(value) {
        return typeof value === "string" && value.trim().length > 0;
    }

    function isValidChromeVersion(version) {
        return /^\d+\.\d+\.\d+\.\d+$/.test(String(version || "").trim());
    }

    function getChromeMajorVersion(version) {
        var majorVersion = parseInt(String(version || "").split(".")[0], 10);
        return Number.isFinite(majorVersion) && majorVersion > 0 ? majorVersion : 0;
    }

    var CONFIG = {
        maxBlocks: 5,
        maxOutputLines: 5,
        defaultMtu: 1280,
        defaultHost: "gosuslugi.ru",
        browserDataUrl: "https://versionhistory.googleapis.com/v1/chrome/platforms/win/channels/stable/versions/all/releases?page_size=1&order_by=version%20desc"
    };
    var CHROME_BROWSER_DATA = {
        updatedAt: "2026-04-01T20:26:32.318Z",
        defaultVersion: "147.0.7727.50",
        uaVersion: "147.0.0.0",
        userAgent: buildChromeUserAgent("147.0.0.0")
    };

    function updateChromeBrowserData(version, updatedAt) {
        var normalizedVersion = String(version || "").trim();
        var majorVersion = getChromeMajorVersion(normalizedVersion);

        if (!isValidChromeVersion(normalizedVersion) || !majorVersion) {
            return false;
        }

        CHROME_BROWSER_DATA.defaultVersion = normalizedVersion;
        CHROME_BROWSER_DATA.uaVersion = majorVersion + ".0.0.0";
        CHROME_BROWSER_DATA.userAgent = buildChromeUserAgent(CHROME_BROWSER_DATA.uaVersion);

        if (isNonEmptyString(updatedAt)) {
            CHROME_BROWSER_DATA.updatedAt = String(updatedAt).trim();
        }

        return true;
    }

    async function loadChromeVersionData(url, timeoutMs) {
        var targetUrl = isNonEmptyString(url) ? String(url).trim() : CONFIG.browserDataUrl;
        var timeout = typeof timeoutMs === "number" && timeoutMs > 0 ? timeoutMs : 1500;
        var controller = null;
        var timerId = null;
        var response;
        var payload;
        var release;

        if (!targetUrl || typeof fetch !== "function") {
            return false;
        }

        if (typeof AbortController === "function") {
            controller = new AbortController();
            timerId = setTimeout(function () {
                controller.abort();
            }, timeout);
        }

        try {
            response = await fetch(targetUrl, {
                cache: "no-store",
                signal: controller ? controller.signal : undefined
            });

            if (!response || !response.ok) {
                return false;
            }

            payload = await response.json();
            release = payload && payload.releases && payload.releases[0];
            return !!(release && updateChromeBrowserData(release.version, release.serving && release.serving.startTime));
        } catch (error) {
            return false;
        } finally {
            if (timerId) {
                clearTimeout(timerId);
            }
        }
    }

    root.PayloadGenData = {
        CONFIG: CONFIG,
        DONATE_URL: "https://boosty.to/sketchystan1",
        LATEST_QUIC_VERSION: 0x00000001,
        SSDP_SEARCH_TARGETS: [
            "ssdp:all",
            "upnp:rootdevice",
            "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
            "urn:schemas-upnp-org:service:WANIPConnection:1",
            "urn:schemas-upnp-org:device:MediaServer:1"
        ],
        CURL_USER_AGENTS: ["curl/8.5.0", "curl/8.7.1", "curl/8.10.1", "curl/8.13.0"],
        CHROME_BROWSER_DATA: CHROME_BROWSER_DATA,
        loadChromeVersionData: loadChromeVersionData
    };
}(typeof globalThis !== "undefined" ? globalThis : this));

(function (root, factory) {
    var api = factory(root, root.PayloadGenData || null);

    if (typeof module !== "undefined" && module.exports) {
        module.exports = api;
    }

    if (typeof window !== "undefined") {
        window.PayloadGen = api;
        window.addEventListener("DOMContentLoaded", function () {
            api.init();
        });
    }
}(typeof globalThis !== "undefined" ? globalThis : this, function (root, SharedData) {
    "use strict";

    if (!SharedData) {
        throw new Error("PayloadGenData is required before app.js.");
    }

    var CONFIG = SharedData.CONFIG;
    var UI = {
        title: "PayloadGen",
        description: "Categorized protocol payload generator.",
        introHtml: "Generate <code>i1..i5</code> payload.",
        blocksTitle: "Payload Blocks",
        outputLabel: "Generated Output",
        outputPlaceholder: "Press Generate to build i1..i5 lines.",
        addButton: "Add Payload",
        generateButton: "Generate",
        copyButton: "Copy Output",
        resetButton: "Reset",
        removeButton: "Remove",
        donateButton: "Donate",
        mtuLabel: "MTU",
        padMtuLabel: "Pad to MTU",
        protocolLabel: "Protocol",
        wikiLinkLabel: "Wiki",
        payloadTitle: "Payload"
    };
    var CATEGORY_DEFS = [
        { id: "discovery", rank: 1, label: "Discovery & Name Resolution" },
        { id: "web", rank: 2, label: "Web & Secure Web" },
        { id: "realtime", rank: 3, label: "Realtime & Media" },
        { id: "iot", rank: 4, label: "IoT & Device" },
        { id: "infra", rank: 5, label: "Infrastructure & Operations" },
        { id: "messaging", rank: 6, label: "Messaging & Databases" },
        { id: "p2p", rank: 7, label: "P2P & Distribution" }
    ];
    var OPTION_SETS = {
        httpMethods: [{ value: "GET", label: "GET" }, { value: "HEAD", label: "HEAD" }, { value: "POST", label: "POST" }],
        sipActions: [{ value: "OPTIONS", label: "OPTIONS" }, { value: "REGISTER", label: "REGISTER" }],
        coapMethods: [{ value: "GET", label: "GET" }, { value: "POST", label: "POST" }],
        tlsAlpn: [{ value: "http/1.1", label: "http/1.1" }, { value: "h2", label: "h2" }],
        syslogFacilities: [{ value: "user", label: "user" }, { value: "daemon", label: "daemon" }, { value: "local0", label: "local0" }],
        syslogSeverities: [{ value: "info", label: "info" }, { value: "notice", label: "notice" }, { value: "warning", label: "warning" }]
    };
    var FIELD_DEFS = {
        host: { type: "text", label: "Domain", placeholder: "example.com", spellcheck: false },
        path: { type: "text", label: "Path", placeholder: "/", defaultValue: "/", spellcheck: false },
        httpMethod: { type: "select", label: "Method", optionSet: "httpMethods", defaultValue: "GET" },
        sipAction: { type: "select", label: "Action", optionSet: "sipActions", defaultValue: "OPTIONS" },
        coapMethod: { type: "select", label: "Method", optionSet: "coapMethods", defaultValue: "GET" },
        randomQuery: { type: "checkbox", label: "Random Query", defaultValue: true },
        filename: { type: "text", label: "Filename", defaultValue: "test.bin", spellcheck: false },
        username: { type: "text", label: "Username", spellcheck: false },
        database: { type: "text", label: "Database", spellcheck: false },
        community: { type: "text", label: "Community", defaultValue: "public", spellcheck: false },
        oid: { type: "text", label: "OID", defaultValue: "1.3.6.1.2.1.1.1.0", spellcheck: false },
        message: { type: "textarea", label: "Message", defaultValue: "payloadgen test", className: "field field-wide", rows: 3, spellcheck: false },
        clientId: { type: "text", label: "Client ID", spellcheck: false },
        tlsAlpn: { type: "select", label: "ALPN", optionSet: "tlsAlpn", defaultValue: "h2" },
        browserVersion: { type: "text", label: "Version", spellcheck: false },
        syslogFacility: { type: "select", label: "Facility", optionSet: "syslogFacilities", defaultValue: "user" },
        syslogSeverity: { type: "select", label: "Severity", optionSet: "syslogSeverities", defaultValue: "info" }
    };
    var PROTOCOL_CATALOG = [
        { id: "dns", categoryId: "discovery", transport: "udp", port: 53, rank: 1, label: "DNS", descriptor: "Standard A-record query", fieldSet: ["host"] },
        { id: "mdns", categoryId: "discovery", transport: "udp", port: 5353, rank: 2, label: "mDNS", descriptor: "Multicast DNS query with randomized query class and DNS case", fieldSet: ["host"] },
        { id: "ssdp", categoryId: "discovery", transport: "udp", port: 1900, rank: 3, label: "SSDP", descriptor: "Generated discovery probe", fieldSet: [] },
        { id: "llmnr", categoryId: "discovery", transport: "udp", port: 5355, rank: 4, label: "LLMNR", descriptor: "LLMNR hostname query", fieldSet: ["host"] },
        { id: "nbns", categoryId: "discovery", transport: "udp", port: 137, rank: 5, label: "NBNS", descriptor: "NetBIOS name query", fieldSet: ["host"] },
        { id: "quic", categoryId: "web", transport: "udp", port: 443, rank: 1, label: "QUIC", descriptor: "Initial-like QUIC payload", fieldSet: ["host"] },
        { id: "tls_client_hello", categoryId: "web", transport: "tcp", port: 443, rank: 2, label: "TLS ClientHello", descriptor: "TLS ClientHello packet", fieldSet: ["host", "browserVersion", "tlsAlpn"], defaults: { tlsAlpn: "h2" } },
        { id: "http2", categoryId: "web", transport: "tcp", port: 80, rank: 3, label: "HTTP/2", descriptor: "Browser-style HTTP/2 preface, SETTINGS, and opening stream", fieldSet: ["host", "path", "browserVersion"], defaults: { path: "/" } },
        { id: "http_browser", categoryId: "web", transport: "tcp", port: 80, rank: 4, label: "HTTP Browser", descriptor: "Browser-style HTTP/1.1 request", fieldSet: ["host", "browserVersion", "path", "randomQuery"], defaults: { path: "/", randomQuery: true } },
        { id: "websocket", categoryId: "web", transport: "tcp", port: 80, rank: 5, label: "WebSocket", descriptor: "WebSocket upgrade request", fieldSet: ["host", "browserVersion", "path"], defaults: { path: "/" } },
        { id: "curl", categoryId: "web", transport: "tcp", port: 80, rank: 6, label: "cURL (HTTP/1.1)", descriptor: "Dynamic HTTP/1.1 request with curl User-Agent", fieldSet: ["host", "path", "httpMethod", "randomQuery"], defaults: { path: "/", httpMethod: "GET", randomQuery: true } },
        { id: "stun", categoryId: "realtime", transport: "udp", port: 3478, rank: 1, label: "STUN", descriptor: "Binding Request with SOFTWARE attribute", fieldSet: ["host"] },
        { id: "dtls", categoryId: "realtime", transport: "udp", port: 443, rank: 2, label: "DTLS (WebRTC)", descriptor: "ClientHello-like DTLS datagram", fieldSet: ["host"] },
        { id: "sip", categoryId: "realtime", transport: "udp", port: 5060, rank: 3, label: "SIP", descriptor: "SIP request with randomized headers", fieldSet: ["host", "sipAction"], defaults: { sipAction: "OPTIONS" } },
        { id: "rtp", categoryId: "realtime", transport: "udp", port: 5004, rank: 4, label: "RTP", descriptor: "12-byte RTP header", fieldSet: [] },
        { id: "rtcp", categoryId: "realtime", transport: "udp", port: 5005, rank: 5, label: "RTCP", descriptor: "Receiver Report-like RTCP packet", fieldSet: [] },
        { id: "coap", categoryId: "iot", transport: "udp", port: 5683, rank: 1, label: "CoAP", descriptor: "CoAP request with Uri-Host and Uri-Path", fieldSet: ["host", "path", "coapMethod"], defaults: { path: "/", coapMethod: "GET" } },
        { id: "mqtt", categoryId: "iot", transport: "tcp", port: 1883, rank: 2, label: "MQTT", descriptor: "MQTT CONNECT packet", fieldSet: ["clientId"] },
        { id: "ntp", categoryId: "infra", transport: "udp", port: 123, rank: 1, label: "NTP", descriptor: "NTP v4 client request", fieldSet: [] },
        { id: "dhcp_discover", categoryId: "infra", transport: "udp", port: 67, rank: 2, label: "DHCP DISCOVER", descriptor: "DHCP DISCOVER packet", fieldSet: [] },
        { id: "snmp", categoryId: "infra", transport: "udp", port: 161, rank: 3, label: "SNMP", descriptor: "SNMP GET request", fieldSet: ["community", "oid"], defaults: { community: "public", oid: "1.3.6.1.2.1.1.1.0" } },
        { id: "syslog", categoryId: "infra", transport: "udp", port: 514, rank: 4, label: "Syslog", descriptor: "UDP syslog message", fieldSet: ["message", "syslogFacility", "syslogSeverity"], defaults: { message: "payloadgen test", syslogFacility: "user", syslogSeverity: "info" } },
        { id: "tftp", categoryId: "infra", transport: "udp", port: 69, rank: 5, label: "TFTP", descriptor: "TFTP RRQ request with negotiated option extensions", fieldSet: ["filename"], defaults: { filename: "test.bin" } },
        { id: "radius", categoryId: "infra", transport: "udp", port: 1812, rank: 6, label: "RADIUS", descriptor: "RADIUS Access-Request", fieldSet: ["username"], defaults: { username: "user" } },
        { id: "redis", categoryId: "messaging", transport: "tcp", port: 6379, rank: 1, label: "Redis RESP", descriptor: "RESP PING request", fieldSet: [] },
        { id: "postgresql", categoryId: "messaging", transport: "tcp", port: 5432, rank: 2, label: "PostgreSQL", descriptor: "PostgreSQL startup packet", fieldSet: ["username", "database"], defaults: { username: "postgres", database: "postgres" } },
        { id: "mysql", categoryId: "messaging", transport: "tcp", port: 3306, rank: 3, label: "MySQL", descriptor: "MySQL client command packet", fieldSet: ["username"], defaults: { username: "root" } },
        { id: "utp", categoryId: "p2p", transport: "udp", port: 6881, rank: 1, label: "uTP (BitTorrent)", descriptor: "20-byte SYN frame", fieldSet: [] },
        { id: "bittorrent_dht", categoryId: "p2p", transport: "udp", port: 6881, rank: 2, label: "BitTorrent DHT", descriptor: "BitTorrent DHT ping query", fieldSet: [] }
    ];
    var PROTOCOL_WIKI_URLS = {
        dns: "https://en.wikipedia.org/wiki/Domain_Name_System",
        mdns: "https://en.wikipedia.org/wiki/Multicast_DNS",
        ssdp: "https://en.wikipedia.org/wiki/Simple_Service_Discovery_Protocol",
        llmnr: "https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution",
        nbns: "https://en.wikipedia.org/wiki/NetBIOS_over_TCP/IP",
        quic: "https://en.wikipedia.org/wiki/QUIC",
        tls_client_hello: "https://en.wikipedia.org/wiki/Transport_Layer_Security",
        http2: "https://en.wikipedia.org/wiki/HTTP/2",
        http_browser: "https://en.wikipedia.org/wiki/HTTP",
        websocket: "https://en.wikipedia.org/wiki/WebSocket",
        curl: "https://en.wikipedia.org/wiki/CURL",
        stun: "https://en.wikipedia.org/wiki/STUN",
        dtls: "https://en.wikipedia.org/wiki/Datagram_Transport_Layer_Security",
        sip: "https://en.wikipedia.org/wiki/Session_Initiation_Protocol",
        rtp: "https://en.wikipedia.org/wiki/Real-time_Transport_Protocol",
        rtcp: "https://en.wikipedia.org/wiki/RTP_Control_Protocol",
        coap: "https://en.wikipedia.org/wiki/Constrained_Application_Protocol",
        mqtt: "https://en.wikipedia.org/wiki/MQTT",
        ntp: "https://en.wikipedia.org/wiki/Network_Time_Protocol",
        dhcp_discover: "https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol",
        snmp: "https://en.wikipedia.org/wiki/Simple_Network_Management_Protocol",
        syslog: "https://en.wikipedia.org/wiki/Syslog",
        tftp: "https://en.wikipedia.org/wiki/Trivial_File_Transfer_Protocol",
        radius: "https://en.wikipedia.org/wiki/RADIUS",
        redis: "https://en.wikipedia.org/wiki/Redis",
        postgresql: "https://en.wikipedia.org/wiki/PostgreSQL",
        mysql: "https://en.wikipedia.org/wiki/MySQL",
        utp: "https://en.wikipedia.org/wiki/Micro_Transport_Protocol",
        bittorrent_dht: "https://en.wikipedia.org/wiki/Mainline_DHT"
    };
    var DOMAIN_POOL = [
        "google.com", "youtube.com", "wikipedia.org", "amazon.com", "facebook.com", "reddit.com", "github.com",
        "microsoft.com", "apple.com", "cloudflare.com", "openai.com", "instagram.com", "linkedin.com", "bing.com",
        "netflix.com", "adobe.com", "paypal.com", "stackoverflow.com", "mozilla.org", "bbc.com", "cnn.com",
        "nytimes.com", "office.com", "whatsapp.com", "discord.com", "dropbox.com", "twitch.tv", "zoom.us",
        "spotify.com", "imdb.com"
    ];
    var IDS = {
        pageTitle: "page-title",
        pageIntro: "page-intro",
        donateButton: "donate-btn",
        blocksPanel: "blocks-panel",
        mtuLabel: "mtu-label",
        padMtuLabel: "pad-mtu-label",
        padMtuCheckbox: "pad-mtu-checkbox",
        outputLabel: "output-label",
        blocks: "payload-blocks",
        mtuInput: "mtu-input",
        output: "output-text",
        addButton: "add-payload-btn",
        generateButton: "generate-btn",
        copyButton: "copy-btn",
        resetButton: "reset-btn"
    };
    var SELECTORS = {
        payloadTitle: ".payload-title",
        payloadMeta: ".payload-meta",
        payloadProtocol: ".payload-protocol",
        payloadProtocolSummary: ".protocol-summary",
        payloadProtocolLink: ".protocol-link",
        payloadRemoveButton: ".remove-payload-btn",
        payloadDynamicFields: ".payload-dynamic-fields",
        payloadError: ".payload-error"
    };
    var CATEGORY_MAP = createMapById(CATEGORY_DEFS);
    var PROTOCOL_MAP = createMapById(PROTOCOL_CATALOG);
    var Generators = null;
    var dom = { initialized: false };

    function init() {
        if (dom.initialized || typeof document === "undefined") {
            return false;
        }

        ensureGenerators();
        dom.initialized = true;
        cacheDom();
        bindEvents();
        resetAll();
        applyCopy();
        maybeLoadChromeVersionInBackground();
        return true;
    }

    function ensureGenerators() {
        if (!Generators) {
            Generators = root.PayloadGenGenerators || (typeof require === "function" ? require("./generators.js") : null);
        }

        if (!Generators) {
            throw new Error("PayloadGenGenerators is required before initialization.");
        }

        return Generators;
    }

    function maybeLoadChromeVersionInBackground() {
        SharedData.loadChromeVersionData(CONFIG.browserDataUrl, 1500).then(function (updated) {
            if (updated) {
                refreshBrowserVersionDefaults();
            }
        }).catch(function () {
        });
    }

    function refreshBrowserVersionDefaults() {
        getBlocks().forEach(function (block) {
            var protocol = getProtocolMeta(block._state.protocolId);
            var refs;
            var input;

            if (!protocolUsesField(protocol, "browserVersion") ||
                Object.prototype.hasOwnProperty.call(block._state.values, "browserVersion")) {
                return;
            }

            refs = getBlockRefs(block);
            input = refs.dynamicFields.querySelector(".payload-field-browserVersion");

            if (input) {
                input.value = getChromeDefaultVersion();
            }
        });
    }

    function cacheDom() {
        Object.keys(IDS).forEach(function (key) {
            dom[key] = getRequiredElement(IDS[key]);
        });

        dom.metaDescription = document.querySelector('meta[name="description"]');
    }

    function bindEvents() {
        dom.addButton.addEventListener("click", handleAddBlock);
        dom.generateButton.addEventListener("click", function () { generateOutput(); });
        dom.copyButton.addEventListener("click", function () { copyOutput(); });
        dom.resetButton.addEventListener("click", function () { resetAll(); });
    }

    function applyCopy() {
        document.documentElement.lang = "en";
        document.title = UI.title;

        if (dom.metaDescription) {
            dom.metaDescription.setAttribute("content", UI.description);
        }

        setElementText(dom.pageTitle, UI.title);
        setElementHtml(dom.pageIntro, UI.introHtml);
        setElementText(dom.mtuLabel, UI.mtuLabel);
        setElementText(dom.padMtuLabel, UI.padMtuLabel);
        setElementText(dom.addButton, UI.addButton);
        setElementText(dom.generateButton, UI.generateButton);
        setElementText(dom.copyButton, UI.copyButton);
        setElementText(dom.resetButton, UI.resetButton);
        setElementText(dom.outputLabel, UI.outputLabel);
        dom.output.placeholder = UI.outputPlaceholder;
        dom.blocksPanel.setAttribute("aria-label", UI.blocksTitle);
        dom.donateButton.href = SharedData.DONATE_URL;
        dom.donateButton.setAttribute("aria-label", UI.donateButton);
        dom.donateButton.setAttribute("title", UI.donateButton);
        getBlocks().forEach(syncBlockUi);
        updateBlockUi();
    }

    function resetAll() {
        clearElement(dom.blocks);
        dom.output.value = "";
        dom.mtuInput.value = String(CONFIG.defaultMtu);
        dom.padMtuCheckbox.checked = false;
        addBlock(createDefaultBlockState("quic"));
        clearAllErrors();
    }

    function handleAddBlock() {
        if (getBlockCount() < CONFIG.maxBlocks) {
            addBlock(createDefaultBlockState("quic"));
        }
    }

    function createDefaultBlockState(protocolId) {
        return { protocolId: protocolId || "quic", values: {} };
    }

    function hydrateBlockState(rawState) {
        return {
            protocolId: isKnownProtocol(rawState && rawState.protocolId) ? rawState.protocolId : "quic",
            values: rawState && rawState.values && typeof rawState.values === "object" ? rawState.values : {}
        };
    }

    function addBlock(initialState) {
        dom.blocks.appendChild(createPayloadBlock(initialState));
        updateBlockUi();
    }

    function createPayloadBlock(initialState) {
        var block = createElement("article", { className: "payload-block" });
        var title = createElement("h3", { className: "payload-title" });
        var meta = createElement("p", { className: "payload-meta" });
        var protocolSelect = createElement("select", { className: "payload-protocol" });
        var protocolSummary = createElement("p", { className: "protocol-summary" });
        var protocolLink = createElement("a", { className: "protocol-link", href: "#", target: "_blank", rel: "noreferrer noopener" });
        var dynamicFields = createElement("div", { className: "field-grid payload-dynamic-fields" });
        var error = createElement("p", { className: "payload-error" });

        block._state = hydrateBlockState(initialState);
        error.setAttribute("aria-live", "polite");
        block.appendChild(createBlockHeader(block, title));
        block.appendChild(meta);
        block.appendChild(createElement("div", {
            className: "field-grid payload-static-fields",
            children: [createField(UI.protocolLabel, protocolSelect, "field")]
        }));
        block.appendChild(createElement("div", { className: "protocol-info", children: [protocolSummary, protocolLink] }));
        block.appendChild(dynamicFields);
        block.appendChild(error);

        protocolSelect.addEventListener("change", function () {
            block._state.protocolId = protocolSelect.value;
            syncBlockUi(block);
            clearBlockError(block);
        });

        syncBlockUi(block);
        return block;
    }

    function createBlockHeader(block, title) {
        var removeButton = createButton(UI.removeButton, "btn btn-ghost remove-payload-btn");

        removeButton.addEventListener("click", function () {
            block.remove();

            if (getBlockCount() === 0) {
                addBlock(createDefaultBlockState("quic"));
            }

            updateBlockUi();
        });

        return createElement("div", {
            className: "payload-block-header",
            children: [
                createElement("div", { className: "payload-title-wrap", children: [title] }),
                removeButton
            ]
        });
    }

    function syncBlockUi(block) {
        var refs = getBlockRefs(block);
        var availableProtocols = listProtocols();
        var protocol;

        if (!protocolListHasId(availableProtocols, block._state.protocolId)) {
            block._state.protocolId = availableProtocols[0].id;
        }

        protocol = getProtocolMeta(block._state.protocolId);
        fillProtocolSelect(refs.protocolSelect, availableProtocols, block._state.protocolId);
        clearElement(refs.dynamicFields);
        protocol.fieldSet.forEach(function (fieldId) {
            refs.dynamicFields.appendChild(createDynamicField(block, protocol, fieldId));
        });
        refs.protocolSelect.title = formatProtocolSummary(protocol);
        refs.protocolSummary.textContent = formatProtocolSummary(protocol);
        refs.protocolLink.textContent = UI.wikiLinkLabel;
        refs.protocolLink.href = PROTOCOL_WIKI_URLS[protocol.id] || "#";
        refs.protocolLink.title = formatProtocolSummary(protocol);
        refs.removeButton.textContent = UI.removeButton;
        refs.meta.textContent = "";
        refs.meta.hidden = true;
        updateBlockUi();
    }

    function createDynamicField(block, protocol, fieldId) {
        var fieldDef = FIELD_DEFS[fieldId];
        var value = getDisplayFieldValue(block, protocol, fieldId);
        var className = fieldDef.className || "field";
        var control;

        if (fieldId === "host") {
            return createHostField(block, value);
        }

        if (fieldDef.type === "checkbox") {
            control = createElement("input", { type: "checkbox", className: "payload-field payload-field-" + fieldId });
            control.checked = !!value;
            control.addEventListener("change", function () {
                setFieldValue(block, fieldId, control.checked);
                syncBlockUi(block);
                clearBlockError(block);
            });
            return createCheckboxField(fieldDef.label, control, "field checkbox-field");
        }

        if (fieldDef.type === "select") {
            control = createElement("select", { className: "payload-field payload-field-" + fieldId });
            fillSelectOptions(control, getFieldOptions(fieldDef.optionSet), String(value));
            control.addEventListener("change", function () {
                setFieldValue(block, fieldId, control.value);
                syncBlockUi(block);
                clearBlockError(block);
            });
            return createField(fieldDef.label, control, className);
        }

        if (fieldDef.type === "textarea") {
            control = createElement("textarea", {
                className: "payload-field payload-field-" + fieldId,
                rows: fieldDef.rows || 3,
                placeholder: fieldDef.placeholder || ""
            });
            control.spellcheck = !!fieldDef.spellcheck;
            control.value = String(value);
            control.addEventListener("input", function () {
                setFieldValue(block, fieldId, control.value);
                clearBlockError(block);
            });
            return createField(fieldDef.label, control, className);
        }

        control = createElement("input", {
            type: "text",
            className: "payload-field payload-field-" + fieldId,
            placeholder: fieldDef.placeholder || "",
            autocomplete: "off"
        });
        control.spellcheck = !!fieldDef.spellcheck;
        control.value = String(value);
        control.addEventListener("input", function () {
            setFieldValue(block, fieldId, control.value);
            clearBlockError(block);
        });
        return createField(fieldDef.label, control, className);
    }

    function createHostField(block, value) {
        var input = createElement("input", {
            type: "text",
            className: "payload-field payload-field-host",
            placeholder: FIELD_DEFS.host.placeholder,
            autocomplete: "off"
        });
        var randomButton = createButton("Random", "btn btn-ghost");

        input.spellcheck = !!FIELD_DEFS.host.spellcheck;
        input.value = String(value);
        input.addEventListener("input", function () {
            setFieldValue(block, "host", input.value);
            clearBlockError(block);
        });
        randomButton.addEventListener("click", function () {
            setFieldValue(block, "host", pickWeightedRankedDomain(DOMAIN_POOL));
            syncBlockUi(block);
            clearBlockError(block);
        });

        return createField("Domain", createElement("div", {
            className: "host-field-row",
            children: [input, createElement("div", { className: "host-field-actions", children: [randomButton] })]
        }), "field");
    }

    function setFieldValue(block, fieldId, value) {
        block._state.values[fieldId] = value;
    }

    function getDisplayFieldValue(block, protocol, fieldId) {
        if (Object.prototype.hasOwnProperty.call(block._state.values, fieldId)) {
            return block._state.values[fieldId];
        }

        if (fieldId === "browserVersion") {
            return getChromeDefaultVersion();
        }

        return getFieldDefault(protocol, fieldId);
    }

    function getFieldDefault(protocol, fieldId) {
        if (protocol.defaults && Object.prototype.hasOwnProperty.call(protocol.defaults, fieldId)) {
            return protocol.defaults[fieldId];
        }

        if (Object.prototype.hasOwnProperty.call(FIELD_DEFS[fieldId], "defaultValue")) {
            return FIELD_DEFS[fieldId].defaultValue;
        }

        return FIELD_DEFS[fieldId].type === "checkbox" ? false : "";
    }

    function getFieldOptions(optionSetId) {
        return OPTION_SETS[optionSetId] || [];
    }

    function fillSelectOptions(select, options, selectedValue) {
        clearElement(select);
        options.forEach(function (option) {
            select.appendChild(createElement("option", { value: String(option.value), textContent: option.label }));
        });
        select.value = String(selectedValue);
    }

    function fillProtocolSelect(select, protocols, selectedId) {
        clearElement(select);
        groupProtocolsByCategory(protocols).forEach(function (group) {
            var optgroup = createElement("optgroup", { label: CATEGORY_MAP[group.categoryId].label });

            group.protocols.forEach(function (protocol) {
                optgroup.appendChild(createElement("option", {
                    value: protocol.id,
                    textContent: protocol.id === "quic" ? protocol.label + " ★" : protocol.label,
                    title: protocol.descriptor
                }));
            });

            select.appendChild(optgroup);
        });
        select.value = selectedId;
    }

    function updateBlockUi() {
        var shouldHideRemove = getBlockCount() <= 1;

        getBlocks().forEach(function (block, index) {
            var refs = getBlockRefs(block);
            refs.title.textContent = UI.payloadTitle + " (i" + (index + 1) + ")";
            refs.removeButton.hidden = shouldHideRemove;
        });

        dom.addButton.disabled = getBlockCount() >= CONFIG.maxBlocks;
    }

    function generateOutput() {
        var mtu = normalizeMtu(dom.mtuInput.value);
        var padMtu = !!dom.padMtuCheckbox.checked;
        var lines = [];
        var capped = false;
        var hasAsyncProtocols = false;

        clearAllErrors();

        getBlocks().forEach(function (block) {
            if (block._state.protocolId === "quic" && shouldUseAsyncQuicOutput(collectProtocolOptions(block))) {
                hasAsyncProtocols = true;
            }
        });

        if (hasAsyncProtocols && typeof ensureGenerators().generatePayloadAsync === "function") {
            generateOutputAsync().then(function (result) {
                dom.output.value = result.lines.join("\n");
            }).catch(function (error) {
                console.error("Async generation failed:", error);
            });

            return { mtu: mtu, lines: [], capped: false, pending: true };
        }

        getBlocks().forEach(function (block) {
            if (lines.length >= CONFIG.maxOutputLines) {
                capped = true;
                return;
            }

            try {
                capped = appendBlockLines(lines, block, mtu, padMtu) || capped;
            } catch (error) {
                setBlockError(block, error && error.message ? error.message : "Failed to generate this payload.");
            }
        });

        dom.output.value = lines.join("\n");
        return { mtu: mtu, lines: lines, capped: capped };
    }

    async function generateOutputAsync() {
        var mtu = normalizeMtu(dom.mtuInput.value);
        var padMtu = !!dom.padMtuCheckbox.checked;
        var lines = [];
        var capped = false;
        var blocks = getBlocks();
        var index;

        clearAllErrors();

        for (index = 0; index < blocks.length; index += 1) {
            if (lines.length >= CONFIG.maxOutputLines) {
                capped = true;
                break;
            }

            try {
                capped = await appendBlockLinesAsync(lines, blocks[index], mtu, padMtu) || capped;
            } catch (error) {
                setBlockError(blocks[index], error && error.message ? error.message : "Failed to generate this payload.");
            }
        }

        return { mtu: mtu, lines: lines, capped: capped };
    }

    function appendBlockLines(lines, block, mtu, padMtu) {
        return appendChunkLines(lines, chunkPayload(ensureGenerators().generatePayload(block._state.protocolId, collectProtocolOptions(block)), mtu, padMtu));
    }

    async function appendBlockLinesAsync(lines, block, mtu, padMtu) {
        var generators = ensureGenerators();
        var options = collectProtocolOptions(block);
        var payloadBytes = block._state.protocolId === "quic" && shouldUseAsyncQuicOutput(options) && typeof generators.generatePayloadAsync === "function"
            ? await generators.generatePayloadAsync(block._state.protocolId, options)
            : generators.generatePayload(block._state.protocolId, options);

        return appendChunkLines(lines, chunkPayload(payloadBytes, mtu, padMtu));
    }

    function collectProtocolOptions(block) {
        var protocol = getProtocolMeta(block._state.protocolId);
        var options = {};

        protocol.fieldSet.forEach(function (fieldId) {
            var value = Object.prototype.hasOwnProperty.call(block._state.values, fieldId) ? block._state.values[fieldId] : getFieldDefault(protocol, fieldId);

            if (fieldId === "host") {
                options.host = normalizeHost(value);
            } else if (fieldId === "path") {
                options.path = normalizePath(value);
            } else if (FIELD_DEFS[fieldId].type === "checkbox") {
                options[fieldId] = !!value;
            } else {
                options[fieldId] = String(value);
            }
        });

        if (protocolUsesField(protocol, "browserVersion") && !options.browserVersion) {
            options.browserVersion = getChromeDefaultVersion();
        }

        if (protocol.id === "quic") {
            options.quicEncrypt = true;
        }

        return options;
    }

    function appendChunkLines(lines, chunks) {
        var wasCapped = false;
        var index;

        for (index = 0; index < chunks.length; index += 1) {
            if (lines.length >= CONFIG.maxOutputLines) {
                wasCapped = true;
                break;
            }

            lines.push("i" + (lines.length + 1) + "=<b 0x" + bytesToHex(chunks[index]) + ">");
        }

        return wasCapped;
    }

    function shouldUseAsyncQuicOutput(options) {
        return !!(options && options.quicEncrypt);
    }

    function copyOutput() {
        var content = dom.output.value.trim();

        if (!content) {
            content = generateOutput().lines.join("\n");
        }

        if (!content) {
            return Promise.resolve(false);
        }

        if (typeof navigator !== "undefined" &&
            navigator.clipboard &&
            typeof navigator.clipboard.writeText === "function" &&
            typeof isSecureContext !== "undefined" &&
            isSecureContext) {
            return navigator.clipboard.writeText(content).then(function () { return true; }).catch(function () { return false; });
        }

        return new Promise(function (resolve) {
            try {
                dom.output.focus();
                dom.output.select();
                dom.output.setSelectionRange(0, dom.output.value.length);
                resolve(!!(typeof document !== "undefined" && typeof document.execCommand === "function" && document.execCommand("copy")));
            } catch (error) {
                resolve(false);
            }
        });
    }

    function getBlocks() {
        return Array.prototype.slice.call(dom.blocks.children);
    }

    function getBlockCount() {
        return dom.blocks ? dom.blocks.children.length : 0;
    }

    function getBlockRefs(block) {
        return {
            title: block.querySelector(SELECTORS.payloadTitle),
            meta: block.querySelector(SELECTORS.payloadMeta),
            protocolSelect: block.querySelector(SELECTORS.payloadProtocol),
            protocolSummary: block.querySelector(SELECTORS.payloadProtocolSummary),
            protocolLink: block.querySelector(SELECTORS.payloadProtocolLink),
            removeButton: block.querySelector(SELECTORS.payloadRemoveButton),
            dynamicFields: block.querySelector(SELECTORS.payloadDynamicFields),
            error: block.querySelector(SELECTORS.payloadError)
        };
    }

    function clearAllErrors() {
        getBlocks().forEach(clearBlockError);
    }

    function clearBlockError(block) {
        getBlockRefs(block).error.textContent = "";
    }

    function setBlockError(block, message) {
        getBlockRefs(block).error.textContent = message;
    }

    function normalizeMtu(rawValue) {
        var mtu = parseInt(String(rawValue || "").trim(), 10);

        if (!Number.isFinite(mtu) || mtu < 1) {
            mtu = CONFIG.defaultMtu;
        }

        dom.mtuInput.value = String(mtu);
        return mtu;
    }

    function normalizeHost(rawValue) {
        var host = String(rawValue || "").trim();
        return host || CONFIG.defaultHost;
    }

    function normalizePath(rawValue) {
        var path = String(rawValue || "").trim();
        return !path ? "/" : (path.charAt(0) === "/" ? path : "/" + path);
    }

    function getChromeDefaultVersion() {
        return SharedData.CHROME_BROWSER_DATA.defaultVersion;
    }

    function listProtocols() {
        return PROTOCOL_CATALOG.slice().sort(function (left, right) {
            var categoryCompare = CATEGORY_MAP[left.categoryId].rank - CATEGORY_MAP[right.categoryId].rank;
            return categoryCompare || left.rank - right.rank || left.label.localeCompare(right.label);
        });
    }

    function groupProtocolsByCategory(protocols) {
        return CATEGORY_DEFS.slice().sort(function (left, right) {
            return left.rank - right.rank;
        }).map(function (category) {
            return {
                categoryId: category.id,
                protocols: protocols.filter(function (protocol) {
                    return protocol.categoryId === category.id;
                })
            };
        }).filter(function (group) {
            return group.protocols.length > 0;
        });
    }

    function protocolListHasId(protocols, protocolId) {
        return protocols.some(function (protocol) { return protocol.id === protocolId; });
    }

    function pickWeightedRankedDomain(domains) {
        var totalWeight = 0;
        var roll;
        var index;

        if (!domains || !domains.length) {
            return CONFIG.defaultHost;
        }

        for (index = 0; index < domains.length; index += 1) {
            totalWeight += domains.length - index;
        }

        roll = Math.floor(Math.random() * Math.max(1, totalWeight));

        for (index = 0; index < domains.length; index += 1) {
            roll -= domains.length - index;
            if (roll < 0) {
                return domains[index];
            }
        }

        return domains[0];
    }

    function isKnownProtocol(protocolId) {
        return Object.prototype.hasOwnProperty.call(PROTOCOL_MAP, protocolId);
    }

    function getProtocolMeta(protocolId) {
        return PROTOCOL_MAP[protocolId] || PROTOCOL_CATALOG[0];
    }

    function protocolUsesField(protocol, fieldId) {
        return protocol.fieldSet.indexOf(fieldId) !== -1;
    }

    function createMapById(items) {
        return items.reduce(function (map, item) {
            map[item.id] = item;
            return map;
        }, {});
    }

    function createField(label, control, className) {
        return createElement("label", {
            className: className,
            children: [createElement("span", { className: "field-label", textContent: label }), control]
        });
    }

    function createCheckboxField(label, control, className) {
        return createElement("label", {
            className: className,
            children: [
                createElement("span", {
                    className: "checkbox-row",
                    children: [control, createElement("span", { className: "checkbox-label", textContent: label })]
                })
            ]
        });
    }

    function createButton(label, className) {
        return createElement("button", { type: "button", className: className, textContent: label });
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
        var slice;
        var padded;

        if (payloadBytes.length === 0) {
            return padMtu ? [new Uint8Array(mtu)] : [payloadBytes];
        }

        while (offset < payloadBytes.length) {
            slice = payloadBytes.slice(offset, Math.min(offset + mtu, payloadBytes.length));

            if (padMtu && slice.length < mtu) {
                padded = new Uint8Array(mtu);
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
        var value;

        for (index = 0; index < bytes.length; index += 1) {
            value = bytes[index].toString(16);
            hex += value.length === 1 ? "0" + value : value;
        }

        return hex;
    }

    function formatProtocolSummary(protocol) {
        var transport = protocol.transport === "tcp" ? "TCP" : "UDP";
        var summary = String(protocol.descriptor || "").trim();
        var portInfo = protocol.port ? "port: " + protocol.port + " | " : "";

        if (summary && summary.charAt(summary.length - 1) !== ".") {
            summary += ".";
        }

        return transport + " | " + portInfo + summary;
    }

    return {
        init: init,
        constants: {
            MAX_BLOCKS: CONFIG.maxBlocks,
            MAX_OUTPUT_LINES: CONFIG.maxOutputLines,
            DEFAULT_MTU: CONFIG.defaultMtu,
            DEFAULT_HOST: CONFIG.defaultHost,
            CATEGORY_DEFS: CATEGORY_DEFS,
            DOMAIN_SNAPSHOTS: { global: DOMAIN_POOL.slice() },
            PROTOCOL_CATALOG: PROTOCOL_CATALOG
        },
        catalog: {
            categories: CATEGORY_DEFS,
            protocols: PROTOCOL_CATALOG,
            listProtocols: listProtocols
        },
        helpers: {
            bytesToHex: bytesToHex,
            chunkPayload: chunkPayload,
            pickWeightedRankedDomain: pickWeightedRankedDomain
        },
        generators: {
            generatePayload: function (protocolId, options) {
                return ensureGenerators().generatePayload(protocolId, options);
            }
        }
    };
}));
