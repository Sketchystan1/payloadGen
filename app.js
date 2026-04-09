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
        minMtu: 1280,
        maxMtu: 1450,
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
    var PROTOCOL_SELECT_PROTOCOL_PREFIX = "protocol:";
    var PROTOCOL_SELECT_PRESET_PREFIX = "preset:";
    var activePresetId = "";
    var UI = {
        protocolPresetHint: "Presets:",
        protocolOptionHint: "Options:",
        protocolPresetHintDescription: "Leave unchecked to use the recommended default.",
        presetActiveLabel: "Preset active:",
        presetDialogTitle: "Keep only this block?",
        presetDialogMessage: "The active %PRESET% preset includes multiple blocks. Remove the other preset blocks and continue with this block only?",
        presetDialogYesButton: "Yes, remove the rest",
        presetDialogNoButton: "No, keep all blocks",
        presetsOptionsGroup: "Presets:",
        bestOptionsGroup: "Works:",
        recommendedOptionsGroup: "Kinda:",
        unconfirmedOptionsGroup: "Lab:",
        removeButton: "Remove",
        protocolLabel: "Protocol",
        customHostLabel: "Domain"
    };
    var CATEGORY_PROVIDERS = {
        best: [
            { label: "Proton", icon: "icons/proton.svg" },
            { label: "Cloudflare", icon: "icons/cloudflare.svg" }
        ],
        recommended: [
            { label: "Cloudflare", icon: "icons/cloudflare.svg" }
        ],
        unconfirmed: []
    };
    var OPTION_SETS = {
        sipActions: [
            { value: "OPTIONS", label: "OPTIONS" },
            { value: "REGISTER", label: "REGISTER" },
            { value: "INVITE", label: "INVITE" },
            { value: "TRYING", label: "TRYING" },
            { value: "RANDOM", label: "RANDOM" }
        ],
        coapMethods: [
            { value: "GET", label: "GET" },
            { value: "POST", label: "POST" },
            { value: "PUT", label: "PUT" },
            { value: "DELETE", label: "DELETE" }
        ],
        coapMessageTypes: [
            { value: "AUTO", label: "Auto" },
            { value: "CON", label: "CON" },
            { value: "NON", label: "NON" }
        ],
        coapMediaTypes: [
            { value: "auto", label: "Auto" },
            { value: "json", label: "application/json (50)" },
            { value: "cbor", label: "application/cbor (60)" },
            { value: "senml_json", label: "application/senml+json (110)" },
            { value: "senml_cbor", label: "application/senml+cbor (112)" },
            { value: "text", label: "text/plain;charset=utf-8 (0)" },
            { value: "link", label: "application/link-format (40)" },
            { value: "octets", label: "application/octet-stream (42)" }
        ],
        coapBlockModes: [
            { value: "auto", label: "Auto" },
            { value: "none", label: "None" },
            { value: "block1", label: "Block1" },
            { value: "block2", label: "Block2" }
        ],
        tlsAlpn: [{ value: "http/1.1", label: "http/1.1" }, { value: "h2", label: "h2" }],
        iceProviders: [
            { value: "google", label: "Google" },
            { value: "twilio", label: "Twilio" },
            { value: "cloudflare", label: "Cloudflare" },
            { value: "meta", label: "Meta" },
            { value: "random", label: "Random" }
        ],
        iceModes: [
            { value: "binding", label: "Binding" },
            { value: "allocate", label: "Allocate" },
            { value: "auto", label: "Auto" }
        ]
    };
    var FIELD_DEFS = {
        host: { type: "text", label: "Domain", placeholder: "example.com", spellcheck: false, className: "field span-12" },
        padMtu: { type: "checkbox", label: "Padding", defaultValue: false, className: "span-12" },
        path: { type: "text", label: "Path", placeholder: "/", defaultValue: "/", spellcheck: false, className: "field span-12" },
        sipAction: { type: "select", label: "Message", optionSet: "sipActions", defaultValue: "OPTIONS", className: "field span-6" },
        sipCustomMessage: { type: "checkbox", label: "Message", defaultValue: false, className: "span-6" },
        coapMethod: { type: "select", label: "Method", optionSet: "coapMethods", defaultValue: "GET", className: "field span-6" },
        coapMessageType: { type: "select", label: "Type", optionSet: "coapMessageTypes", defaultValue: "AUTO", className: "field span-6" },
        coapMediaType: { type: "select", label: "Media", optionSet: "coapMediaTypes", defaultValue: "auto", className: "field span-6" },
        coapBlockMode: { type: "select", label: "Blockwise", optionSet: "coapBlockModes", defaultValue: "auto", className: "field span-6" },
        coapObserve: { type: "checkbox", label: "Observe", defaultValue: false, className: "span-6" },
        randomQuery: { type: "checkbox", label: "Random Query", defaultValue: true, className: "span-6" },
        database: { type: "text", label: "Database", spellcheck: false, className: "field span-6" },
        clientId: { type: "text", label: "Client ID", spellcheck: false, className: "field span-6" },
        tlsAlpn: { type: "select", label: "ALPN", optionSet: "tlsAlpn", defaultValue: "h2", className: "field span-6" },
        browserVersion: { type: "text", label: "Version", spellcheck: false, className: "field span-6" },
        iceProvider: { type: "select", label: "Provider", optionSet: "iceProviders", defaultValue: "google", className: "field span-6" },
        iceMode: { type: "select", label: "Mode", optionSet: "iceModes", defaultValue: "auto", className: "field span-6" },
        iceServerHost: {
            type: "text",
            label: "Domain",
            placeholder: "leave blank to use provider pool",
            spellcheck: false,
            className: "field span-12"
        }
    };
    var PROTOCOL_CATALOG = [
        { id: "bittorrent_dht", label: "BitTorrent (DHT)", fieldSet: [], hidden: true },
        {
            id: "coap",
            label: "CoAP",
            fieldSet: ["host", "path", "coapMethod", "coapMessageType", "coapMediaType", "coapBlockMode", "coapObserve"],
            defaults: { path: "/", coapMethod: "GET", coapMessageType: "AUTO", coapMediaType: "auto", coapBlockMode: "auto", coapObserve: false },
            hidden: true
        },
        { id: "curl_quic", label: "cURL", fieldSet: ["host", "padMtu"], defaults: { padMtu: false } },
        { id: "dhcp_discover", label: "DHCP DISCOVER", fieldSet: [], hidden: true },
        { id: "dns", label: "DNS", fieldSet: ["host"], defaults: { customHost: false } },
        { id: "dtls", label: "DTLS", fieldSet: ["host"], hidden: true },
        { id: "llmnr", label: "LLMNR", fieldSet: ["host"], hidden: true },
        { id: "mdns", label: "mDNS", fieldSet: ["host"], hidden: true },
        { id: "nbns", label: "NBNS", fieldSet: ["host"], hidden: true },
        { id: "ntp", label: "NTP", fieldSet: [] },
        { id: "quic", label: "QUIC", fieldSet: ["host", "padMtu"], defaults: { padMtu: false } },
        { id: "rtcp", label: "RTCP", fieldSet: [], hidden: true },
        { id: "rtp", label: "RTP", fieldSet: [] },
        { id: "sip", label: "SIP", fieldSet: ["host", "sipCustomMessage"], defaults: { sipAction: "OPTIONS", sipCustomMessage: false, customHost: false } },
        { id: "ssdp", label: "SSDP", fieldSet: [] },
        {
            id: "stun",
            label: "STUN",
            fieldSet: ["iceProvider", "iceMode", "iceServerHost"],
            defaults: { iceProvider: "random", iceMode: "auto", iceServerHost: "", customIceServerHost: false, customIceProvider: false, customIceMode: false }
        },
        {
            id: "webrtc_combined",
            label: "WebRTC",
            fieldSet: ["iceProvider", "iceServerHost"],
            defaults: { iceProvider: "random", iceServerHost: "", customIceServerHost: false, customIceProvider: false }
        },
        { id: "utp", label: "BitTorrent (uTP)", fieldSet: [], hidden: true }
    ];
    var BLOCK_PRESETS = [
        {
            id: "sip_register_trying",
            label: "SIP: reg, try (preset)",
            description: "SIP REGISTER + TRYING",
            blocks: [
                { protocol: "sip", values: { sipAction: "REGISTER", sipCustomMessage: true } },
                { protocol: "sip", values: { sipAction: "TRYING", sipCustomMessage: true } }
            ]
        }
    ];
    var PRESET_MAP = createMapById(BLOCK_PRESETS);
    var PRESET_PROTOCOL_HINTS = createPresetProtocolMap(BLOCK_PRESETS);
    var DOMAIN_POOL = [
        "google.com", "amazon.com", "reddit.com", "github.com", "mozilla.org",
        "microsoft.com", "apple.com", "cloudflare.com", "bing.com", "adobe.com", "stackoverflow.com", 
        "office.com", "dropbox.com", "zoom.us", "spotify.com", "imdb.com", 
        "wikipedia.org", "yandex.ru", "ozon.ru", "vk.com", "google.com", "gismeteo.ru", "mail.ru", 
        "kinopoisk.ru", "pinterest.com", "dzen.ru", "rutube.ru", "gdz.ru", "apple.com", "rbc.ru", 
        "wildberries.ru", "asna.ru", "ya.ru", "vidal.ru", "banki.ru", "sberbank.ru", "ria.ru", "tbank.ru", 
        "championat.com", "fandom.com", "rambler.ru", "kp.ru", "dns-shop.ru", "russianfood.com", "eapteka.ru",
        "chatgpt.com", "avito.ru", "2gis.ru", "cbr.ru", "ivi.ru", "gosuslugi.ru", "pozdravok.com",
        "microsoft.com", "kino-teatr.ru", "consultant.ru", "lenta.ru", "auto.ru", "smclinic.ru", 
        "steampowered.com", "funpay.com", "rustore.ru", "okko.tv", "domclick.ru", "sports.ru", "cian.ru", 
        "drom.ru", "investing.com", "gastronom.ru", "24smi.org", "sravni.ru", "iamcook.ru", "vseinstrumenti.ru", 
        "planetazdorovo.ru", "wiktionary.org", "soccer365.ru", "aviasales.ru", "sovcombank.ru", "irecommend.ru",
        "sportbox.ru", "freepik.com", "gemotest.ru", "invitro.ru", "github.com", "tutu.ru", "skysmart.ru", "vtb.ru", 
        "goldapple.ru", "ok.ru", "kareliameteo.ru", "pikabu.ru", "deepl.com", "meteoinfo.ru", "tripadvisor.ru", 
        "iz.ru", "megapteka.ru", "apteka.ru", "reverso.net", "hh.ru", "primpogoda.ru", "habr.com", 
        "gdz-raketa.ru", "uchi.ru", "lamoda.ru", "deti-online.com", "promokodi.net", "gorzdrav.org", 
        "uiscom.ru", "primbank.ru"
    ];
    var IDS = {
        donateButton: "donate-btn",
        blocksStatus: "blocks-status",
        presetDialogBackdrop: "preset-dialog-backdrop",
        presetDialog: "preset-dialog",
        presetDialogTitle: "preset-dialog-title",
        presetDialogMessage: "preset-dialog-message",
        presetDialogNoButton: "preset-dialog-no-btn",
        presetDialogYesButton: "preset-dialog-yes-btn",
        blocks: "payload-blocks",
        output: "output-text",
        addButton: "add-payload-btn",
        generateButton: "generate-btn",
        copyButton: "copy-btn",
        resetButton: "reset-btn"
    };
    var SELECTORS = {
        blockTitleText: ".block-title-text",
        payloadProtocol: ".payload-protocol",
        payloadProtocolHint: ".payload-protocol-hint",
        payloadRemoveButton: ".remove-payload-btn",
        payloadDynamicFields: ".payload-dynamic-fields",
        payloadError: ".payload-error"
    };
    var PROTOCOL_MAP = createMapById(PROTOCOL_CATALOG);
    var Generators = null;
    var dom = { initialized: false };
    var blockUidCounter = 0;
    var presetDialogResolver = null;
    var presetDialogReturnFocus = null;
    var sharedMtu = CONFIG.defaultMtu;
    var outputGenerationToken = 0;

    function init() {
        if (dom.initialized || typeof document === "undefined") {
            return false;
        }

        ensureGenerators();
        dom.initialized = true;
        cacheDom();
        bindEvents();
        resetAll();
        syncUiState();
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
    }

    function bindEvents() {
        dom.addButton.addEventListener("click", handleAddBlock);
        dom.generateButton.addEventListener("click", function () { generateOutput(); });
        dom.copyButton.addEventListener("click", function () { copyOutput(); });
        dom.resetButton.addEventListener("click", function () { resetAll(); });
        dom.presetDialogYesButton.addEventListener("click", function () { resolvePresetBlockDialog(true); });
        dom.presetDialogNoButton.addEventListener("click", function () { resolvePresetBlockDialog(false); });
        dom.presetDialogBackdrop.addEventListener("click", function (event) {
            if (event.target === dom.presetDialogBackdrop) {
                resolvePresetBlockDialog(false);
            }
        });
        document.addEventListener("keydown", handleDocumentKeydown);
    }

    function loadPresetById(presetId) {
        var preset = PRESET_MAP[presetId];

        if (!preset) {
            return;
        }

        invalidateGeneratedOutput();
        setActivePresetId(preset.id);
        clearElement(dom.blocks);
        clearAllErrors();

        buildPresetStates(preset).forEach(function (state) {
            addBlock(state);
        });
    }

    function buildPresetStates(preset) {
        var sharedSipHost = preset.blocks.some(function (blockDef) {
            return blockDef.protocol === "sip";
        }) ? buildRandomPresetSipHost() : "";

        return preset.blocks.map(function (blockDef) {
            var protocol = getProtocolMeta(blockDef.protocol);
            var values = Object.assign({}, protocol.defaults || {}, blockDef.values || {});

            if (blockDef.protocol === "sip" && !normalizeOptionalHost(values.host)) {
                values.host = sharedSipHost;
            }

            return {
                protocolId: protocol.id,
                values: values
            };
        });
    }

    function buildRandomPresetSipHost() {
        var baseDomain = pickWeightedRankedDomain(DOMAIN_POOL);
        var shouldUseSipSubdomain = Math.random() < 0.65;

        if (!shouldUseSipSubdomain) {
            return baseDomain;
        }

        return "sip-" + (10 + Math.floor(Math.random() * 90)) + "." + baseDomain;
    }

    function getPresetMeta(presetId) {
        return presetId && PRESET_MAP[presetId] ? PRESET_MAP[presetId] : null;
    }

    function listPresets() {
        return BLOCK_PRESETS.slice();
    }

    function syncUiState() {
        syncActivePresetStatus();
        syncPresetDialogCopy();
        syncCopyButtonVisibility();
        dom.donateButton.href = SharedData.DONATE_URL;
        getBlocks().forEach(syncBlockUi);
        updateBlockUi();
    }

    function resetAll() {
        setActivePresetId("");
        invalidateGeneratedOutput();
        clearElement(dom.blocks);
        setSharedMtu(sharedMtu);
        addBlock(createDefaultBlockState("quic"));
        clearAllErrors();
    }

    function handleAddBlock() {
        if (getBlockCount() < CONFIG.maxBlocks) {
            invalidateGeneratedOutput();
            clearActivePreset();
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
        var title = createElement("h3", { className: "block-title" });
        var titleText = createElement("span", { className: "block-title-text" });
        var titleActions = createElement("div", { className: "block-title-actions" });
        var removeButton = createButton(UI.removeButton, "btn btn-ghost remove-payload-btn");
        var protocolSelect = createElement("select", { className: "payload-protocol" });
        var protocolHint = createElement("div", { className: "blocks-hint payload-protocol-hint", hidden: true });
        var dynamicFields = createElement("div", { className: "payload-dynamic-fields" });
        var errorField = createElement("p", { className: "payload-error", hidden: true });

        removeButton.addEventListener("click", function () {
            invalidateGeneratedOutput();
            block.remove();
            clearActivePreset();

            if (getBlockCount() === 0) {
                addBlock(createDefaultBlockState("quic"));
            }

            updateBlockUi();
        });

        block._state = hydrateBlockState(initialState);
        block._uid = nextBlockUid();
        assignControlIdentity(protocolSelect, block, "protocol");
        protocolSelect.setAttribute("aria-label", UI.protocolLabel);
        title.appendChild(titleText);
        titleActions.appendChild(protocolSelect);
        titleActions.appendChild(removeButton);
        title.appendChild(titleActions);
        block.appendChild(title);
        block.appendChild(protocolHint);
        block.appendChild(dynamicFields);
        block.appendChild(errorField);

        protocolSelect.addEventListener("change", async function () {
            var selection = parseProtocolSelectValue(protocolSelect.value);
            var shouldKeepOnlyEditedBlock = false;

            invalidateGeneratedOutput();

            if (selection.kind === "preset") {
                loadPresetById(selection.id);
                return;
            }

            if (block._state.protocolId !== selection.id) {
                shouldKeepOnlyEditedBlock = await confirmPresetBlockIsolation(protocolSelect);

                if (shouldKeepOnlyEditedBlock) {
                    removeOtherBlocks(block);
                }

                clearActivePreset();
                clearProtocolDomainMemory(block);
            }

            block._state.protocolId = selection.id;
            syncBlockUi(block);
            clearBlockError(block);
        });

        syncBlockUi(block);
        return block;
    }

    function syncBlockUi(block) {
        var refs = getBlockRefs(block);
        var availableProtocols = listProtocols();
        var protocol;

        if (!protocolListHasId(availableProtocols, block._state.protocolId)) {
            block._state.protocolId = availableProtocols[0].id;
        }

        protocol = getProtocolMeta(block._state.protocolId);
        ensureProtocolUiState(block, protocol);
        fillProtocolSelect(refs.protocolSelect, availableProtocols, BLOCK_PRESETS, block._state.protocolId);
        syncProtocolPresetState(refs.protocolSelect, block._state.protocolId);
        syncProtocolHint(block);
        clearElement(refs.dynamicFields);
        protocol.fieldSet.forEach(function (fieldId) {
            refs.dynamicFields.appendChild(createDynamicField(block, protocol, fieldId));
        });
        refs.removeButton.textContent = UI.removeButton;
        updateBlockUi();
    }

    function createDynamicField(block, protocol, fieldId) {
        var fieldDef = FIELD_DEFS[fieldId];
        var value = getDisplayFieldValue(block, protocol, fieldId);
        var className = fieldDef.className || "field span-6";
        var control;
        var controlIdentity;

        if (fieldId === "host" || (fieldId === "iceServerHost" && (protocol.id === "stun" || protocol.id === "webrtc_combined"))) {
            return createOptionalHostField(block, protocol, fieldId, value);
        }

        if ((fieldId === "iceProvider" || fieldId === "iceMode") && (protocol.id === "stun" || protocol.id === "webrtc_combined")) {
            return createOptionalSelectField(block, protocol, fieldId, value);
        }

        if (fieldId === "sipCustomMessage") {
            return createSipMessageField(block, protocol, value);
        }

        if (fieldId === "padMtu" && isQuicLikeProtocolId(protocol.id)) {
            return createPaddingField(block, protocol, value);
        }

        if (fieldDef.type === "checkbox") {
            control = createElement("input", { type: "checkbox", className: "payload-field payload-field-" + fieldId });
            controlIdentity = assignControlIdentity(control, block, fieldId);
            control.checked = !!value;
            control.addEventListener("change", function () {
                setFieldValue(block, fieldId, control.checked);
                syncBlockUi(block);
                clearBlockError(block);
            });
            return createCheckboxField(fieldDef.label, control, "field checkbox-field " + (fieldDef.className || "span-6"), controlIdentity.id);
        }

        if (fieldDef.type === "select") {
            control = createElement("select", { className: "payload-field payload-field-" + fieldId });
            controlIdentity = assignControlIdentity(control, block, fieldId);
            fillSelectOptions(control, getFieldOptions(fieldDef.optionSet), String(value));
            control.addEventListener("change", function () {
                setFieldValue(block, fieldId, control.value);
                syncBlockUi(block);
                clearBlockError(block);
            });
            return createField(fieldDef.label, control, className, controlIdentity.id);
        }

        if (fieldDef.type === "number") {
            control = createElement("input", {
                type: "number",
                className: "payload-field payload-field-" + fieldId + (fieldDef.inputClassName ? " " + fieldDef.inputClassName : ""),
                min: String(fieldDef.min),
                max: String(fieldDef.max),
                step: String(fieldDef.step || 1),
                inputMode: fieldDef.inputMode || "numeric"
            });
            controlIdentity = assignControlIdentity(control, block, fieldId);
            control.value = String(resolveMtuValue(value));
            syncMtuInputWidth(control);
            control.addEventListener("input", function () {
                syncMtuInputWidth(control);
                setFieldValue(block, fieldId, control.value);
                clearBlockError(block);
            });
            control.addEventListener("change", function () {
                control.value = String(resolveMtuValue(control.value));
                syncMtuInputWidth(control);
                setFieldValue(block, fieldId, control.value);
                clearBlockError(block);
            });
            return createField(fieldDef.label, control, className, controlIdentity.id);
        }

        if (fieldDef.type === "textarea") {
            control = createElement("textarea", {
                className: "payload-field payload-field-" + fieldId,
                rows: fieldDef.rows || 3,
                placeholder: fieldDef.placeholder || ""
            });
            controlIdentity = assignControlIdentity(control, block, fieldId);
            control.spellcheck = !!fieldDef.spellcheck;
            control.value = String(value);
            control.addEventListener("input", function () {
                setFieldValue(block, fieldId, control.value);
                clearBlockError(block);
            });
            return createField(fieldDef.label, control, className, controlIdentity.id);
        }

        control = createElement("input", {
            type: "text",
            className: "payload-field payload-field-" + fieldId,
            placeholder: fieldDef.placeholder || "",
            autocomplete: "off"
        });
        controlIdentity = assignControlIdentity(control, block, fieldId);
        control.spellcheck = !!fieldDef.spellcheck;
        control.value = String(value);
        control.addEventListener("input", function () {
            setFieldValue(block, fieldId, control.value);
            clearBlockError(block);
        });
        return createField(fieldDef.label, control, className, controlIdentity.id);
    }

    function getOptionalHostToggleFieldId(fieldId) {
        if (fieldId === "host") {
            return "customHost";
        }

        return "custom" + String(fieldId || "").charAt(0).toUpperCase() + String(fieldId || "").slice(1);
    }

    function isOptionalHostEnabled(block, protocol, fieldId) {
        var toggleFieldId = getOptionalHostToggleFieldId(fieldId);

        if (Object.prototype.hasOwnProperty.call(block._state.values, toggleFieldId)) {
            return !!block._state.values[toggleFieldId];
        }

        if (protocol && protocol.defaults && protocol.defaults[toggleFieldId] === false) {
            return false;
        }

        return normalizeOptionalHost(block._state.values[fieldId]) !== "" && !isQuicLikeProtocolId(protocol && protocol.id ? protocol.id : "");
    }

    function createOptionalHostField(block, protocol, fieldId, value) {
        var toggleFieldId = getOptionalHostToggleFieldId(fieldId);
        var customHostToggle = createElement("input", {
            type: "checkbox",
            className: "payload-field payload-field-" + toggleFieldId
        });
        var input = createElement("input", {
            type: "text",
            className: "payload-field payload-field-" + fieldId,
            placeholder: FIELD_DEFS[fieldId].placeholder,
            autocomplete: "off",
            "aria-label": FIELD_DEFS[fieldId].label
        });
        var isSipProtocol = protocol && protocol.id === "sip" && fieldId === "host";
        var randomButton = isSipProtocol ? null : createButton("Random", "btn btn-ghost");
        var customHostIdentity = assignControlIdentity(customHostToggle, block, toggleFieldId);
        assignControlIdentity(input, block, fieldId);
        var hostActions = createElement("div", {
            className: "host-field-actions",
            children: randomButton ? [randomButton] : []
        });
        var customHostEnabled = isOptionalHostEnabled(block, protocol, fieldId);

        customHostToggle.checked = customHostEnabled;
        customHostToggle.addEventListener("change", function () {
            setFieldValue(block, toggleFieldId, customHostToggle.checked);
            input.hidden = !customHostToggle.checked;
            input.disabled = !customHostToggle.checked;
            hostActions.hidden = !customHostToggle.checked;
            if (randomButton) {
                randomButton.disabled = !customHostToggle.checked;
            }
            syncBlockUi(block);
            clearBlockError(block);
        });
        input.spellcheck = !!FIELD_DEFS[fieldId].spellcheck;
        input.value = String(value);
        input.addEventListener("input", function () {
            setFieldValue(block, fieldId, input.value);
            clearBlockError(block);
        });
        if (randomButton) {
            randomButton.addEventListener("click", function () {
                setFieldValue(block, fieldId, pickWeightedRankedDomain(DOMAIN_POOL));
                syncBlockUi(block);
                clearBlockError(block);
            });
        }

        input.hidden = !customHostEnabled;
        input.disabled = !customHostEnabled;
        hostActions.hidden = !customHostEnabled || isSipProtocol;
        if (randomButton) {
            randomButton.disabled = !customHostEnabled;
        }

        var checkboxLabel = createElement("label", {
            className: "inline-checkbox",
            htmlFor: customHostIdentity.id,
            children: [customHostToggle, createElement("span", {
                className: "checkbox-label",
                textContent: FIELD_DEFS[fieldId].label
            })]
        });

        return createElement("div", {
            className: "field host-field span-12",
            children: [createElement("div", {
                className: "host-field-row",
                children: [checkboxLabel, input, hostActions]
            })]
        });
    }

        function createOptionalSelectField(block, protocol, fieldId, value) {
            var fieldDef = FIELD_DEFS[fieldId];
            var toggleFieldId = getOptionalHostToggleFieldId(fieldId);
            var customToggle = createElement("input", {
                type: "checkbox",
                className: "payload-field payload-field-" + toggleFieldId
            });
            var select = createElement("select", { className: "payload-field payload-field-" + fieldId });
            var toggleIdentity = assignControlIdentity(customToggle, block, toggleFieldId);
            assignControlIdentity(select, block, fieldId);
            fillSelectOptions(select, getFieldOptions(fieldDef.optionSet), String(value));
            var actions = createElement("div", { className: "host-field-actions", children: [] });

            var customEnabled = Object.prototype.hasOwnProperty.call(block._state.values, toggleFieldId)
                ? !!block._state.values[toggleFieldId]
                : (protocol && protocol.defaults && protocol.defaults[toggleFieldId] === false ? false : normalizeOptionalHost(block._state.values[fieldId]) !== "");

            customToggle.checked = customEnabled;
            customToggle.addEventListener("change", function () {
                setFieldValue(block, toggleFieldId, customToggle.checked);
                select.hidden = !customToggle.checked;
                select.disabled = !customToggle.checked;
                actions.hidden = !customToggle.checked;
                syncBlockUi(block);
                clearBlockError(block);
            });

            select.addEventListener("change", function () {
                setFieldValue(block, fieldId, select.value);
                clearBlockError(block);
            });

            select.hidden = !customEnabled;
            select.disabled = !customEnabled;
            actions.hidden = !customEnabled;

            var checkboxLabel = createElement("label", {
                className: "inline-checkbox",
                htmlFor: toggleIdentity.id,
                children: [customToggle, createElement("span", { className: "checkbox-label", textContent: FIELD_DEFS[fieldId].label })]
            });

            return createElement("div", {
                className: "field host-field " + (fieldDef.className || "span-6"),
                children: [createElement("div", {
                    className: "host-field-row",
                    children: [checkboxLabel, select, actions]
                })]
            });
        }

    function createSipMessageField(block, protocol, value) {
        var checkbox = createElement("input", {
            type: "checkbox",
            className: "payload-field payload-field-sipCustomMessage"
        });
        var select = createElement("select", { className: "payload-field payload-field-sipAction" });
        var checkboxIdentity = assignControlIdentity(checkbox, block, "sipCustomMessage");
        var selectIdentity = assignControlIdentity(select, block, "sipAction");
        var isCustomMessageEnabled = !!block._state.values.sipCustomMessage;

        fillSelectOptions(select, getFieldOptions("sipActions"), String(block._state.values.sipAction || "OPTIONS"));
        select.hidden = !isCustomMessageEnabled;
        select.disabled = !isCustomMessageEnabled;

        checkbox.checked = isCustomMessageEnabled;
        checkbox.addEventListener("change", function () {
            setFieldValue(block, "sipCustomMessage", checkbox.checked);
            select.hidden = !checkbox.checked;
            select.disabled = !checkbox.checked;
            clearBlockError(block);
        });

        select.addEventListener("change", function () {
            setFieldValue(block, "sipAction", select.value);
            clearBlockError(block);
        });

        var checkboxLabel = createElement("label", {
            className: "inline-checkbox",
            htmlFor: checkboxIdentity.id,
            children: [checkbox, createElement("span", {
                className: "checkbox-label",
                textContent: FIELD_DEFS.sipCustomMessage.label
            })]
        });

        return createElement("div", {
            className: "field span-12",
            children: [createElement("div", {
                className: "host-field-row",
                children: [checkboxLabel, select]
            })]
        });
    }

    function setFieldValue(block, fieldId, value) {
        clearActivePreset();
        invalidateGeneratedOutput();
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

    function getPresetEntriesForProtocol(protocolId) {
        if (shouldHidePresetHintsForProtocol(protocolId)) {
            return [];
        }

        return PRESET_PROTOCOL_HINTS[protocolId] ? PRESET_PROTOCOL_HINTS[protocolId].map(function (entry) {
            return {
                id: entry.id,
                label: formatPresetLabel(entry.label),
                recommended: getPresetOptionGroup(entry.id) !== "unconfirmed"
            };
        }) : [];
    }

    function getPresetLabelsForProtocol(protocolId) {
        return getPresetEntriesForProtocol(protocolId).map(function (entry) {
            return entry.label;
        });
    }

    function isBestProtocol(protocolId) {
        return protocolId === "quic" || protocolId === "curl_quic";
    }

    function isRecommendedProtocol(protocolId) {
        return protocolId === "sip" || protocolId === "stun" || protocolId === "dns" ||
            protocolId === "dhcp_discover" || protocolId === "dtls" || protocolId === "rtcp" ||
            protocolId === "nbns" || protocolId === "mdns" || protocolId === "llmnr" || protocolId === "webrtc_combined";
    }

    function getProtocolOptionGroup(protocolId) {
        if (isBestProtocol(protocolId)) {
            return "best";
        }

        if (isRecommendedProtocol(protocolId)) {
            return "recommended";
        }

        return "unconfirmed";
    }

    function getPresetOptionGroup(presetId) {
        var preset = PRESET_MAP && PRESET_MAP[presetId];

        if (!preset || !Array.isArray(preset.blocks) || preset.blocks.length === 0) {
            return "unconfirmed";
        }

        // If the preset contains only SIP blocks, treat it as recommended ("Kinda").
        var allSip = preset.blocks.every(function (block) { return block.protocol === "sip"; });

        if (allSip) {
            return "recommended";
        }

        return "unconfirmed";
    }

    function shouldRenderProtocolMuted(protocolId) {
        return !isHighlightedSelection(protocolId);
    }

    function getProtocolPresetHintText(protocolId) {
        var presetLabels = getPresetLabelsForProtocol(protocolId);
        var protocol = getProtocolMeta(protocolId);
        var hasOptions = protocol && protocol.fieldSet && protocol.fieldSet.length;
        var hintText = "";

        if (!presetLabels.length && !hasOptions) {
            return "";
        }

        if (presetLabels.length) {
            hintText = UI.protocolPresetHint + " " + presetLabels.join(", ");
        }

        if (hasOptions) {
            hintText = hintText ? hintText + " | " + UI.protocolOptionHint + " " + UI.protocolPresetHintDescription : UI.protocolOptionHint + " " + UI.protocolPresetHintDescription;
        }

        return hintText;
    }

    function syncProtocolHint(block) {
        var protocolId = block._state.protocolId;
        var presetEntries = getPresetEntriesForProtocol(protocolId);
        var protocol = getProtocolMeta(protocolId);
        var hasOptions = protocol && protocol.fieldSet && protocol.fieldSet.length;
        var refs = getBlockRefs(block);
        var hint = refs.protocolHint;

        if (hasActivePreset()) {
            hint.hidden = true;
            clearElement(hint);
            return;
        }

        clearElement(hint);
        hint.hidden = !(presetEntries.length || hasOptions);

        if (hint.hidden) {
            return;
        }

        if (presetEntries.length) {
            hint.appendChild(createElement("div", {
                className: "payload-protocol-hint-row",
                children: [
                    createElement("span", {
                        className: "blocks-hint-label",
                        textContent: UI.protocolPresetHint
                    }),
                    createElement("div", {
                        className: "payload-protocol-hint-links",
                        children: presetEntries.map(function (entry) {
                            var presetButton = createButton(entry.label, "preset-hint-link");

                            if (!entry.recommended) {
                                presetButton.classList.add("preset-hint-link-muted");
                            }

                            presetButton.addEventListener("click", function () {
                                loadPresetById(entry.id);
                            });
                            return presetButton;
                        })
                    })
                ]
            }));
        }

        if (hasOptions) {
            hint.appendChild(createElement("div", {
                className: "payload-protocol-hint-row",
                children: [
                    createElement("span", {
                        className: "blocks-hint-label",
                        textContent: UI.protocolOptionHint
                    }),
                    createElement("div", {
                        className: "payload-protocol-hint-message",
                        textContent: UI.protocolPresetHintDescription
                    })
                ]
            }));
        }
    }

    function fillSelectOptions(select, options, selectedValue) {
        clearElement(select);
        options.forEach(function (option) {
            select.appendChild(createElement("option", { value: String(option.value), textContent: option.label }));
        });
        select.value = String(selectedValue);
    }

    function fillProtocolSelect(select, protocols, presets, selectedId) {
        var bestGroup;
        var recommendedGroup;
        var unconfirmedGroup;

        clearElement(select);
        bestGroup = createElement("optgroup", { label: UI.bestOptionsGroup });
        recommendedGroup = createElement("optgroup", { label: UI.recommendedOptionsGroup });
        unconfirmedGroup = createElement("optgroup", { label: UI.unconfirmedOptionsGroup });

        protocols.forEach(function (protocol) {
            var hintText = getProtocolPresetHintText(protocol.id);
            var optionGroup = getProtocolOptionGroup(protocol.id);
            var option = createElement("option", {
                value: encodeProtocolSelectValue("protocol", protocol.id),
                textContent: protocol.label
            });

            if (optionGroup !== "unconfirmed") {
                option.className = "protocol-option-recommended";
                option.style.color = "var(--text)";
                option.style.fontWeight = "600";
            } else {
                option.className = "protocol-option-unconfirmed";
                option.style.color = "var(--muted)";
            }

            if (hintText) {
                option.title = hintText;
            }

            getOptionGroupElement(optionGroup, bestGroup, recommendedGroup, unconfirmedGroup).appendChild(option);
        });

        presets.forEach(function (preset) {
            var option = createElement("option", {
                value: encodeProtocolSelectValue("preset", preset.id),
                textContent: String(preset.label || "")
            });

            var group = getPresetOptionGroup(preset.id);

            if (group !== "unconfirmed") {
                option.className = "protocol-option-recommended";
                option.style.color = "var(--text)";
                option.style.fontWeight = "600";
            } else {
                option.className = "protocol-option-unconfirmed";
                option.style.color = "var(--muted)";
            }

            option.title = preset.description;
            getOptionGroupElement(group, bestGroup, recommendedGroup, unconfirmedGroup).appendChild(option);
        });

        if (bestGroup.children.length) {
            select.appendChild(bestGroup);
        }

        if (recommendedGroup.children.length) {
            select.appendChild(recommendedGroup);
        }

        if (unconfirmedGroup.children.length) {
            select.appendChild(unconfirmedGroup);
        }

        // Presets are appended into the corresponding option groups above.

        select.value = encodeProtocolSelectValue("protocol", selectedId);
    }

    function syncProtocolPresetState(select, protocolId) {
        var hintText = hasActivePreset()
            ? UI.presetActiveLabel + " " + formatPresetLabel(getActivePreset().label)
            : getProtocolPresetHintText(protocolId);
        var isRecommended = isHighlightedSelection(protocolId);

        select.classList.toggle("protocol-select-favorite", isRecommended);
        select.classList.toggle("protocol-select-muted", shouldRenderProtocolMuted(protocolId));
        select.style.color = isRecommended ? "var(--text)" : "var(--muted)";
        select.title = hintText;
    }

    function updateBlockUi() {
        var shouldHideRemove = getBlockCount() <= 1;
        var blockCount = getBlockCount();
        var nextPayloadIndex = Math.min(blockCount + 1, CONFIG.maxBlocks);

        getBlocks().forEach(function (block, index) {
            var refs = getBlockRefs(block);
            refs.title.textContent = "Payload i" + (index + 1);
            refs.removeButton.hidden = shouldHideRemove;
        });

        dom.addButton.textContent = "Add payload";
        dom.addButton.setAttribute("data-next-index", String(nextPayloadIndex));
        dom.addButton.disabled = blockCount >= CONFIG.maxBlocks;
    }

    function isQuicLikeProtocolId(protocolId) {
        return protocolId === "quic" || protocolId === "curl_quic";
    }

    function generateOutput() {
        var blocks = getBlocks();
        var mtu = getSharedMtu();
        var lines = [];
        var capped = false;
        var hasAsyncProtocols = false;
        var generationToken = ++outputGenerationToken;

        clearAllErrors();

        blocks.forEach(function (block) {
            var settings = getBlockGenerationSettings(block);

            if (isQuicLikeProtocolId(block._state.protocolId) && shouldUseAsyncQuicOutput(collectProtocolOptions(block, mtu, settings.padMtu))) {
                hasAsyncProtocols = true;
            }
        });

        if (hasAsyncProtocols && typeof ensureGenerators().generatePayloadAsync === "function") {
            generateOutputAsync().then(function (result) {
                if (generationToken === outputGenerationToken) {
                    setOutputValue(formatOutputLines(result.lines));
                }
            }).catch(function (error) {
                console.error("Async generation failed:", error);
            });

            return { mtu: mtu, lines: [], capped: false, pending: true };
        }

        blocks.forEach(function (block) {
            if (lines.length >= CONFIG.maxOutputLines) {
                capped = true;
                return;
            }

            try {
                capped = appendBlockLines(lines, block, mtu) || capped;
            } catch (error) {
                setBlockError(block, error && error.message ? error.message : "Failed to generate this payload.");
            }
        });

        if (generationToken === outputGenerationToken) {
            setOutputValue(formatOutputLines(lines));
        }
        return { mtu: mtu, lines: lines, capped: capped };
    }

    async function generateOutputAsync() {
        var blocks = getBlocks();
        var mtu = getSharedMtu();
        var lines = [];
        var capped = false;
        var index;

        clearAllErrors();

        for (index = 0; index < blocks.length; index += 1) {
            if (lines.length >= CONFIG.maxOutputLines) {
                capped = true;
                break;
            }

            try {
                capped = await appendBlockLinesAsync(lines, blocks[index], mtu) || capped;
            } catch (error) {
                setBlockError(blocks[index], error && error.message ? error.message : "Failed to generate this payload.");
            }
        }

        return { mtu: mtu, lines: lines, capped: capped };
    }

    function appendBlockLines(lines, block, fallbackMtu, fallbackPadMtu) {
        var settings = getBlockGenerationSettings(block, fallbackMtu, fallbackPadMtu);
        var options = collectProtocolOptions(block, settings.mtu, settings.padMtu);

        return appendChunkLines(
            lines,
            chunkPayload(
                ensureGenerators().generatePayload(block._state.protocolId, options),
                settings.mtu,
                shouldPadOutputChunks(block._state.protocolId, options, settings.padMtu)
            )
        );
    }

    async function appendBlockLinesAsync(lines, block, fallbackMtu, fallbackPadMtu) {
        var generators = ensureGenerators();
        var settings = getBlockGenerationSettings(block, fallbackMtu, fallbackPadMtu);
        var options = collectProtocolOptions(block, settings.mtu, settings.padMtu);
        var payloadBytes = isQuicLikeProtocolId(block._state.protocolId) && shouldUseAsyncQuicOutput(options) && typeof generators.generatePayloadAsync === "function"
            ? await generators.generatePayloadAsync(block._state.protocolId, options)
            : generators.generatePayload(block._state.protocolId, options);

        return appendChunkLines(
            lines,
            chunkPayload(payloadBytes, settings.mtu, shouldPadOutputChunks(block._state.protocolId, options, settings.padMtu))
        );
    }

    function collectProtocolOptions(block, mtu, padMtu) {
        var protocol = getProtocolMeta(block._state.protocolId);
        var options = {};

        protocol.fieldSet.forEach(function (fieldId) {
            var value = Object.prototype.hasOwnProperty.call(block._state.values, fieldId) ? block._state.values[fieldId] : getFieldDefault(protocol, fieldId);
            var toggleFieldId = getOptionalHostToggleFieldId(fieldId);
            var customHostEnabled;

            if (fieldId === "mtu" || fieldId === "padMtu") {
                return;
            }

            if (fieldId === "host" || (fieldId === "iceServerHost" && protocol.id === "stun")) {
                customHostEnabled = Object.prototype.hasOwnProperty.call(block._state.values, toggleFieldId)
                    ? !!block._state.values[toggleFieldId]
                    : normalizeOptionalHost(value) !== "" && (!protocol || !isQuicLikeProtocolId(protocol.id) || fieldId !== "host");
                if (fieldId === "host") {
                    options.hasCustomHost = customHostEnabled;
                    options.host = customHostEnabled ? normalizeHost(value) : CONFIG.defaultHost;
                } else {
                    options.hasCustomIceServerHost = customHostEnabled;
                    options.iceServerHost = customHostEnabled ? normalizeOptionalHost(value) : "";
                }
            } else if ((fieldId === "iceProvider" || fieldId === "iceMode") && protocol.id === "stun") {
                var toggleId = toggleFieldId;
                var customEnabled = Object.prototype.hasOwnProperty.call(block._state.values, toggleId)
                    ? !!block._state.values[toggleId]
                    : (protocol && protocol.defaults && protocol.defaults[toggleId] === false ? false : normalizeOptionalHost(block._state.values[fieldId]) !== "");

                if (fieldId === "iceProvider") {
                    options.hasCustomIceProvider = customEnabled;
                    options.iceProvider = customEnabled ? String(value) : getFieldDefault(protocol, fieldId);
                } else {
                    options.hasCustomIceMode = customEnabled;
                    options.iceMode = customEnabled ? String(value) : getFieldDefault(protocol, fieldId);
                }
            } else if (fieldId === "iceServerHost") {
                options.iceServerHost = normalizeOptionalHost(value);
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

        if (isQuicLikeProtocolId(protocol.id)) {
            options.quicEncrypt = true;
            options.quicMtu = resolveMtuValue(mtu);
            options.quicPadToMtu = !!padMtu;
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

    function shouldPadOutputChunks(protocolId, options, padMtu) {
        if (!padMtu) {
            return false;
        }

        return !(isQuicLikeProtocolId(protocolId) && options && options.quicPadToMtu && options.quicEncrypt);
    }

    function copyOutput() {
        var content = dom.output.value.trim();

        if (!content) {
            content = generateOutput().lines.join("\n");
        }

        if (!content) {
            return Promise.resolve(false);
        }

        function flashCopyState(ok) {
            var originalText = dom.copyButton.textContent;
            dom.copyButton.textContent = ok ? "Copied" : "Copy failed";
            dom.copyButton.disabled = true;
            setTimeout(function () {
                dom.copyButton.textContent = originalText;
                dom.copyButton.disabled = false;
            }, 1200);
        }

        if (typeof navigator !== "undefined" &&
            navigator.clipboard &&
            typeof navigator.clipboard.writeText === "function" &&
            typeof isSecureContext !== "undefined" &&
            isSecureContext) {
            return navigator.clipboard.writeText(content).then(function () {
                flashCopyState(true);
                return true;
            }).catch(function () {
                flashCopyState(false);
                return false;
            });
        }

        return new Promise(function (resolve) {
            try {
                dom.output.focus();
                dom.output.select();
                dom.output.setSelectionRange(0, dom.output.value.length);
                var ok = !!(typeof document !== "undefined" && typeof document.execCommand === "function" && document.execCommand("copy"));
                flashCopyState(ok);
                resolve(ok);
            } catch (error) {
                flashCopyState(false);
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
            title: block.querySelector(SELECTORS.blockTitleText),
            protocolSelect: block.querySelector(SELECTORS.payloadProtocol),
            protocolHint: block.querySelector(SELECTORS.payloadProtocolHint),
            removeButton: block.querySelector(SELECTORS.payloadRemoveButton),
            dynamicFields: block.querySelector(SELECTORS.payloadDynamicFields),
            errorField: block.querySelector(SELECTORS.payloadError)
        };
    }

    function clearAllErrors() {
        getBlocks().forEach(function (block) {
            clearBlockError(block);
        });
    }

    function clearBlockError(block) {
        var refs = getBlockRefs(block);
        if (!refs || !refs.errorField) {
            return;
        }
        refs.errorField.textContent = "";
        refs.errorField.hidden = true;
    }

    function setBlockError(block, message) {
        var refs = getBlockRefs(block);
        if (!refs || !refs.errorField) {
            return;
        }
        refs.errorField.textContent = String(message || "Failed to generate this payload.");
        refs.errorField.hidden = false;
    }

    function formatOutputLines(lines) {
        return lines && lines.length ? lines.join("\n") + "\n" : "";
    }

    function setOutputValue(value) {
        dom.output.value = String(value || "");
        syncCopyButtonVisibility();
    }

    function invalidateGeneratedOutput() {
        outputGenerationToken += 1;
        setOutputValue("");
    }

    function syncCopyButtonVisibility() {
        dom.copyButton.hidden = !String(dom.output.value || "").trim();
    }

    function syncMtuInputWidth(input) {
        var value;
        var digitCount;

        if (!input) {
            return;
        }

        value = String(typeof input.value === "undefined" ? "" : input.value).trim();
        digitCount = Math.max(
            String(CONFIG.defaultMtu).length,
            Math.min(String(CONFIG.maxMtu).length, value.length || 1)
        );

        input.style.setProperty("--mtu-input-chars", String(digitCount));
    }

    function getSharedMtu() {
        return resolveMtuValue(sharedMtu);
    }

    function setSharedMtu(rawValue) {
        sharedMtu = resolveMtuValue(rawValue);

        getBlocks().forEach(function (block) {
            var refs = getBlockRefs(block);
            if (!refs || !refs.dynamicFields) {
                return;
            }
            Array.prototype.slice.call(refs.dynamicFields.querySelectorAll(".payload-mtu-input")).forEach(function (input) {
                input.value = String(sharedMtu);
                syncMtuInputWidth(input);
            });
        });
    }

    function createPaddingField(block, protocol, value) {
        void protocol;

        var checkbox = createElement("input", { type: "checkbox", className: "payload-field payload-field-padMtu" });
        var checkboxIdentity = assignControlIdentity(checkbox, block, "padMtu");
        var mtuLabel = createElement("span", { className: "blocks-hint-label", textContent: "MTU" });
        var mtuInput = createElement("input", {
            type: "number",
            className: "mtu-input payload-mtu-input",
            min: String(CONFIG.minMtu),
            max: String(CONFIG.maxMtu),
            inputMode: "numeric",
            value: String(getSharedMtu()),
            "aria-label": "MTU"
        });
        var mtuWrap = createElement("div", {
            className: "toolbar-group",
            children: [mtuLabel, mtuInput]
        });

        checkbox.checked = !!value;
        mtuInput.disabled = !checkbox.checked;
        mtuWrap.hidden = !checkbox.checked;
        syncMtuInputWidth(mtuInput);

        checkbox.addEventListener("change", function () {
            setFieldValue(block, "padMtu", checkbox.checked);
            mtuInput.disabled = !checkbox.checked;
            mtuWrap.hidden = !checkbox.checked;
            syncBlockUi(block);
            clearBlockError(block);
        });

        mtuInput.addEventListener("input", function () {
            syncMtuInputWidth(mtuInput);
            setSharedMtu(mtuInput.value);
            clearBlockError(block);
        });

        mtuInput.addEventListener("change", function () {
            setSharedMtu(mtuInput.value);
            mtuInput.value = String(getSharedMtu());
            syncMtuInputWidth(mtuInput);
            clearBlockError(block);
        });

        return createElement("div", {
            className: "field checkbox-field span-12",
            children: [createElement("div", {
                className: "checkbox-row",
                children: [
                    createElement("label", {
                        className: "inline-checkbox",
                        htmlFor: checkboxIdentity.id,
                        children: [checkbox, createElement("span", { className: "checkbox-label-muted", textContent: FIELD_DEFS.padMtu.label })]
                    }),
                    mtuWrap
                ]
            })]
        });
    }

    function resolveMtuValue(rawValue) {
        var mtu = parseInt(String(rawValue || "").trim(), 10);

        if (!Number.isFinite(mtu)) {
            mtu = CONFIG.defaultMtu;
        }

        return Math.max(CONFIG.minMtu, Math.min(CONFIG.maxMtu, mtu));
    }

    function normalizeHost(rawValue) {
        var host = String(rawValue || "").trim();
        return host || CONFIG.defaultHost;
    }

    function normalizeOptionalHost(rawValue) {
        return String(rawValue || "").trim();
    }

    function normalizePath(rawValue) {
        var path = String(rawValue || "").trim();
        return !path ? "/" : (path.charAt(0) === "/" ? path : "/" + path);
    }

    function cloneBlockState(state) {
        var hydrated = hydrateBlockState(state);
        return {
            protocolId: hydrated.protocolId,
            values: Object.assign({}, hydrated.values)
        };
    }

    function createHeadlessBlock(state) {
        return { _state: cloneBlockState(state) };
    }

    function normalizeBlockStates(states) {
        if (!Array.isArray(states) || !states.length) {
            return [cloneBlockState(createDefaultBlockState("quic"))];
        }

        return states.map(function (state) {
            return cloneBlockState(state);
        });
    }

    function expandPresetById(presetId) {
        var preset = getPresetMeta(presetId);

        if (!preset) {
            throw new Error("Unknown preset.");
        }

        return buildPresetStates(preset);
    }

    function buildProtocolState(protocolId, values) {
        return {
            protocolId: protocolId,
            values: Object.assign({}, values || {})
        };
    }

    function resolveBlockMtu(block, fallbackMtu) {
        return resolveMtuValue(typeof fallbackMtu === "undefined" ? CONFIG.defaultMtu : fallbackMtu);
    }

    function resolveBlockPadMtu(block, fallbackPadMtu) {
        if (!isQuicLikeProtocolId(block._state.protocolId)) {
            return false;
        }

        if (Object.prototype.hasOwnProperty.call(block._state.values, "padMtu")) {
            return !!block._state.values.padMtu;
        }

        return !!fallbackPadMtu;
    }

    function getBlockGenerationSettings(block, fallbackMtu, fallbackPadMtu) {
        return {
            mtu: resolveBlockMtu(block, fallbackMtu),
            padMtu: resolveBlockPadMtu(block, fallbackPadMtu)
        };
    }

    function collectProtocolOptionsFromState(state, mtu, padMtu) {
        return collectProtocolOptions(createHeadlessBlock(state), resolveMtuValue(mtu), !!padMtu);
    }

    function generateLinesFromStatesSync(states, rawMtu, padMtu) {
        var normalizedStates = normalizeBlockStates(states);
        var mtu = resolveMtuValue(rawMtu);
        var lines = [];
        var capped = false;
        var index;

        for (index = 0; index < normalizedStates.length; index += 1) {
            if (lines.length >= CONFIG.maxOutputLines) {
                capped = true;
                break;
            }

            capped = appendBlockLines(lines, createHeadlessBlock(normalizedStates[index]), mtu, !!padMtu) || capped;
        }

        return { mtu: mtu, lines: lines, capped: capped };
    }

    async function generateLinesFromStatesAsync(states, rawMtu, padMtu) {
        var normalizedStates = normalizeBlockStates(states);
        var mtu = resolveMtuValue(rawMtu);
        var lines = [];
        var capped = false;
        var index;

        for (index = 0; index < normalizedStates.length; index += 1) {
            if (lines.length >= CONFIG.maxOutputLines) {
                capped = true;
                break;
            }

            capped = await appendBlockLinesAsync(lines, createHeadlessBlock(normalizedStates[index]), mtu, !!padMtu) || capped;
        }

        return { mtu: mtu, lines: lines, capped: capped };
    }

    function clearProtocolDomainMemory(block) {
        delete block._state.values.host;
        delete block._state.values.iceServerHost;
        delete block._state.values.customHost;
        delete block._state.values.customIceServerHost;
    }

    function ensureProtocolUiState(block, protocol) {
        if (!protocolUsesField(protocol, "host") || Object.prototype.hasOwnProperty.call(block._state.values, "customHost")) {
            return;
        }

        if (protocol.defaults && protocol.defaults.customHost === false) {
            block._state.values.customHost = false;
            return;
        }

        block._state.values.customHost = normalizeOptionalHost(block._state.values.host) !== "" || !isQuicLikeProtocolId(protocol.id);
    }

    function isCustomHostEnabled(block, protocol) {
        if (Object.prototype.hasOwnProperty.call(block._state.values, "customHost")) {
            return !!block._state.values.customHost;
        }

        if (protocol && protocol.defaults && protocol.defaults.customHost === false) {
            return false;
        }

        if (normalizeOptionalHost(block._state.values.host) !== "") {
            return true;
        }

        return !!(protocol && !isQuicLikeProtocolId(protocol.id));
    }

    function removeOtherBlocks(targetBlock) {
        getBlocks().forEach(function (block) {
            if (block !== targetBlock) {
                block.remove();
            }
        });
    }

    async function confirmPresetBlockIsolation(triggerElement) {
        if (!hasActivePreset() || getBlockCount() <= 1) {
            return false;
        }

        return showPresetBlockDialog(triggerElement);
    }

    function buildPresetBlockDialogMessage() {
        var activePreset = getActivePreset();
        var presetLabel = activePreset && activePreset.label ? activePreset.label : "current";

        return UI.presetDialogMessage.replace("%PRESET%", presetLabel);
    }

    function showPresetBlockDialog(triggerElement) {
        if (presetDialogResolver) {
            return false;
        }

        dom.presetDialogMessage.textContent = buildPresetBlockDialogMessage();
        dom.presetDialogBackdrop.hidden = false;
        presetDialogReturnFocus = triggerElement || document.activeElement || null;

        return new Promise(function (resolve) {
            presetDialogResolver = resolve;
            dom.presetDialogYesButton.focus();
        });
    }

    function resolvePresetBlockDialog(shouldKeepOnlyEditedBlock) {
        var resolver = presetDialogResolver;

        if (!resolver) {
            return;
        }

        presetDialogResolver = null;
        dom.presetDialogBackdrop.hidden = true;
        dom.presetDialogMessage.textContent = "";

        if (presetDialogReturnFocus && typeof presetDialogReturnFocus.focus === "function") {
            presetDialogReturnFocus.focus();
        }

        presetDialogReturnFocus = null;
        resolver(!!shouldKeepOnlyEditedBlock);
    }

    function syncPresetDialogCopy() {
        dom.presetDialogTitle.textContent = UI.presetDialogTitle;
        dom.presetDialogYesButton.textContent = UI.presetDialogYesButton;
        dom.presetDialogNoButton.textContent = UI.presetDialogNoButton;
    }

    function handleDocumentKeydown(event) {
        if (!presetDialogResolver || event.key !== "Escape") {
            return;
        }

        event.preventDefault();
        resolvePresetBlockDialog(false);
    }

    function encodeProtocolSelectValue(kind, id) {
        return (kind === "preset" ? PROTOCOL_SELECT_PRESET_PREFIX : PROTOCOL_SELECT_PROTOCOL_PREFIX) + String(id || "");
    }

    function parseProtocolSelectValue(rawValue) {
        var value = String(rawValue || "");

        if (value.indexOf(PROTOCOL_SELECT_PRESET_PREFIX) === 0) {
            return { kind: "preset", id: value.slice(PROTOCOL_SELECT_PRESET_PREFIX.length) };
        }

        if (value.indexOf(PROTOCOL_SELECT_PROTOCOL_PREFIX) === 0) {
            return { kind: "protocol", id: value.slice(PROTOCOL_SELECT_PROTOCOL_PREFIX.length) };
        }

        return { kind: "protocol", id: value };
    }

    function getChromeDefaultVersion() {
        return SharedData.CHROME_BROWSER_DATA.defaultVersion;
    }

    function listProtocols() {
        return PROTOCOL_CATALOG.slice().filter(function (p) { return !p.hidden; }).sort(function (left, right) {
            return left.label.localeCompare(right.label);
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

    function shouldHidePresetHintsForProtocol(protocolId) {
        return protocolId === "curl_quic";
    }

    function isHighlightedSelection(protocolId) {
        var activePreset = getActivePreset();

        if (activePreset) {
            return getPresetOptionGroup(activePreset.id) !== "unconfirmed" ||
                getProtocolOptionGroup(protocolId) !== "unconfirmed";
        }

        return getProtocolOptionGroup(protocolId) !== "unconfirmed";
    }

    function formatPresetLabel(label) {
        return String(label || "");
    }

    function hasActivePreset() {
        return !!getActivePreset();
    }

    function getActivePreset() {
        return activePresetId && PRESET_MAP[activePresetId] ? PRESET_MAP[activePresetId] : null;
    }

    function setActivePresetId(presetId) {
        activePresetId = PRESET_MAP[presetId] ? presetId : "";
        syncActivePresetStatus();
    }

    function clearActivePreset() {
        if (!activePresetId) {
            return;
        }

        activePresetId = "";
        syncActivePresetStatus();
        refreshPresetUi();
    }

    function refreshPresetUi() {
        getBlocks().forEach(function (block) {
            var refs = getBlockRefs(block);

            syncProtocolPresetState(refs.protocolSelect, block._state.protocolId);
            syncProtocolHint(block);
        });
    }

    function syncActivePresetStatus() {
        var preset = getActivePreset();

        clearElement(dom.blocksStatus);
        dom.blocksStatus.hidden = !preset;

        if (!preset) {
            return;
        }

        dom.blocksStatus.appendChild(createElement("span", {
            className: "blocks-status-label",
            textContent: UI.presetActiveLabel
        }));
        dom.blocksStatus.appendChild(createElement("strong", {
            className: "blocks-status-value" + (getPresetOptionGroup(preset.id) !== "unconfirmed" ? "" : " blocks-status-value-muted"),
            textContent: formatPresetLabel(preset.label)
        }));
    }

    function getOptionGroupElement(optionGroup, bestGroup, recommendedGroup, unconfirmedGroup) {
        if (optionGroup === "best") {
            return bestGroup;
        }

        if (optionGroup === "recommended") {
            return recommendedGroup;
        }

        return unconfirmedGroup;
    }

    function getOptionGroupLabel(optionGroup) {
        if (optionGroup === "best") {
            return UI.bestOptionsGroup.replace(/:\s*$/, "");
        }

        if (optionGroup === "recommended") {
            return UI.recommendedOptionsGroup.replace(/:\s*$/, "");
        }

        return UI.unconfirmedOptionsGroup.replace(/:\s*$/, "");
    }

    function createMapById(items) {
        return items.reduce(function (map, item) {
            map[item.id] = item;
            return map;
        }, {});
    }

    function createPresetProtocolMap(presets) {
        return presets.reduce(function (map, preset) {
            preset.blocks.forEach(function (block) {
                if (!map[block.protocol]) {
                    map[block.protocol] = [];
                }

                if (!map[block.protocol].some(function (entry) { return entry.id === preset.id; })) {
                    map[block.protocol].push({ id: preset.id, label: preset.label });
                }
            });

            return map;
        }, {});
    }

    function createField(label, control, className, controlId) {
        var wrapperOptions = {
            className: className,
            children: [createElement("label", {
                className: "field-label",
                textContent: label
            }), control]
        };

        if (controlId) {
            wrapperOptions.children[0].htmlFor = controlId;
        }

        return createElement("div", wrapperOptions);
    }

    function createCheckboxField(label, control, className, controlId) {
        var checkboxLabel = createElement("label", {
            className: "inline-checkbox",
            children: [control, createElement("span", { className: "checkbox-label-muted", textContent: label })]
        });

        if (controlId) {
            checkboxLabel.htmlFor = controlId;
        }

        return createElement("div", {
            className: className,
            children: [checkboxLabel]
        });
    }

    function nextBlockUid() {
        blockUidCounter += 1;
        return blockUidCounter;
    }

    function assignControlIdentity(control, block, fieldId) {
        var identity = getControlIdentity(block, fieldId);

        control.id = identity.id;
        control.name = identity.name;
        return identity;
    }

    function getControlIdentity(block, fieldId) {
        var safeFieldId = String(fieldId || "field").replace(/[^a-z0-9_-]+/gi, "-");
        var base = "payload-block-" + String(block && block._uid ? block._uid : "0") + "-" + safeFieldId;

        return {
            id: base,
            name: base
        };
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

    return {
        init: init,
        constants: {
            MAX_BLOCKS: CONFIG.maxBlocks,
            MAX_OUTPUT_LINES: CONFIG.maxOutputLines,
            MIN_MTU: CONFIG.minMtu,
            MAX_MTU: CONFIG.maxMtu,
            DEFAULT_MTU: CONFIG.defaultMtu,
            DEFAULT_HOST: CONFIG.defaultHost,
            DOMAIN_SNAPSHOTS: { global: DOMAIN_POOL.slice() },
            PROTOCOL_CATALOG: PROTOCOL_CATALOG
        },
        catalog: {
            protocols: PROTOCOL_CATALOG,
            presets: BLOCK_PRESETS,
            listProtocols: listProtocols,
            listPresets: listPresets
        },
        helpers: {
            bytesToHex: bytesToHex,
            chunkPayload: chunkPayload,
            formatOutputLines: formatOutputLines,
            pickWeightedRankedDomain: pickWeightedRankedDomain
        },
        generators: {
            generatePayload: function (protocolId, options) {
                return ensureGenerators().generatePayload(protocolId, options);
            },
            generatePayloadAsync: function (protocolId, options) {
                return ensureGenerators().generatePayloadAsync(protocolId, options);
            }
        },
        cli: {
            resolveMtu: resolveMtuValue,
            buildProtocolState: buildProtocolState,
            expandPreset: expandPresetById,
            collectProtocolOptions: collectProtocolOptionsFromState,
            generateLinesSync: generateLinesFromStatesSync,
            generateLines: generateLinesFromStatesAsync
        }
    };
}));
