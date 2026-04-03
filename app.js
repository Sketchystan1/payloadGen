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
        payloadTitle: "Payload"
    };
    var OPTION_SETS = {
        sipActions: [{ value: "OPTIONS", label: "OPTIONS" }, { value: "REGISTER", label: "REGISTER" }],
        coapMethods: [{ value: "GET", label: "GET" }, { value: "POST", label: "POST" }],
        tlsAlpn: [{ value: "http/1.1", label: "http/1.1" }, { value: "h2", label: "h2" }]
    };
    var FIELD_DEFS = {
        host: { type: "text", label: "Domain", placeholder: "example.com", spellcheck: false },
        path: { type: "text", label: "Path", placeholder: "/", defaultValue: "/", spellcheck: false },
        sipAction: { type: "select", label: "Action", optionSet: "sipActions", defaultValue: "OPTIONS" },
        coapMethod: { type: "select", label: "Method", optionSet: "coapMethods", defaultValue: "GET" },
        randomQuery: { type: "checkbox", label: "Random Query", defaultValue: true },
        database: { type: "text", label: "Database", spellcheck: false },
        clientId: { type: "text", label: "Client ID", spellcheck: false },
        tlsAlpn: { type: "select", label: "ALPN", optionSet: "tlsAlpn", defaultValue: "h2" },
        browserVersion: { type: "text", label: "Version", spellcheck: false }
    };
    var PROTOCOL_CATALOG = [
        { id: "bittorrent_dht", label: "BitTorrent DHT", fieldSet: [] },
        { id: "coap", label: "CoAP", fieldSet: ["host", "path", "coapMethod"], defaults: { path: "/", coapMethod: "GET" } },
        { id: "curl_quic", label: "cURL", fieldSet: ["host"] },
        { id: "dhcp_discover", label: "DHCP DISCOVER", fieldSet: [] },
        { id: "dns", label: "DNS", fieldSet: ["host"] },
        { id: "dtls", label: "DTLS (WebRTC)", fieldSet: ["host"] },
        { id: "llmnr", label: "LLMNR", fieldSet: ["host"] },
        { id: "mdns", label: "mDNS", fieldSet: ["host"] },
        { id: "nbns", label: "NBNS", fieldSet: ["host"] },
        { id: "ntp", label: "NTP", fieldSet: [] },
        { id: "quic", label: "QUIC", fieldSet: ["host"] },
        { id: "rtcp", label: "RTCP", fieldSet: [] },
        { id: "rtp", label: "RTP", fieldSet: [] },
        { id: "sip", label: "SIP", fieldSet: ["host", "sipAction"], defaults: { sipAction: "OPTIONS" } },
        { id: "ssdp", label: "SSDP", fieldSet: [] },
        { id: "stun", label: "STUN", fieldSet: ["host"] },
        { id: "utp", label: "uTP (BitTorrent)", fieldSet: [] }
    ];
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
        payloadProtocol: ".payload-protocol",
        payloadRemoveButton: ".remove-payload-btn",
        payloadDynamicFields: ".payload-dynamic-fields",
        payloadError: ".payload-error"
    };
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
        var protocolSelect = createElement("select", { className: "payload-protocol" });
        var dynamicFields = createElement("div", { className: "field-grid payload-dynamic-fields" });
        var error = createElement("p", { className: "payload-error" });

        block._state = hydrateBlockState(initialState);
        error.setAttribute("aria-live", "polite");
        block.appendChild(createBlockHeader(block, title));
        block.appendChild(createElement("div", {
            className: "field-grid payload-static-fields",
            children: [createField(UI.protocolLabel, protocolSelect, "field")]
        }));
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
        refs.removeButton.textContent = UI.removeButton;
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
        var visibleProtocols = protocols.filter(function (protocol) {
            return isQuicLikeProtocolId(protocol.id);
        });

        visibleProtocols.forEach(function (protocol) {
            select.appendChild(createElement("option", {
                value: protocol.id,
                textContent: protocol.label
            }));
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

    function isQuicLikeProtocolId(protocolId) {
        return protocolId === "quic" || protocolId === "curl_quic";
    }

    function generateOutput() {
        var mtu = normalizeMtu(dom.mtuInput.value);
        var padMtu = !!dom.padMtuCheckbox.checked;
        var lines = [];
        var capped = false;
        var hasAsyncProtocols = false;

        clearAllErrors();

        getBlocks().forEach(function (block) {
            if (isQuicLikeProtocolId(block._state.protocolId) && shouldUseAsyncQuicOutput(collectProtocolOptions(block, mtu, padMtu))) {
                hasAsyncProtocols = true;
            }
        });

        if (hasAsyncProtocols && typeof ensureGenerators().generatePayloadAsync === "function") {
            generateOutputAsync().then(function (result) {
                dom.output.value = result.lines.join("\n") + "\n";
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

        dom.output.value = lines.join("\n") + "\n";
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
        var options = collectProtocolOptions(block, mtu, padMtu);
        return appendChunkLines(lines, chunkPayload(ensureGenerators().generatePayload(block._state.protocolId, options), mtu, shouldPadOutputChunks(block._state.protocolId, options, padMtu)));
    }

    async function appendBlockLinesAsync(lines, block, mtu, padMtu) {
        var generators = ensureGenerators();
        var options = collectProtocolOptions(block, mtu, padMtu);
        var payloadBytes = isQuicLikeProtocolId(block._state.protocolId) && shouldUseAsyncQuicOutput(options) && typeof generators.generatePayloadAsync === "function"
            ? await generators.generatePayloadAsync(block._state.protocolId, options)
            : generators.generatePayload(block._state.protocolId, options);

        return appendChunkLines(lines, chunkPayload(payloadBytes, mtu, shouldPadOutputChunks(block._state.protocolId, options, padMtu)));
    }

    function collectProtocolOptions(block, mtu, padMtu) {
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

        if (isQuicLikeProtocolId(protocol.id)) {
            options.quicEncrypt = true;
            options.quicMtu = mtu;
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
            protocolSelect: block.querySelector(SELECTORS.payloadProtocol),
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

    return {
        init: init,
        constants: {
            MAX_BLOCKS: CONFIG.maxBlocks,
            MAX_OUTPUT_LINES: CONFIG.maxOutputLines,
            DEFAULT_MTU: CONFIG.defaultMtu,
            DEFAULT_HOST: CONFIG.defaultHost,
            DOMAIN_SNAPSHOTS: { global: DOMAIN_POOL.slice() },
            PROTOCOL_CATALOG: PROTOCOL_CATALOG
        },
        catalog: {
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
