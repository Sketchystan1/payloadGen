(function (root, factory) {
    var data = root.PayloadGenData || (typeof require === "function" ? require("./data.js") : null);
    var generators = root.PayloadGenGenerators || (typeof require === "function" ? require("./generators.js") : null);
    var api = factory(root, data, generators);

    if (typeof module !== "undefined" && module.exports) {
        module.exports = api;
    }

    if (typeof window !== "undefined") {
        window.PayloadGen = api;
        window.addEventListener("DOMContentLoaded", function () {
            api.init();
        });
    }
}(typeof globalThis !== "undefined" ? globalThis : this, function (root, Data, Generators) {
    "use strict";

    if (!Data) {
        throw new Error("PayloadGenData is required before app.js.");
    }

    if (!Generators) {
        throw new Error("PayloadGenGenerators is required before app.js.");
    }

    var CONFIG = Data.CONFIG;
    var STORAGE_KEYS = Data.STORAGE_KEYS;
    var CATEGORY_DEFS = Data.CATEGORY_DEFS;
    var FIELD_DEFS = Data.FIELD_DEFS;
    var OPTION_SETS = Data.OPTION_SETS;
    var PROTOCOL_CATALOG = Data.PROTOCOL_CATALOG;
    var PROTOCOL_WIKI_URLS = Data.PROTOCOL_WIKI_URLS;
    var DOMAIN_SNAPSHOTS = Data.DOMAIN_SNAPSHOTS;
    var LOCALES = Data.LOCALES;
    var POPULAR_PROTOCOL_IDS = Data.POPULAR_PROTOCOL_IDS;
    var DONATE_URL = Data.DONATE_URL;
    var IDS = {
        pageTitle: "page-title",
        pageIntro: "page-intro",
        localeToggleButton: "locale-toggle-btn",
        donateButton: "donate-btn",
        donateButtonLabel: "donate-btn-label",
        blocksPanel: "blocks-panel",
        mtuLabel: "mtu-label",
        padMtuLabel: "pad-mtu-label",
        padMtuCheckbox: "pad-mtu-checkbox",
        outputLabel: "output-label",
        blocks: "payload-blocks",
        mtuInput: "mtu-input",
        output: "output-text",
        status: "status-banner",
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
    var STATUS_CLASS_BY_TONE = {
        error: "status-error",
        info: "status-info"
    };
    var CATEGORY_MAP = Generators.helpers.createMapById(CATEGORY_DEFS);
    var PROTOCOL_MAP = Generators.helpers.createMapById(PROTOCOL_CATALOG);
    var bytesToHex = Generators.helpers.bytesToHex;
    var chunkPayload = Generators.helpers.chunkPayload;
    var clearElement = Generators.helpers.clearElement;
    var createElement = Generators.helpers.createElement;
    var getRequiredElement = Generators.helpers.getRequiredElement;
    var setElementHtml = Generators.helpers.setElementHtml;
    var setElementText = Generators.helpers.setElementText;
    var generatePayload = Generators.generatePayload;
    var dom = {
        initialized: false
    };
    var state = {
        locale: getInitialLocale(),
        status: {
            key: "ready",
            tone: "info",
            data: {}
        }
    };

    function init() {
        if (dom.initialized || typeof document === "undefined") {
            return;
        }

        cacheDom();
        bindEvents();
        resetAll(false);
        applyLocalization();
        dom.initialized = true;
    }

    function cacheDom() {
        Object.keys(IDS).forEach(function (key) {
            dom[key] = getRequiredElement(IDS[key]);
        });

        dom.metaDescription = document.querySelector('meta[name="description"]');
    }

    function bindEvents() {
        dom.localeToggleButton.addEventListener("click", function () {
            setLocale(state.locale === "en" ? "ru" : "en");
        });
        dom.addButton.addEventListener("click", handleAddBlock);
        dom.generateButton.addEventListener("click", function () {
            generateOutput();
        });
        dom.copyButton.addEventListener("click", function () {
            copyOutput();
        });
        dom.resetButton.addEventListener("click", function () {
            resetAll(true);
        });
    }

    function setLocale(locale) {
        if (locale !== "en" && locale !== "ru") {
            return;
        }

        if (state.locale === locale) {
            renderLocaleButton();
            return;
        }

        state.locale = locale;
        setStoredValue(STORAGE_KEYS.locale, locale);
        applyLocalization();
    }

    function applyLocalization() {
        document.documentElement.lang = state.locale;
        document.title = t("documentTitle");

        if (dom.metaDescription) {
            dom.metaDescription.setAttribute("content", t("pageDescription"));
        }

        setElementText(dom.pageTitle, t("pageTitle"));
        setElementHtml(dom.pageIntro, t("pageIntroHtml"));
        setElementText(dom.mtuLabel, t("mtuLabel"));
        if (dom.padMtuLabel) { setElementText(dom.padMtuLabel, t("padMtuLabel")); }
        setElementText(dom.addButton, t("addButton"));
        setElementText(dom.generateButton, t("generateButton"));
        setElementText(dom.copyButton, t("copyButton"));
        setElementText(dom.resetButton, t("resetButton"));
        dom.blocksPanel.setAttribute("aria-label", t("blocksTitle"));
        setElementText(dom.outputLabel, t("outputLabel"));
        dom.output.placeholder = t("outputPlaceholder");
        dom.donateButtonLabel.textContent = t("donateButton");
        dom.donateButton.href = DONATE_URL;
        renderLocaleButton();

        localizeBlocks();
        renderStatus();
    }

    function renderLocaleButton() {
        dom.localeToggleButton.textContent = state.locale === "en" ? "EN / RU" : "RU / EN";
        dom.localeToggleButton.setAttribute("aria-label", t("localeToggleLabel"));
        dom.localeToggleButton.setAttribute("title", t("localeToggleLabel"));
    }

    function resetAll(announceStatus) {
        clearElement(dom.blocks);
        dom.output.value = "";
        dom.mtuInput.value = String(CONFIG.defaultMtu);
        dom.padMtuCheckbox.checked = false;
        addBlock(createDefaultBlockState("quic"));
        clearAllErrors();

        if (announceStatus) {
            setStatus("reset", "info");
        }
    }

    function handleAddBlock() {
        if (getBlockCount() >= CONFIG.maxBlocks) {
            return;
        }

        addBlock(createDefaultBlockState("quic"));
        setStatus("addedBlock", "info");
    }

    function applyRandomRankedDomainToBlock(block) {
        var protocol = getProtocolMeta(block._state.protocolId);
        var pool = getRankedDomainPool();
        var domain;

        if (!protocolUsesField(protocol, "host")) {
            setStatus("randomDomainNoTargets", "error");
            return;
        }

        domain = pickWeightedRankedDomain(pool);
        setFieldValue(block, "host", domain);
        syncBlockUi(block);
        clearBlockError(block);

        setStatus("randomDomainApplied", "info", {
            count: 1,
            domain: domain,
            ranking: t("rankingRu")
        });
    }

    function createDefaultBlockState(protocolId) {
        return {
            protocolId: protocolId || "quic",
            values: createDefaultBlockValues()
        };
    }

    function hydrateBlockState(rawState) {
        var blockState = rawState || {};
        var protocolId = isKnownProtocol(blockState.protocolId) ? blockState.protocolId : "quic";
        var values = blockState.values && typeof blockState.values === "object" ? blockState.values : {};

        return {
            protocolId: protocolId,
            values: mergeDefaultBlockValues(values)
        };
    }

    function createDefaultBlockValues() {
        return {};
    }

    function mergeDefaultBlockValues(values) {
        var merged = createDefaultBlockValues();
        Object.keys(values).forEach(function (key) {
            merged[key] = values[key];
        });
        return merged;
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
        var protocolLink = createElement("a", {
            className: "protocol-link",
            href: "#",
            target: "_blank",
            rel: "noreferrer noopener"
        });
        var dynamicFields = createElement("div", { className: "field-grid payload-dynamic-fields" });
        var error = createElement("p", { className: "payload-error" });

        block._state = hydrateBlockState(initialState);
        error.setAttribute("aria-live", "polite");

        block.appendChild(createBlockHeader(block, title));
        block.appendChild(meta);
        block.appendChild(createElement("div", {
            className: "field-grid payload-static-fields",
            children: [
                createField("protocolLabel", protocolSelect, "field")
            ]
        }));
        block.appendChild(createElement("div", {
            className: "protocol-info",
            children: [protocolSummary, protocolLink]
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
        var titleWrap = createElement("div", {
            className: "payload-title-wrap",
            children: [title]
        });
        var removeButton = createTranslatableButton("removeButton", "btn btn-ghost remove-payload-btn");

        removeButton.addEventListener("click", function () {
            block.remove();

            if (getBlockCount() === 0) {
                addBlock(createDefaultBlockState("quic"));
            }

            updateBlockUi();
            setStatus("removedBlock", "info");
        });

        return createElement("div", {
            className: "payload-block-header",
            children: [titleWrap, removeButton]
        });
    }

    function createField(labelKey, control, className) {
        return createElement("label", {
            className: className,
            children: [
                createElement("span", {
                    className: "field-label",
                    textContent: t(labelKey)
                }),
                control
            ]
        });
    }

    function createCheckboxField(labelKey, control, className, noteKey) {
        var children = [
            createElement("span", {
                className: "checkbox-row",
                children: [
                    control,
                    createElement("span", {
                        className: "checkbox-label",
                        textContent: t(labelKey)
                    })
                ]
            })
        ];

        if (noteKey) {
            children.push(createElement("span", {
                className: "field-note",
                innerHTML: t(noteKey)
            }));
        }

        return createElement("label", {
            className: className,
            children: children
        });
    }

    function createTranslatableButton(labelKey, className) {
        return createElement("button", {
            type: "button",
            className: className,
            textContent: t(labelKey)
        });
    }

    function localizeBlocks() {
        getBlocks().forEach(function (block) {
            syncBlockUi(block);
        });

        updateBlockUi();
    }

    function syncBlockUi(block) {
        var refs = getBlockRefs(block);
        var availableProtocols = listProtocols();

        if (!protocolListHasId(availableProtocols, block._state.protocolId)) {
            block._state.protocolId = availableProtocols[0].id;
        }

        fillProtocolSelect(refs.protocolSelect, availableProtocols, block._state.protocolId);
        renderDynamicFields(block);
        renderProtocolInfo(block);
        refs.removeButton.textContent = t("removeButton");
        refs.meta.textContent = "";
        refs.meta.hidden = true;
        updateBlockUi();
    }

    function renderProtocolInfo(block) {
        var refs = getBlockRefs(block);
        var protocol = getProtocolMeta(block._state.protocolId);
        var summary = formatProtocolSummary(protocol);

        refs.protocolSelect.title = summary;
        refs.protocolSummary.textContent = summary;
        refs.protocolLink.textContent = t("wikiLinkLabel");
        refs.protocolLink.href = getProtocolWikiUrl(protocol.id);
        refs.protocolLink.title = summary;
    }

    function renderDynamicFields(block) {
        var protocol = getProtocolMeta(block._state.protocolId);
        var refs = getBlockRefs(block);

        clearElement(refs.dynamicFields);

        getRenderableProtocolFieldIds(protocol).forEach(function (fieldId) {
            refs.dynamicFields.appendChild(createDynamicField(block, protocol, fieldId));
        });
    }

    function getProtocolOptionFieldIds(protocol) {
        var fieldIds = protocol.fieldSet.slice();

        if (protocol.id !== "quic") {
            fieldIds.push("awgSplitMode");
        }

        return fieldIds;
    }

    function getRenderableProtocolFieldIds(protocol) {
        return getProtocolOptionFieldIds(protocol).filter(function (fieldId) {
            return !(protocol.id === "quic" && fieldId === "quicEncrypt");
        });
    }

    function createDynamicField(block, protocol, fieldId) {
        var fieldDef = FIELD_DEFS[fieldId];
        var value = getDisplayFieldValue(block, protocol, fieldId);
        var className = fieldDef.className || "field";

        if (fieldId === "host") {
            return createHostField(block, value);
        }

        if (fieldDef.type === "checkbox") {
            var checkbox = createElement("input", {
                type: "checkbox",
                className: "payload-field payload-field-" + fieldId
            });
            checkbox.checked = !!value;
            checkbox.addEventListener("change", function () {
                setFieldValue(block, fieldId, checkbox.checked);
                syncBlockUi(block);
                clearBlockError(block);
            });
            return createCheckboxField(fieldDef.labelKey, checkbox, "field checkbox-field", fieldDef.noteKey);
        }

        if (fieldDef.type === "select") {
            var select = createElement("select", {
                className: "payload-field payload-field-" + fieldId
            });
            fillSelectOptions(select, getFieldOptions(fieldDef.optionSet), String(value));
            select.addEventListener("change", function () {
                setFieldValue(block, fieldId, select.value);
                syncBlockUi(block);
                clearBlockError(block);
            });
            return createField(fieldDef.labelKey, select, className);
        }

        if (fieldDef.type === "textarea") {
            var textarea = createElement("textarea", {
                className: "payload-field payload-field-" + fieldId,
                rows: fieldDef.rows || 3,
                placeholder: fieldDef.placeholder || ""
            });
            textarea.spellcheck = !!fieldDef.spellcheck;
            textarea.value = String(value);
            textarea.addEventListener("input", function () {
                setFieldValue(block, fieldId, textarea.value);
                clearBlockError(block);
            });
            return createField(fieldDef.labelKey, textarea, className);
        }

        var input = createElement("input", {
            type: "text",
            className: "payload-field payload-field-" + fieldId,
            placeholder: fieldDef.placeholder || "",
            autocomplete: "off"
        });
        input.spellcheck = !!fieldDef.spellcheck;
        input.value = String(value);
        input.addEventListener("input", function () {
            setFieldValue(block, fieldId, input.value);
            clearBlockError(block);
        });
        return createField(fieldDef.labelKey, input, className);
    }

    function createHostField(block, value) {
        var input = createElement("input", {
            type: "text",
            className: "payload-field payload-field-host",
            placeholder: FIELD_DEFS.host.placeholder || "",
            autocomplete: "off"
        });
        var randomButton = createTranslatableButton("randomHostButton", "btn btn-ghost");

        input.spellcheck = !!FIELD_DEFS.host.spellcheck;
        input.value = String(value);
        input.addEventListener("input", function () {
            setFieldValue(block, "host", input.value);
            clearBlockError(block);
        });

        randomButton.addEventListener("click", function () {
            applyRandomRankedDomainToBlock(block);
        });

        return createField("hostLabel", createElement("div", {
            className: "host-field-row",
            children: [
                input,
                createElement("div", {
                    className: "host-field-actions",
                    children: [randomButton]
                })
            ]
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
            return getBrowserDefaultVersion(getResolvedBrowserProfile(block, protocol));
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
        return (OPTION_SETS[optionSetId] || []).map(function (option) {
            return {
                value: option.value,
                label: t(option.labelKey)
            };
        });
    }

    function fillSelectOptions(select, options, selectedValue) {
        clearElement(select);

        options.forEach(function (option) {
            select.appendChild(createElement("option", {
                value: String(option.value),
                textContent: option.label
            }));
        });

        select.value = String(selectedValue);
    }

    function fillProtocolSelect(select, protocols, selectedId) {
        var groupedByCategory = groupProtocolsByCategory(protocols);

        clearElement(select);

        // Native optgroups keep the catalog compact while preserving the curated category order.
        groupedByCategory.forEach(function (group) {
            var optgroup = createElement("optgroup", {
                label: t(CATEGORY_MAP[group.categoryId].labelKey)
            });

            group.protocols.forEach(function (protocol) {
                optgroup.appendChild(createElement("option", {
                    value: protocol.id,
                    textContent: formatProtocolOptionLabel(protocol),
                    title: getProtocolShortDescription(protocol)
                }));
            });

            select.appendChild(optgroup);
        });

        select.value = selectedId;
    }

    function updateBlockUi() {
        getBlocks().forEach(function (block, index) {
            var refs = getBlockRefs(block);

            refs.title.textContent = t("payloadBlockTitle") + " (i" + (index + 1) + ")";
            refs.removeButton.hidden = index === 0;
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

        // Check if any blocks use async-only formatting or generation.
        getBlocks().forEach(function (block) {
            if (block._state.protocolId === "quic" && shouldUseAsyncQuicOutput(collectProtocolOptions(block))) {
                hasAsyncProtocols = true;
            }
        });

        if (hasAsyncProtocols && typeof Generators.generatePayloadAsync === "function") {
            // Use async generation
            generateOutputAsync().then(function (result) {
                dom.output.value = result.lines.join("\n");
                setGenerationStatus(result.lines, result.capped, result.mtu);
            }).catch(function (error) {
                setStatus("noOutput", "error");
                console.error("Async generation failed:", error);
            });

            return {
                mtu: mtu,
                lines: [],
                capped: false,
                pending: true
            };
        }

        // Synchronous generation
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
        setGenerationStatus(lines, capped, mtu);

        return {
            mtu: mtu,
            lines: lines,
            capped: capped
        };
    }

    async function generateOutputAsync() {
        var mtu = normalizeMtu(dom.mtuInput.value);
        var padMtu = !!dom.padMtuCheckbox.checked;
        var lines = [];
        var capped = false;
        var blocks = getBlocks();

        clearAllErrors();

        for (var i = 0; i < blocks.length; i++) {
            var block = blocks[i];
            
            if (lines.length >= CONFIG.maxOutputLines) {
                capped = true;
                break;
            }

            try {
                capped = await appendBlockLinesAsync(lines, block, mtu, padMtu) || capped;
            } catch (error) {
                setBlockError(block, error && error.message ? error.message : "Failed to generate this payload.");
            }
        }

        return {
            mtu: mtu,
            lines: lines,
            capped: capped
        };
    }

    function appendBlockLines(lines, block, mtu, padMtu) {
        var options = collectProtocolOptions(block);
        var protocolId = block._state.protocolId;

        if (protocolId === "quic" && isSplitModeEnabled(options.quicAwgLevel)) {
            throw new Error("AWG segmented QUIC output requires async generation.");
        }

        var payloadBytes = generatePayload(protocolId, options);
        var chunks = chunkPayload(payloadBytes, mtu, padMtu);

        return appendChunkLines(lines, chunks, protocolId, options);
    }

    async function appendBlockLinesAsync(lines, block, mtu, padMtu) {
        var options = collectProtocolOptions(block);
        var protocolId = block._state.protocolId;
        var payloadBytes;

        if (protocolId === "quic" && isSplitModeEnabled(options.quicAwgLevel)) {
            if (lines.length >= CONFIG.maxOutputLines) {
                return true;
            }

            if (typeof Generators.generateQuicAwgSignaturePartsAsync !== "function" &&
                typeof Generators.generateQuicAwgSignatureAsync !== "function") {
                throw new Error("AWG segmented QUIC output is not available in this build.");
            }

            var awgResult;

            if (typeof Generators.generateQuicAwgSignaturePartsAsync === "function") {
                awgResult = await Generators.generateQuicAwgSignaturePartsAsync(options);
            } else {
                awgResult = {
                    expression: await Generators.generateQuicAwgSignatureAsync(options),
                    packetLength: 0
                };
            }

            lines.push(formatOutputExpressionLine(
                lines.length + 1,
                maybePadAwgExpression(awgResult.expression, awgResult.packetLength, mtu, padMtu)
            ));
            return false;
        }

        // Use async generator for protocols that support it
        if (typeof Generators.generatePayloadAsync === "function" && 
            (protocolId === "quic" && shouldUseAsyncQuicOutput(options))) {
            payloadBytes = await Generators.generatePayloadAsync(protocolId, options);
        } else {
            payloadBytes = generatePayload(protocolId, options);
        }

        var chunks = chunkPayload(payloadBytes, mtu, padMtu);

        return appendChunkLines(lines, chunks, protocolId, options);
    }

    function collectProtocolOptions(block) {
        var protocol = getProtocolMeta(block._state.protocolId);
        var options = {};

        getProtocolOptionFieldIds(protocol).forEach(function (fieldId) {
            var value = getResolvedOptionValue(block, protocol, fieldId);

            if (fieldId === "host") {
                options.host = normalizeHost(value);
                return;
            }

            if (fieldId === "path") {
                options.path = normalizePath(value);
                return;
            }

            if (FIELD_DEFS[fieldId].type === "checkbox") {
                options[fieldId] = !!value;
                return;
            }

            options[fieldId] = String(value);
        });

        if (options.browserProfile && !options.browserVersion) {
            options.browserVersion = getBrowserDefaultVersion(options.browserProfile);
        }

        if (protocol.id === "quic") {
            options.quicEncrypt = true;
            options.quicVersion = String(options.quicVersion || "v1");
        }

        return options;
    }

    function appendChunkLines(lines, chunks, protocolId, options) {
        var wasCapped = false;
        var index;

        for (index = 0; index < chunks.length; index += 1) {
            if (lines.length >= CONFIG.maxOutputLines) {
                wasCapped = true;
                break;
            }

            lines.push(formatChunkLine(lines.length + 1, chunks[index], protocolId, options));
        }

        return wasCapped;
    }

    function formatChunkLine(lineNumber, chunk, protocolId, options) {
        if (shouldUseGenericSplitOutput(protocolId, options)) {
            return formatOutputExpressionLine(lineNumber, formatGenericSplitExpression(chunk, options.awgSplitMode));
        }

        return formatOutputLine(lineNumber, chunk);
    }

    function shouldUseGenericSplitOutput(protocolId, options) {
        return protocolId !== "quic" && !!(options && isSplitModeEnabled(options.awgSplitMode));
    }

    function getResolvedOptionValue(block, protocol, fieldId) {
        if (Object.prototype.hasOwnProperty.call(block._state.values, fieldId)) {
            return block._state.values[fieldId];
        }

        return getFieldDefault(protocol, fieldId);
    }

    function setGenerationStatus(lines, capped, mtu) {
        if (lines.length === 0) {
            setStatus("noOutput", "error");
            return;
        }

        if (capped) {
            setStatus("generatedCapped", "info", { count: lines.length, mtu: mtu });
            return;
        }

        setStatus("generated", "info", { count: lines.length, mtu: mtu });
    }

    function copyOutput() {
        var content = dom.output.value.trim();

        if (!content) {
            content = generateOutput().lines.join("\n");
        }

        if (!content) {
            setStatus("copyEmpty", "error");
            return Promise.resolve(false);
        }

        return copyText(content).then(function () {
            setStatus("copied", "info", { count: content.split("\n").length });
            return true;
        }).catch(function () {
            setStatus("copyFailed", "error");
            return false;
        });
    }

    function copyText(text) {
        var secureClipboardAvailable = typeof navigator !== "undefined" &&
            navigator.clipboard &&
            typeof navigator.clipboard.writeText === "function" &&
            typeof isSecureContext !== "undefined" &&
            isSecureContext;

        if (secureClipboardAvailable) {
            return navigator.clipboard.writeText(text);
        }

        return new Promise(function (resolve, reject) {
            try {
                dom.output.focus();
                dom.output.select();
                dom.output.setSelectionRange(0, dom.output.value.length);

                if (typeof document !== "undefined" && typeof document.execCommand === "function" && document.execCommand("copy")) {
                    resolve();
                    return;
                }
            } catch (error) {
                reject(error);
                return;
            }

            reject(new Error("Copy command was not available."));
        });
    }

    function setStatus(key, tone, data) {
        state.status = {
            key: key,
            tone: tone || "info",
            data: data || {}
        };
        renderStatus();
    }

    function renderStatus() {
        var tone = state.status.tone || "info";

        dom.status.textContent = getStatusText(state.status.key, state.status.data);

        Object.keys(STATUS_CLASS_BY_TONE).forEach(function (statusTone) {
            dom.status.classList.remove(STATUS_CLASS_BY_TONE[statusTone]);
        });

        if (STATUS_CLASS_BY_TONE[tone]) {
            dom.status.classList.add(STATUS_CLASS_BY_TONE[tone]);
        }
    }

    function getStatusText(key, data) {
        if (key === "addedBlock") {
            return t("statusAddedBlock");
        }

        if (key === "removedBlock") {
            return t("statusRemovedBlock");
        }

        if (key === "reset") {
            return t("statusReset");
        }

        if (key === "ready") {
            return t("statusReady");
        }

        if (key === "noOutput") {
            return t("statusNoOutput");
        }

        if (key === "copyEmpty") {
            return t("statusCopyEmpty");
        }

        if (key === "copyFailed") {
            return t("statusCopyFailed");
        }

        if (key === "randomDomainNoTargets") {
            return t("statusRandomDomainNoTargets");
        }

        if (key === "generated") {
            return state.locale === "ru"
                ? "Сгенерировано частей payload: " + data.count + ". MTU " + data.mtu + "."
                : "Generated " + data.count + " payload part(s) using MTU " + data.mtu + ".";
        }

        if (key === "generatedCapped") {
            return state.locale === "ru"
                ? "Сгенерировано частей payload: " + data.count + ". " + t("statusCappedOutput")
                : "Generated " + data.count + " payload part(s). " + t("statusCappedOutput");
        }

        if (key === "copied") {
            return state.locale === "ru"
                ? "Скопировано строк payload: " + data.count + "."
                : "Copied " + data.count + " payload line(s) to the clipboard.";
        }

        if (key === "randomDomainApplied") {
            return state.locale === "ru"
                ? "Выбран домен " + data.domain + " из рейтинга " + data.ranking + " и применён к " + data.count + " блок(ам)."
                : "Picked " + data.domain + " from the " + data.ranking + " ranking and applied it to " + data.count + " block(s).";
        }

        return t("statusReady");
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

        if (!path) {
            return "/";
        }

        if (path.charAt(0) !== "/") {
            return "/" + path;
        }

        return path;
    }

    function formatOutputLine(lineNumber, bytes) {
        return "i" + lineNumber + "=<b 0x" + bytesToHex(bytes) + ">";
    }

    function formatOutputExpressionLine(lineNumber, expression) {
        return "i" + lineNumber + "=" + String(expression || "");
    }

    function maybePadAwgExpression(expression, packetLength, mtu, padMtu) {
        if (!padMtu || !Number.isFinite(packetLength) || packetLength <= 0 || packetLength >= mtu) {
            return String(expression || "");
        }

        return String(expression || "") + "<b 0x" + repeatHexByte("00", mtu - packetLength) + ">";
    }

    function repeatHexByte(hexByte, count) {
        return new Array(Math.max(0, count) + 1).join(String(hexByte || ""));
    }

    function normalizeSplitMode(level) {
        var normalized = String(level == null ? "" : level).trim().toLowerCase();

        if (!normalized || normalized === "off") {
            return null;
        }

        if (normalized === "0" || normalized === "1" || normalized === "2" || normalized === "3" || normalized === "4") {
            return normalized;
        }

        return "0";
    }

    function isSplitModeEnabled(level) {
        return normalizeSplitMode(level) !== null;
    }

    function shouldUseAsyncQuicOutput(options) {
        return !!(options && (options.quicEncrypt || isSplitModeEnabled(options.quicAwgLevel)));
    }

    function formatGenericSplitExpression(bytes, level) {
        var normalized = normalizeSplitMode(level);
        var length = bytes.length;
        var prefixEnd;
        var hiddenEnd;
        var suffixStart;

        if (normalized == null || length === 0) {
            return "<b 0x" + bytesToHex(bytes) + ">";
        }

        if (normalized === "0") {
            prefixEnd = Math.min(length, Math.max(1, Math.min(8, length)));
            hiddenEnd = Math.min(length, prefixEnd + Math.max(1, Math.min(16, length - prefixEnd)));
            return buildSplitExpression(bytes, [
                { visible: true, start: 0, end: prefixEnd },
                { visible: false, start: prefixEnd, end: hiddenEnd },
                { visible: true, start: hiddenEnd, end: length }
            ]);
        }

        if (normalized === "1") {
            prefixEnd = Math.min(length, Math.max(1, Math.floor(length / 3)));
            hiddenEnd = Math.min(length, prefixEnd + Math.max(1, Math.floor(length / 3)));
            return buildSplitExpression(bytes, [
                { visible: true, start: 0, end: prefixEnd },
                { visible: false, start: prefixEnd, end: hiddenEnd },
                { visible: true, start: hiddenEnd, end: length }
            ]);
        }

        if (normalized === "2") {
            prefixEnd = Math.min(length, Math.max(1, Math.floor(length / 4)));
            hiddenEnd = Math.min(length, prefixEnd + Math.max(1, Math.floor(length / 2)));
            return buildSplitExpression(bytes, [
                { visible: true, start: 0, end: prefixEnd },
                { visible: false, start: prefixEnd, end: hiddenEnd },
                { visible: true, start: hiddenEnd, end: length }
            ]);
        }

        if (normalized === "3") {
            return buildSplitExpression(bytes, [
                { visible: true, start: 0, end: Math.min(1, length) },
                { visible: false, start: Math.min(1, length), end: length }
            ]);
        }

        suffixStart = Math.max(1, length - Math.min(8, Math.max(0, length - 1)));

        while (suffixStart < length && bytes[suffixStart] === 0) {
            suffixStart += 1;
        }

        return buildSplitExpression(bytes, [
            { visible: true, start: 0, end: Math.min(1, length) },
            { visible: false, start: Math.min(1, length), end: Math.min(suffixStart, length) },
            { visible: true, start: Math.min(suffixStart, length), end: length }
        ]);
    }

    function buildSplitExpression(bytes, segments) {
        var expression = "";

        segments.forEach(function (segment) {
            var start = Math.max(0, segment.start);
            var end = Math.max(start, Math.min(bytes.length, segment.end));

            if (end <= start) {
                return;
            }

            if (segment.visible) {
                expression += "<b 0x" + bytesToHex(bytes.slice(start, end)) + ">";
                return;
            }

            expression += "<r " + (end - start) + ">";
        });

        return expression || "<b 0x" + bytesToHex(bytes) + ">";
    }

    function t(key) {
        return (LOCALES[state.locale] && LOCALES[state.locale][key]) ||
            LOCALES.en[key] ||
            key;
    }

    function detectLocale() {
        var browserLocale;

        browserLocale = typeof navigator !== "undefined" ? String(navigator.language || "").toLowerCase() : "";
        return browserLocale.indexOf("ru") === 0 ? "ru" : "en";
    }

    function getInitialLocale() {
        var storedLocale = getStoredValue(STORAGE_KEYS.locale);

        if (storedLocale === "ru" || storedLocale === "en") {
            return storedLocale;
        }

        return detectLocale();
    }

    function getStoredValue(key) {
        try {
            if (typeof root.localStorage === "undefined") {
                return null;
            }

            return root.localStorage.getItem(key);
        } catch (error) {
            return null;
        }
    }

    function setStoredValue(key, value) {
        try {
            if (typeof root.localStorage === "undefined") {
                return;
            }

            root.localStorage.setItem(key, value);
        } catch (error) {
            return;
        }
    }

    function getTransportLabelKey(transport) {
        return transport === "tcp" ? "transportTcp" : "transportUdp";
    }

    function getProtocolShortDescription(protocol) {
        return truncateText(t(protocol.descriptorKey), 160);
    }

    function formatProtocolSummary(protocol) {
        var transport = t(getTransportLabelKey(protocol.transport));
        var summary = getProtocolShortDescription(protocol);

        if (summary.charAt(summary.length - 1) !== ".") {
            summary += ".";
        }

        var portInfo = protocol.port ? "port: " + protocol.port + " | " : "";
        return transport + " | " + portInfo + summary;
    }

    function getProtocolWikiUrl(protocolId) {
        var localeUrls = PROTOCOL_WIKI_URLS[state.locale] || {};
        return localeUrls[protocolId] || PROTOCOL_WIKI_URLS.en[protocolId] || "#";
    }

    function getResolvedBrowserProfile(block, protocol) {
        if (Object.prototype.hasOwnProperty.call(block._state.values, "browserProfile")) {
            return String(block._state.values.browserProfile);
        }

        return getFieldDefault(protocol, "browserProfile");
    }

    function getBrowserDefaultVersion(profileId) {
        var browserProfile = Data.BROWSER_PROFILES[profileId] || Data.BROWSER_PROFILES.chrome;
        return browserProfile.defaultVersion;
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

    function getRankedDomainPool() {
        return DOMAIN_SNAPSHOTS.ru;
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

        roll = randomIntExclusive(totalWeight);

        for (index = 0; index < domains.length; index += 1) {
            roll -= domains.length - index;

            if (roll < 0) {
                return domains[index];
            }
        }

        return domains[0];
    }

    function randomIntExclusive(maxExclusive) {
        return Math.floor(Math.random() * Math.max(1, maxExclusive));
    }

    function listProtocols() {
        return PROTOCOL_CATALOG.slice().sort(function (left, right) {
            var categoryCompare = CATEGORY_MAP[left.categoryId].rank - CATEGORY_MAP[right.categoryId].rank;

            if (categoryCompare !== 0) {
                return categoryCompare;
            }

            if (left.rank !== right.rank) {
                return left.rank - right.rank;
            }

            return t(left.labelKey).localeCompare(t(right.labelKey));
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
        return protocols.some(function (protocol) {
            return protocol.id === protocolId;
        });
    }

    function isPopularProtocol(protocolId) {
        return POPULAR_PROTOCOL_IDS.indexOf(protocolId) !== -1;
    }

    function formatProtocolOptionLabel(protocol) {
        return t(protocol.labelKey) + (isPopularProtocol(protocol.id) ? " ★" : "");
    }

    function truncateText(text, maxLength) {
        var normalized = String(text || "").trim();

        if (normalized.length <= maxLength) {
            return normalized;
        }

        return normalized.slice(0, Math.max(0, maxLength - 1)).trimEnd() + "…";
    }


    return {
        init: init,
        constants: {
            MAX_BLOCKS: CONFIG.maxBlocks,
            MAX_OUTPUT_LINES: CONFIG.maxOutputLines,
            DEFAULT_MTU: CONFIG.defaultMtu,
            DEFAULT_HOST: CONFIG.defaultHost,
            CATEGORY_DEFS: CATEGORY_DEFS,
            DOMAIN_SNAPSHOTS: DOMAIN_SNAPSHOTS,
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
            generatePayload: generatePayload
        }
    };
}));
