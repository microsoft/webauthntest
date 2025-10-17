



(function () {
    /**
     * @typedef {import('./types').EncodedAttestationResponse} EncodedAttestationResponse
     * @typedef {import('./types').EncodedAssertionResponse} EncodedAssertionResponse
     * @typedef {import('./types').Credential} Credential
     */

    /**
     * @type Array<Credential>
     */
    var credentials = [];
    var conditionalAuthOperationInProgress = false;
    var ongoingAuth = null;

    $(window).on('load', async function () {
        var createDialog = document.querySelector('#createDialog');
        if (!createDialog.showModal) {
            dialogPolyfill.registerDialog(createDialog);
        }

        var getDialog = document.querySelector('#getDialog');
        if (!getDialog.showModal) {
            dialogPolyfill.registerDialog(getDialog);
        }

        var creationDataDialog = document.querySelector('#creationDataDialog');
        if (!creationDataDialog.showModal) {
            dialogPolyfill.registerDialog(creationDataDialog);
        }

        var authenticationDataDialog = document.querySelector('#authenticationDataDialog');
        if (!authenticationDataDialog.showModal) {
            dialogPolyfill.registerDialog(authenticationDataDialog);
        }

        var moreDialog = document.querySelector('#moreDialog');
        if (!moreDialog.showModal) {
            dialogPolyfill.registerDialog(moreDialog);
        }

        if (!Cookies.get("uid")) {
            //user is signed out
            Cookies.remove('uid');
            window.location.href = "./login.html";
        }

        $('body').removeClass("cloak");

        setTimeout(() => {
            updateCredentials().catch(e => toast("ERROR: " + e));
        }, 100);

        $('#signOutButton').click(() => {
            Cookies.remove('uid');
            window.location.href = "./login.html";
        });

        $('#createButton').click(() => {
            createDialog.showModal();
        });

        $('#getButton').click(async () => {

            if (conditionalAuthOperationInProgress === false)
            {
                if (window.PublicKeyCredential) {
                    try {
                        const capabilities = await PublicKeyCredential.getClientCapabilities();
                        if (capabilities.conditionalGet) {
                            var id;
                            conditionalAuthOperationInProgress = true;
                            console.log("Starting Conditional Auth Operation");
                            getChallenge().then(challenge => {
                                return getAssertion(challenge, true)
                            }).then(credential => {
                                id = credential.id;
                                return updateCredentials();
                            }).then(() => {
                                conditionalAuthOperationInProgress = false;
                                getDialog.close();
                                setTimeout(() => {
                                    highlightCredential(id);
                                    toast("Successful AutoFill Assertion");
                                }, 50);
                            }).catch(e => {
                                console.log(e);
                            });
                        }
                    } catch (e) {
                        console.error(e.message);
                    }
                }
            }

            getDialog.showModal();
        });

        $('#moreButton').click(async () => {
            if (!PublicKeyCredential || typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !== "function") {
                $("#moreDialog_platformAuthenticatorAvailable").text("Not defined");
            } else {
                PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().then(availability => {
                    $("#moreDialog_platformAuthenticatorAvailable").text(availability ? "Available" : "Not available");
                }).catch(e => {
                    $("#moreDialog_platformAuthenticatorAvailable").text("Error");
                });
            }

            if (!PublicKeyCredential || typeof PublicKeyCredential.isConditionalMediationAvailable !== "function") {
                $("#moreDialog_autofillUiSupported").text("Not defined");
            } else {
                let isConditionalMediationAvailable = await PublicKeyCredential.isConditionalMediationAvailable();
                $("#moreDialog_autofillUiSupported").text(isConditionalMediationAvailable);
            }

            if (!PublicKeyCredential || typeof PublicKeyCredential.getClientCapabilities !== "function") {
                $("#moreDialog_ClientCapabilities").text("Not defined");
            } else {
                try {
                    let capabilities = await PublicKeyCredential.getClientCapabilities();
                    $("#moreDialog_ClientCapabilities tr").remove();
                    $("#moreDialog_ClientCapabilities").append(`<tr><th align:left>Capability</th><th>Supported?</th></tr>`);
                    Object.keys(capabilities).forEach((e) => {
                        $("#moreDialog_ClientCapabilities").append(`<tr><td>${e}</td><td>${capabilities[e]}</td></tr>`);
                    })
                 } catch (error) {
                    console.error('Error getting client capabilities:', error);
                 }
            }
            moreDialog.showModal();
        });

        $('#cborButton').click(() => {
            window.location.href = "./cbor.html";
        });

        $('#createDialog_createButton').click(() => {
            var id;

            disableControls();

            getChallenge().then(challenge => {
                return createCredential(challenge)
            }).then(credential => {
                id = credential.id;
                return updateCredentials();
            }).then(() => {
                createDialog.close();
                enableControls();
                setTimeout(() => {
                    highlightCredential(id);
                    toast("Successfully created credential");
                }, 50);

            }).catch(e => {
                enableControls();
                createDialog.close();
                toast("ERROR: " + e);
            });
        });

        $('#createDialog_cancelButton').click(() => {
            createDialog.close();
        });

        $('#getDialog_getButton').click(() => {
            var id;

            disableControls();
            getChallenge().then(challenge => {
                return getAssertion(challenge, false)
            }).then(credential => {
                id = credential.id;
                return updateCredentials();
            }).then(() => {
                getDialog.close();
                enableControls();
                setTimeout(() => {
                    highlightCredential(id);
                    toast("Successful assertion");
                }, 50);

            }).catch(e => {
                enableControls();
                getDialog.close();
                toast("ERROR: " + e);
            });
        });

        $('#moreDialog_closeButton').click(() => {
            moreDialog.close();
        });

        $('#getDialog_cancelButton').click(() => {
            if (ongoingAuth) {
                conditionalAuthOperationInProgress = false;
                ongoingAuth.abort('User cancelled get dialog');
                ongoingAuth = null;
            }
            enableControls();
            getDialog.close();
        });

        $('#creationDataDialog_closeButton').click(() => {
            creationDataDialog.close();
        });
        $('#creationDataDialog_xButton').click(() => {
            creationDataDialog.close();
        });

        $('#authenticationDataDialog_closeButton').click(() => {
            authenticationDataDialog.close();
        });
        $('#authenticationDataDialog_xButton').click(() => {
            authenticationDataDialog.close();
        });

        // Initialize priority lists (algorithms + hints) via generalized helper
        initPriorityList({
            listId: 'create_algorithmsList',
            upClass: 'alg-up',
            downClass: 'alg-down',
            resetButtonId: 'algorithmsResetOrder',
            enforceMinimumChecked: true,
            minimumWarningElementId: 'algorithmsWarning',
            disableButtonId: 'createDialog_createButton'
        });
        initPriorityList({
            listId: 'create_hintsList',
            upClass: 'hint-up',
            downClass: 'hint-down',
            resetButtonId: 'hintsResetOrderCreate'
        });
        initPriorityList({
            listId: 'get_hintsList',
            upClass: 'hint-up',
            downClass: 'hint-down',
            resetButtonId: 'hintsResetOrderGet'
        });
    });

    /**
     * Generalized priority list initializer (algorithms, hints, etc.)
     * @param {Object} cfg configuration
     * @param {string} cfg.listId UL element id containing <li>
     * @param {string} cfg.upClass CSS class for move-up buttons
     * @param {string} cfg.downClass CSS class for move-down buttons
     * @param {string} [cfg.resetButtonId] optional reset button id
     * @param {boolean} [cfg.enforceMinimumChecked] enforce at least one checkbox selected
     * @param {string} [cfg.minimumWarningElementId] element id to toggle for minimum warning
     * @param {string} [cfg.disableButtonId] button id to disable when minimum not met
     */
    function initPriorityList(cfg) {
        var list = document.getElementById(cfg.listId);
        if (!list) return;
        var originalOrder = Array.from(list.children).map(li => li.id);
        var warningEl = cfg.minimumWarningElementId ? document.getElementById(cfg.minimumWarningElementId) : null;
        var disableBtn = cfg.disableButtonId ? document.getElementById(cfg.disableButtonId) : null;

        function updateMinimumState() {
            if (!cfg.enforceMinimumChecked) return;
            var checked = list.querySelectorAll('input[type="checkbox"]:checked').length;
            if (checked === 0) {
                if (warningEl) warningEl.style.display = 'block';
                if (disableBtn) disableBtn.disabled = true;
            } else {
                if (warningEl) warningEl.style.display = 'none';
                if (disableBtn) disableBtn.disabled = false;
            }
        }

        function updateButtonDisabledState() {
            var items = Array.from(list.children);
            items.forEach((li, idx) => {
                var up = li.querySelector('.' + cfg.upClass);
                var down = li.querySelector('.' + cfg.downClass);
                if (up) up.disabled = (idx === 0);
                if (down) down.disabled = (idx === items.length - 1);
            });
            updateMinimumState();
        }

        function move(li, direction) {
            if (!li) return;
            if (direction === -1 && li.previousElementSibling) {
                li.parentNode.insertBefore(li, li.previousElementSibling);
            } else if (direction === 1 && li.nextElementSibling) {
                li.parentNode.insertBefore(li.nextElementSibling, li);
            }
            updateButtonDisabledState();
        }

        list.addEventListener('click', (e) => {
            var target = e.target;
            if (target.classList.contains(cfg.upClass)) {
                move(target.closest('li'), -1);
            } else if (target.classList.contains(cfg.downClass)) {
                move(target.closest('li'), 1);
            }
        });

        if (cfg.enforceMinimumChecked) {
            list.querySelectorAll('input[type="checkbox"]').forEach(cb => {
                cb.addEventListener('change', updateMinimumState);
            });
        }

        if (cfg.resetButtonId) {
            var resetBtn = document.getElementById(cfg.resetButtonId);
            if (resetBtn) {
                resetBtn.addEventListener('click', () => {
                    var currentLis = Array.from(list.children);
                    currentLis.sort((a, b) => originalOrder.indexOf(a.id) - originalOrder.indexOf(b.id));
                    currentLis.forEach(li => list.appendChild(li));
                    updateButtonDisabledState();
                });
            }
        }

        // Drag & drop
        Array.from(list.children).forEach(li => {
            li.draggable = true;
            li.addEventListener('dragstart', (ev) => {
                ev.dataTransfer.setData('text/plain', li.id);
            });
            li.addEventListener('dragover', (ev) => {
                ev.preventDefault();
                var draggingId = ev.dataTransfer.getData('text/plain');
                var draggingEl = document.getElementById(draggingId);
                if (!draggingEl || draggingEl === li) return;
                var rect = li.getBoundingClientRect();
                var before = (ev.clientY - rect.top) < rect.height / 2;
                if (before) {
                    list.insertBefore(draggingEl, li);
                } else if (li.nextSibling !== draggingEl) {
                    list.insertBefore(draggingEl, li.nextSibling);
                }
            });
            li.addEventListener('drop', (ev) => {
                ev.preventDefault();
                updateButtonDisabledState();
            });
        });

        updateButtonDisabledState();
        updateMinimumState();
    }

    function getChallenge() {
        return rest_get(
            "/challenge"
        ).then(response => {
            return response.json();
        }).then(response => {
            if (response.error) {
                return Promise.reject(response.error);
            }
            else {
                var challenge = stringToArrayBuffer(response.result);
                return Promise.resolve(challenge);
            }
        });
    }

    /**
     * Calls the .create() webauthn APIs and sends returns to server
     * @param {ArrayBuffer} challenge challenge to use
     * @return {Promise<Credential>} server response object
     */
    function createCredential(challenge) {
        if (!PublicKeyCredential)
            return Promise.reject("Error: WebAuthn APIs are not present on this device");

        var createCredentialOptions = {
            rp: {
                name: "WebAuthn Test Server",
                icon: "https://example.com/rpIcon.png"
            },
            user: {
                icon: "https://example.com/userIcon.png"
            },
            challenge: challenge,
            pubKeyCredParams: [],
            timeout: 180000,
            excludeCredentials: [],
            authenticatorSelection: {},
            attestation: undefined,
            extensions: {}
        };

        switch ($('#create_rpInfo').val()) {
            case "normal":
                createCredentialOptions.rp.id = window.location.hostname;
                break;
            case "suffix":
                createCredentialOptions.rp.id = "suffix." + window.location.hostname;
                break;
            case "securityerror":
                createCredentialOptions.rp.id = "foo.com";
                break;
            case "emptyrpid":
                createCredentialOptions.rp.id = "";
                break;
            case "emptyrpname":
                createCredentialOptions.rp.name = undefined;
                break;
            case "emptyrpicon":
                createCredentialOptions.rp.icon = undefined;
            case "undefined":
            default:
                break;
        }

        switch ($('#create_userInfo').val()) {
            case "empty":
                createCredentialOptions.user.displayName = "";
                createCredentialOptions.user.name = "";
                break;
            case "alice":
                createCredentialOptions.user.displayName = "Alice Doe";
                createCredentialOptions.user.name = "alice@example.com";
                break;
            case "stella":
                createCredentialOptions.user.displayName = "Stella Ipsum";
                createCredentialOptions.user.name = "stella@example.com";
                break;
            case "john":
                createCredentialOptions.user.displayName = "John Smith";
                createCredentialOptions.user.name = "john@example.com";
                break;
            case "mike":
                createCredentialOptions.user.displayName = "Mike Marlowe";
                createCredentialOptions.user.name = "mike@example.com";
                break;
            case "bob":
            default:
                createCredentialOptions.user.displayName = "Bob Smith";
                createCredentialOptions.user.name = "bob@example.com";
                break;
        }
        //don't do this in production code. user.id should not contain PII
        createCredentialOptions.user.id = stringToArrayBuffer(createCredentialOptions.user.name);

        // New prioritized algorithm collection: iterate list in current DOM order
        var algItems = document.querySelectorAll('#create_algorithmsList li');
        algItems.forEach(li => {
            var cb = li.querySelector('input[type="checkbox"]');
            if (cb && cb.checked) {
                var algId = parseInt(li.getAttribute('data-alg-id'), 10);
                if (!isNaN(algId)) {
                    createCredentialOptions.pubKeyCredParams.push({ type: 'public-key', alg: algId });
                }
            }
        });
        if (createCredentialOptions.pubKeyCredParams.length === 0) {
            return Promise.reject("No algorithms selected. Select at least one algorithm.");
        }

        // Collect prioritized hints (optional)
        var hintItems = document.querySelectorAll('#create_hintsList li');
        var hints = [];
        hintItems.forEach(li => {
            var cb = li.querySelector('input[type="checkbox"]');
            if (cb && cb.checked) {
                var hintVal = li.getAttribute('data-hint');
                if (hintVal) hints.push(hintVal);
            }
        });
        if (hints.length > 0) {
            createCredentialOptions.hints = hints; // WebAuthn Level 3 hints
        }

        var overWriteTransports = false;
        var transports = [];
        if ($('#create_internal').is(":checked") ||
            $('#create_usb').is(":checked") || $('#create_nfc').is(":checked") || $('#create_ble').is(":checked") ||
            $('#create_hybrid').is(":checked")) {
            overWriteTransports = true;
            if ($('#create_internal').is(":checked")) {
                transports.push('internal');
            }
            if ($('#create_usb').is(":checked")) {
                transports.push('usb');
            }
            if ($('#create_nfc').is(":checked")) {
                transports.push('nfc');
            }
            if ($('#create_ble').is(":checked")) {
                transports.push('ble');
            }
            if ($('#create_hybrid').is(":checked")) {
                transports.push('hybrid');
            }
        }

        if ($('#create_excludeCredentials').is(":checked")) {
            var excludeCredentials = credentials.map(cred => {
                var excludeCred = {
                    type: "public-key",
                    id: Uint8Array.from(atob(cred.id), c => c.charCodeAt(0)),
                    transports: cred.transports
                };
                if (overWriteTransports) {
                    excludeCred.transports = transports;
                }
                return excludeCred;
            });

            createCredentialOptions.excludeCredentials = excludeCredentials;
        }

        if ($('#create_authenticatorAttachment').val() !== "undefined") {
            createCredentialOptions.authenticatorSelection.authenticatorAttachment = $('#create_authenticatorAttachment').val();
        }

        if ($('#create_userVerification').val() !== "undefined") {
            createCredentialOptions.authenticatorSelection.userVerification = $('#create_userVerification').val();
        }

        if ($('#create_attestation').val() !== "undefined") {
            createCredentialOptions.attestation = $('#create_attestation').val();
        }

        if ($('#create_requireResidentKey').val() !== "undefined") {
            var requireResidentKey = ($('#create_requireResidentKey').val() == "true");
            createCredentialOptions.authenticatorSelection.requireResidentKey = requireResidentKey;
        }

        if ($('#create_residentKey').val() !== "undefined") {
            createCredentialOptions.authenticatorSelection.residentKey = $('#create_residentKey').val();
        }

        if ($('#create_cred_protect').val() !== "undefined") {
            var credProtect = $('#create_cred_protect').val();
            createCredentialOptions.extensions.credentialProtectionPolicy = credProtect;
        }

        if ($('#create_cred_protect_enforce').val() !== "undefined") {
            var enforceCredProtect = ($('#create_cred_protect_enforce').val() == "true");
            createCredentialOptions.extensions.enforceCredentialProtectionPolicy = enforceCredProtect;
        }

        if ($('#create_hmac_create').val() !== "undefined") {
            var hmacCreateSecret = ($('#create_hmac_create').val() == "true");
            createCredentialOptions.extensions.hmacCreateSecret = hmacCreateSecret;
        }

        if ($('#create_prf').val() !== "undefined") {
            var prfEnable = ($('#create_prf').val() == "enable");
            if (prfEnable) {
                createCredentialOptions.extensions.prf = {};
            }
        }

        if ($('#create_prf_first').val() || $('#create_prf_second').val()) {
            createCredentialOptions.extensions.prf = {};
            createCredentialOptions.extensions.prf.eval = {};
            if ($('#create_prf_first').val()) {
                var first = $('#create_prf_first').val();
                createCredentialOptions.extensions.prf.eval.first = stringToArrayBuffer(first);
            }

            if ($('#create_prf_second').val()) {
                var second = $('#create_prf_second').val();
                createCredentialOptions.extensions.prf.eval.second = stringToArrayBuffer(second);
            }
        }

        if ($('#create_minPinLength').val() !== "undefined") {
            var minPinLength = ($('#create_minPinLength').val() == "true");
            createCredentialOptions.extensions.minPinLength = minPinLength;
        }

        if ($('#create_credBlob').val()) {
            createCredentialOptions.extensions.credBlob = stringToArrayBuffer($('#create_credBlob').val());
        }

        if ($('#create_largeBlob').val() !== "undefined") {
            createCredentialOptions.extensions.largeBlob = {};
            createCredentialOptions.extensions.largeBlob.support = $('#create_largeBlob').val();
        }

        return navigator.credentials.create({
            publicKey: createCredentialOptions
        }).then(attestation => {
            /** @type {EncodedAttestationResponse} */

            console.log("=== Create Options ===");
            console.log(createCredentialOptions);
            console.log("=== Create response ===");
            console.log(attestation);
            console.log("=== Create Extension Results ===");
            console.log(attestation.getClientExtensionResults());
            var RegistrationResponseJSON = null;
            var RegistrationResponseJSONString = "";
            try {
                RegistrationResponseJSON = attestation.toJSON();
                RegistrationResponseJSONString = JSON.stringify(RegistrationResponseJSON);
                console.log("=== Create response JSON (String) ===");
                console.log(RegistrationResponseJSONString);
            } catch (error) {
                console.warn("attestation.toJSON() failed", error);
            }

            var prfEnabled = false;
            var prfFirstHex = "";
            var prfSecondHex = "";
            var clientExtensionResults = attestation.getClientExtensionResults();

            if (typeof clientExtensionResults.prf !== 'undefined') {
                if (typeof clientExtensionResults.prf.enabled !== 'undefined') {
                    prfEnabled = clientExtensionResults.prf.enabled;
                    console.log("PRF Enabled: ", prfEnabled);
                }
                if (typeof clientExtensionResults.prf.results !== 'undefined') {
                    if (typeof clientExtensionResults.prf.results.first !== 'undefined') {
                        prfFirstHex = arrayBufferToHexString(clientExtensionResults.prf.results.first);
                        console.log("PRF First (Hex):     ", prfFirstHex);
                    }
                    if (typeof clientExtensionResults.prf.results.second !== 'undefined') {
                        prfSecondHex = arrayBufferToHexString(clientExtensionResults.prf.results.second);
                        console.log("PRF Second (Hex):    ", prfSecondHex);
                    }
                }
            }

            var credential = {
                id: arrayBufferToBase64(attestation.rawId),
                authenticatorAttachment: attestation.authenticatorAttachment,
                transports: attestation.response.getTransports(),
                authenticatorData: arrayBufferToBase64(attestation.response.getAuthenticatorData()),
                publicKey: arrayBufferToBase64(attestation.response.getPublicKey()),
                publicKeyAlgorithm: attestation.response.getPublicKeyAlgorithm(),
                clientDataJSON: arrayBufferToUTF8(attestation.response.clientDataJSON),
                attestationObject: arrayBufferToBase64(attestation.response.attestationObject),
                attestationObjectHex: arrayBufferToHexString(attestation.response.attestationObject),
                prfEnabled: prfEnabled,
                prfFirst: prfFirstHex,
                prfSecond: prfSecondHex,
                metadata: {
                    rpId: createCredentialOptions.rp.id,
                    userName: createCredentialOptions.user.name,
                    residentKey: createCredentialOptions.authenticatorSelection.requireResidentKey
                },
            };

            console.log("=== Create response parsed===");
            console.log(credential);

            return rest_put("/credentials", credential);
        }).then(response => {
            return response.json();
        }).then(response => {
            if (response.error) {
                return Promise.reject(response.error);
            } else {
                return Promise.resolve(response.result);
            }
        });
    }

    /**
    * Calls the .get() API and sends result to server to verify
    * @param {ArrayBuffer} challenge
    * @param {boolean} conditional Set to `true` if this is for a conditional UI.
    * @return {any} server response object
    */
    function getAssertion(challenge, conditional = false) {
        var largeBlobPresent = false;

        if (typeof(PublicKeyCredential) === "undefined")
            return Promise.reject("Error: WebAuthn APIs are not present on this device");

        var getAssertionOptions = {
            rpId: undefined,
            timeout: 600000,
            challenge: challenge,
            allowCredentials: [],
            userVerification: undefined,
            extensions: {}
        };

        switch ($('#get_rpId').val()) {
            case "normal":
                getAssertionOptions.rpId = window.location.hostname;
                break;
            case "suffix":
                getAssertionOptions.rpId = "suffix." + window.location.hostname;
                break;
            case "securityerror":
                getAssertionOptions.rpId = "foo.com";
                break;
            case "undefined":
            default:
                break;
        }

        var overWriteTransports = false;
        var transports = [];
        if ($('#get_internal').is(":checked") ||
            $('#get_usb').is(":checked") || $('#get_nfc').is(":checked") || $('#get_ble').is(":checked") ||
            $('#get_hybrid').is(":checked")) {
            overWriteTransports = true;
            if ($('#get_internal').is(":checked")) {
                transports.push('internal');
            }
            if ($('#get_usb').is(":checked")) {
                transports.push('usb');
            }
            if ($('#get_nfc').is(":checked")) {
                transports.push('nfc');
            }
            if ($('#get_ble').is(":checked")) {
                transports.push('ble');
            }
            if ($('#get_hybrid').is(":checked")) {
                transports.push('hybrid');
            }
        }

        if (conditional === false)
        {
            if ($('#get_allowCredentials').is(":checked")) {
                var allowCredentials = credentials.map(cred => {
                    var allowCred = {
                        type: "public-key",
                        id: Uint8Array.from(atob(cred.id), c => c.charCodeAt(0)),
                        transports: cred.transports
                    };
                    if (overWriteTransports) {
                        allowCred.transports = transports;
                    }
                    return allowCred;
                });
                getAssertionOptions.allowCredentials = allowCredentials;
            }
        }

        if ($('#get_userVerification').val() !== "undefined") {
            getAssertionOptions.userVerification = $('#get_userVerification').val();
        }

        // Collect prioritized hints (optional) for get()
        var getHintItems = document.querySelectorAll('#get_hintsList li');
        var getHints = [];
        getHintItems.forEach(li => {
            var cb = li.querySelector('input[type="checkbox"]');
            if (cb && cb.checked) {
                var hintVal = li.getAttribute('data-hint');
                if (hintVal) getHints.push(hintVal);
            }
        });
        if (getHints.length > 0) {
            getAssertionOptions.hints = getHints; // WebAuthn Level 3 hints
        }

        if ($('#get_prf_first').val() || $('#get_prf_second').val()) {
            var prfEval = {};
            if ($('#get_prf_first').val()) {
                prfEval.first = stringToArrayBuffer($('#get_prf_first').val());
            }
            if ($('#get_prf_second').val()) {
                prfEval.second = stringToArrayBuffer($('#get_prf_second').val());
            }
            if ($('#get_prf_global').is(":checked") || $('#get_prf_per_credential').is(":checked")) {
                getAssertionOptions.extensions.prf = {};
                if ($('#get_prf_global').is(":checked")) {
                    getAssertionOptions.extensions.prf.eval = prfEval;
                }
                if ($('#get_prf_per_credential').is(":checked")) {
                    if (getAssertionOptions.allowCredentials.length > 0)
                    {
                        var evalByCredential = {};
                        for (const cred of getAssertionOptions.allowCredentials) {
                            var idBase64Url = byteArrayToBase64URL(cred.id);
                            evalByCredential[idBase64Url] = prfEval;
                        }
                        getAssertionOptions.extensions.prf.evalByCredential = evalByCredential;
                    }
                }
            }
        }

        if ($('#get_credBlob').val() !== "undefined") {
            var getCredBlob = ($('#get_credBlob').val() == "true");
            getAssertionOptions.extensions.getCredBlob = getCredBlob;
        }

        if ($('#get_largeBlob').val() !== "undefined") {
            getAssertionOptions.extensions.largeBlob = {};
            getAssertionOptions.extensions.largeBlob.read = $('#get_largeBlob').val();
            largeBlobPresent = true;
        }

        if ($('#get_largeBlobText').val()) {
            if (!largeBlobPresent) {
                getAssertionOptions.extensions.largeBlob = {};
            }
            getAssertionOptions.extensions.largeBlob.write = stringToArrayBuffer($('#get_largeBlobText').val());
        }

        if(ongoingAuth != null) {
            conditionalAuthOperationInProgress = false;
            ongoingAuth.abort('Cancel ongoing authentication')
        }

        ongoingAuth = new AbortController();

        return navigator.credentials.get({
            publicKey: getAssertionOptions,
            mediation: conditional ? 'conditional' : 'optional',
            signal: ongoingAuth.signal
        }).then(assertion => {
            /** @type {EncodedAssertionResponse} */

            var prfFirstHex = "";
            var prfSecondHex = "";
            var clientExtensionResults = assertion.getClientExtensionResults();

            if (typeof clientExtensionResults.prf !== 'undefined') {
                if (typeof clientExtensionResults.prf.results !== 'undefined') {
                    if (typeof clientExtensionResults.prf.results.first !== 'undefined') {
                        prfFirstHex = arrayBufferToHexString(clientExtensionResults.prf.results.first);
                        console.log("PRF First (Hex):     ", prfFirstHex);
                    }
                    if (typeof clientExtensionResults.prf.results.second !== 'undefined') {
                        prfSecondHex = arrayBufferToHexString(clientExtensionResults.prf.results.second);
                        console.log("PRF Second (Hex):    ", prfSecondHex);
                    }
                }
            }

            var credential = {
                id: arrayBufferToBase64(assertion.rawId),
                clientDataJSON: arrayBufferToUTF8(assertion.response.clientDataJSON),
                userHandle: arrayBufferToBase64(assertion.response.userHandle),
                signature: arrayBufferToBase64(assertion.response.signature),
                authenticatorData: arrayBufferToBase64(assertion.response.authenticatorData),
                authenticatorAttachment: assertion.authenticatorAttachment,
                prfFirst: prfFirstHex,
                prfSecond: prfSecondHex,
                metadata: {
                    rpId: getAssertionOptions.rpId
                }
            };

            console.log("=== Get Options ===");
            console.log(getAssertionOptions);
            console.log("=== Get response ===");
            console.log(assertion);
            console.log("=== Get Extension Results ===");
            console.log(assertion.getClientExtensionResults());
            var assertionResponseJSON = null;
            var assertionResponseJSONString = "";
            try {
                assertionResponseJSON = assertion.toJSON();
                assertionResponseJSONString = JSON.stringify(assertionResponseJSON);
                console.log("=== Get response JSON (String) ===");
                console.log(assertionResponseJSONString);
            } catch (error) {
                console.warn("assertion.toJSON() failed", error);
            }

            return rest_put("/assertion", credential);
        }).then(response => {
            return response.json();
        }).then(response => {
            ongoingAuth = null;
            if (response.error) {
                return Promise.reject(response.error);
            } else {
                return Promise.resolve(response.result);
            }
        });
    }

    /**
    * Deletes a credential on the server
    * @param {string} id id of credential to delete 
    * @return {Promise<any>} awaitable promise
    */
    function deleteCredential(id) {
        return rest_delete(
            "/credentials",
            {
                id: id
            }
        ).then((response) => {
            return response.json();
        }).then((response) => {
            if (response.error) {
                return Promise.reject(response.error);
            }
            else {
                return updateCredentials();
            }
        });
    }

    //#endregion Event Handling


    //#region UI Rendering
    
    /**
     * UI: Updates the credential list
     */
    function updateCredentials() {
        return rest_get(
            "/credentials"
        ).then((response) => {
            return response.json();
        }).then((response) => {
            if (response.error) {
                return Promise.reject(response.error);
            } else {
                credentials = response.result;
                renderCredentialList();
                return Promise.resolve({});
            }
        });
    }

    /**
     * UI: Renders the credential list
     */
    function renderCredentialList() {
        $("#credentialsContainer").html("");
        credentials.forEach(cred => {
            renderCredential(cred);
        });

        $("a.deleteCredentialButton").click(e => {
            deleteCredential($(event.target).attr("data-value"));
        });

        $("a.creationDataDetails").click(e => {
            showCreationData($(event.target).attr("data-value"));
        });

        $("a.authenticationDataDetails").click(e => {
            showAuthenticationData($(event.target).attr("data-value"));
        });
    }

    /**
     * UI: Renders a single credential
     * @param {Credential} credential 
     */
    function renderCredential(credential) {
        var html = '';

        html += '<div class="mdl-card mdl-shadow--2dp mdl-cell mdl-cell--4-col" id="credential' + credential.id + '">';
        html += ' <div class="mdl-card__title">';
        html += '     <h2 class="mdl-card__title-text">' + credential.metadata.userName + '</h2>';
        html += ' </div>';
        html += ' <div class="mdl-card__supporting-text mdl-card--expand">';
        html += '     <p><b>Credential ID</b><br/>' + credential.idHex + '</p>';
        html += '     <p><b>RP ID</b><br/>' + credential.metadata.rpId + '</p>';
        html += '     <p><b>AAGUID </b><br/>' + credential.creationData.aaguid + '</p>';
        html += '     <p>';
        html += '         <b>Credential Registration Data</b>';
        html += '         <a href="#" class="creationDataDetails" data-value="' + credential.id + '">[more details]</a>';
        html += '         <br>Key Type: ' + credential.creationData.publicKeySummary + ' (' + credential.creationData.publicKeyAlgorithm +')';
        html += '         <br>Requested Discoverable Credential: ' + credential.metadata.residentKey;
        html += '         <br>Attestation Type: ' + credential.creationData.attestationStatementSummary;
        html += '         <br>Authenticator Attachment: ' + credential.creationData.authenticatorAttachment;
        if (credential.hasOwnProperty('transports')) {
            html += '         <br>Transports: [' + credential.transports.join(', ') + ']';
        }
        html += '         <br>PRF Enabled: ' + credential.creationData.prfEnabled;
        html += '         <br>' + credential.creationData.authenticatorDataSummary;
        html += '     </p>';
        html += '     <p>';
        html += '         <b>Last Authentication Data</b>';
        html += '         <a href="#" class="authenticationDataDetails" data-value="' + credential.id + '">[more details]</a>';
        html += '         <br>' + credential.authenticationData.authenticatorDataSummary;
        html += '     </p>';
        html += ' </div>';
        html += ' <div class="mdl-card__actions mdl-card--border">';
        html += '     <a class="mdl-button mdl-button--colored mdl-js-button mdl-js-ripple-effect deleteCredentialButton" data-value="'
            + credential.id
            + '">Delete</a>';
        html += ' </div>';
        html += '</div>';


        $("#credentialsContainer").append(html);

    }

    /**
     * UI: Animates hightlighting of a credential
     * @param {string} id id of credenital to highlight
     */
    function highlightCredential(id) {
        var credentialCard = document.getElementById("credential" + id);

        if (!credentialCard) return;

        credentialCard.classList.add("highlighted");
        setTimeout(() => {
            credentialCard.classList.remove("highlighted");
        }, 2000);
    }

    /**
     * UI: Displays a modal with creation data for a credential
     * @param {string} id id of credental to display 
     */
    function showCreationData(id) {
        var credential = credentials.find(c => c.id === id);

        var publicKeyType = credential.creationData.publicKeySummary + " ";
        if (credential.creationData.publicKeyAlgorithm !== undefined) {
            publicKeyType += "(" + credential.creationData.publicKeyAlgorithm +") ";
        }

        $("#creationData_attestationObject").text(credential.creationData.attestationObject);
        $("#creationData_attestationStatementChainJSON").text(credential.creationData.attestationStatementChainJSON);
        $("#creationData_clientDataJSON").text(credential.creationData.clientDataJSON);
        $("#creationData_authenticatorDataHex").text(credential.creationData.authenticatorDataHex);
        $("#creationData_publicKeyType").text(publicKeyType);
        $("#creationData_publicKey").text(credential.creationData.publicKey2);
        $("#creationData_publicKeyCbor").text(credential.creationData.publicKeyHex);
        $("#creationData_extensionData").text(credential.creationData.extensionDataHex);
        $("#creationData_residentKey").text(credential.metadata.residentKey);
        $("#creationData_PRF_First").text(credential.creationData.prfFirst);
        $("#creationData_PRF_Second").text(credential.creationData.prfSecond);


        var creationDataDialog = document.querySelector('#creationDataDialog');
        creationDataDialog.showModal();
    }

    /**
     * UI: Displays a modal with authentication data for a credential
     * @param {string} id id of credental to display 
     */
    function showAuthenticationData(id) {
        var credential = credentials.find(c => c.id === id);

        $("#authenticationData_userHandleHex").text(credential.authenticationData.userHandleHex);
        $("#authenticationData_authenticatorDataHex").text(credential.authenticationData.authenticatorDataHex);
        $("#authenticationData_extensionData").text(credential.authenticationData.extensionDataHex);
        $("#authenticationData_clientDataJSON").text(credential.authenticationData.clientDataJSON);
        $("#authenticationData_signatureHex").text(credential.authenticationData.signatureHex);
        $("#authenticationData_authenticatorAttachment").text(credential.authenticationData.authenticatorAttachment);
        $("#authenticationData_PRF_First").text(credential.authenticationData.prfFirst);
        $("#authenticationData_PRF_Second").text(credential.authenticationData.prfSecond);


        var authenticationDataDialog = document.querySelector('#authenticationDataDialog');
        authenticationDataDialog.showModal();
    }


    /**
     * UI: Displays a toast
     * @param {string} text text to display in toast
     */
    function toast(text) {
        var container = document.querySelector('#toast');
        container.MaterialSnackbar.showSnackbar({
            message: text,
            timeout: 5000,
        });
    }

    /**
     * UI: Disables all page controls (used when loading)
     */
    function disableControls() {
        $('dialog').find('div.mdl-progress').removeClass('cloak');
        $('body').find('input, button, select').attr('disabled', true);
    }

    /**
     * UI: Enables all page controls (used when loading is complete)
     */
    function enableControls() {
        $('dialog').find('div.mdl-progress').addClass('cloak');
        $('body').find('input, button, select').attr('disabled', false);
    }

    //#endregion UI Rendering

    //#region Helpers

    /**
     * Helper: Base64 encodes an array buffer
     * @param {ArrayBuffer} arrayBuffer 
     */
    function arrayBufferToBase64(arrayBuffer) {
        if (!arrayBuffer || arrayBuffer.byteLength == 0)
            return undefined;

        return btoa(String.fromCharCode.apply(null, new Uint8Array(arrayBuffer)));
    }

    /**
     * Helper: Converts an array buffer to a UTF-8 string
     * @param {ArrayBuffer} arrayBuffer 
     * @returns {string}
     */
    function arrayBufferToUTF8(arrayBuffer) {
        return String.fromCharCode.apply(null, new Uint8Array(arrayBuffer));
    }

    /**
     * Helper: Converts an array buffer to a Hex string
     * @param {ArrayBuffer} arrayBuffer 
     * @returns {string}
     */
    function arrayBufferToHexString(arrayBuffer) {
        return Array.from(new Uint8Array(arrayBuffer)).map(n => n.toString(16).toUpperCase().padStart(2, "0")).join("");
    }

    /**
     * Helper: Base64Url Encoding
     */
    function byteArrayToBase64URL(byteArray) {
        return btoa(Array.from(new Uint8Array(byteArray)).map(val => {
          return String.fromCharCode(val);
        }).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');
    }

    /**
     * Helper: Converts a string to an ArrayBuffer
     * @param {string} str string to convert
     * @returns {ArrayBuffer}
     */
    function stringToArrayBuffer(str){
        return Uint8Array.from(str, c => c.charCodeAt(0)).buffer;
    }

    /**
     * Helper: Performs an HTTP get operation
     * @param {string} endpoint endpoint URL
     * @returns {Promise} Promise resolving to javascript object received back
     */
    function rest_get(endpoint) {
        return fetch(endpoint, {
            method: "GET",
            credentials: "same-origin"
        });
    }

    /**
     * Helper: Performs an HTTP put operation
     * @param {string} endpoint endpoint URL
     * @param {any} object 
     * @returns {Promise} Promise resolving to javascript object received back
     */
    function rest_put(endpoint, object) {
        return fetch(endpoint, {
            method: "PUT",
            credentials: "same-origin",
            body: JSON.stringify(object),
            headers: {
                "content-type": "application/json"
            }
        });
    }

    /**
     * Helper: Performs an HTTP delete operation
     * @param {string} endpoint endpoint URL
     * @param {any} object 
     * @returns {Promise} Promise resolving to javascript object received back
     */
    function rest_delete(endpoint, object) {
        return fetch(endpoint, {
            method: "DELETE",
            credentials: "same-origin",
            body: JSON.stringify(object),
            headers: {
                "content-type": "application/json"
            }
        });
    }

    //#endregion Helpers
})();

