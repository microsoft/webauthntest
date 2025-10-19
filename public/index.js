


// This file is now loaded as an ES module (see index.html).
// Import PKIJS + peer dependencies from Skypack and initialize the crypto engine.
import * as asn1js from 'https://cdn.skypack.dev/asn1js@3.0.6';
import * as pvutils from 'https://cdn.skypack.dev/pvutils@1.1.3';
import * as pvtsutils from 'https://cdn.skypack.dev/pvtsutils@1.3.6';
import * as pkijs from 'https://cdn.skypack.dev/pkijs@3.3.0';

// Expose commonly used libs on window for compatibility with the rest of the app
window.asn1js = asn1js;
window.pvutils = pvutils;
window.pvtsutils = pvtsutils;
window.pkijs = pkijs;

// Initialize PKIJS engine to use browser WebCrypto
try {
    if (pkijs && typeof pkijs.setEngine === 'function' && typeof pkijs.CryptoEngine === 'function') {
        const engine = new pkijs.CryptoEngine({ name: 'webcrypto', crypto: window.crypto });
        pkijs.setEngine('webcrypto', engine);
    }
} catch (e) {
    console.warn('PKIJS engine init failed:', e);
}

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
    var selectedTransportCredentialId = null; // credential id currently being edited for transports

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

        var updateTransportsDialog = document.querySelector('#updateTransportsDialog');
        if (updateTransportsDialog && !updateTransportsDialog.showModal) {
            dialogPolyfill.registerDialog(updateTransportsDialog);
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

        // Update Transports dialog events
        if (updateTransportsDialog) {
            function closeUpdateTransportsDialog() {
                selectedTransportCredentialId = null;
                updateTransportsDialog.close();
            }
            $('#updateTransportsDialog_xButton').click(closeUpdateTransportsDialog);
            $('#updateTransportsDialog_cancelButton').click(closeUpdateTransportsDialog);
            $('#updateTransportsDialog_clearButton').click(() => {
                ['internal','usb','nfc','ble','hybrid'].forEach(t => resetTransportCheckbox(t));
            });

            // Confirm Delete dialog handlers
            const confirmDeleteDialog = document.getElementById('confirmDeleteDialog');
            if (confirmDeleteDialog) {
                $('#confirmDeleteDialog_confirm').click(() => {
                    const id = confirmDeleteDialog._deleteId;
                    if (id) {
                        deleteCredential(id).then(()=>{
                            confirmDeleteDialog.close();
                        }).catch(err => {
                            toast('Delete failed: ' + (err && err.message ? err.message : err));
                            confirmDeleteDialog.close();
                        });
                    } else {
                        confirmDeleteDialog.close();
                    }
                });
                $('#confirmDeleteDialog_cancel').click(() => { confirmDeleteDialog.close(); });
                $('#confirmDeleteDialog_xButton').click(() => { confirmDeleteDialog.close(); });
            }
            $('#updateTransportsDialog_selectAllButton').click(() => {
                ['internal','usb','nfc','ble','hybrid'].forEach(t => setTransportCheckbox(t, true));
            });
            $('#updateTransportsDialog_saveButton').click(() => {
                if (!selectedTransportCredentialId) {
                    closeUpdateTransportsDialog();
                    return;
                }
                var transports = [];
                ['internal','usb','nfc','ble','hybrid'].forEach(t => {
                    if ($('#update_transport_' + t).prop('checked')) transports.push(t);
                });
                    updateCredentialTransports(selectedTransportCredentialId, transports).then((result) => {
                        // Optimistically update local credential list with server-sanctioned transports
                        if (result && Array.isArray(result.transports)) {
                            var cred = credentials.find(c => c.id === selectedTransportCredentialId);
                            if (cred) {
                                cred.transports = result.transports.slice();
                            }
                            // Re-render list to reflect new transports immediately
                            renderCredentialList();
                        }
                        // Background refresh to ensure consistency
                        return updateCredentials();
                }).catch(err => {
                    toast('Failed to update transports: ' + err);
                }).finally(() => {
                    closeUpdateTransportsDialog();
                });
            });
        }

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
                // Server returns base64 (or base64url)-encoded challenge; decode to ArrayBuffer
                function base64ToArrayBuffer(base64input) {
                    // Normalize base64url -> base64 and strip invalid characters
                    let base64 = base64input.replace(/-/g, '+').replace(/_/g, '/');
                    // Remove any characters that are not base64
                    base64 = base64.replace(/[^A-Za-z0-9+/=]/g, '');
                    // Pad with '=' to make length a multiple of 4
                    while (base64.length % 4) base64 += '=';
                    // atob returns binary string
                    const binary = atob(base64);
                    const len = binary.length;
                    const bytes = new Uint8Array(len);
                    for (let i = 0; i < len; i++) {
                        bytes[i] = binary.charCodeAt(i);
                    }
                    return bytes.buffer;
                }
                try {
                    var challenge = base64ToArrayBuffer(response.result);
                    return Promise.resolve(challenge);
                } catch (err) {
                    console.error('Failed to decode challenge:', response.result, err);
                    // Provide a clearer message to the user
                    return Promise.reject('Received malformed challenge from server. See console for details.');
                }
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

        // Build excludeCredentials list (fake + optionally existing) with new rules
        (function(){
            var excludeCredentials = [];

            // Parse fake credential parameters regardless of excludeExisting toggle
            var fakeCount = parseInt($('#create_fakeExcludeCount').val(), 10);
            var fakeLen = parseInt($('#create_fakeExcludeLength').val(), 10);
            if (isNaN(fakeCount)) fakeCount = 0;
            if (isNaN(fakeLen)) fakeLen = 64;
            if (fakeCount < 0) fakeCount = 0;
            if (fakeLen < 1) fakeLen = 1;
            if (fakeLen > 2048) fakeLen = 2048; // safety cap

            // Generate fake credentials first (we will splice real ones in middle later if needed)
            var fakeCreds = [];
            for (var i = 0; i < fakeCount; i++) {
                try {
                    var randomId = new Uint8Array(fakeLen);
                    if (window.crypto && window.crypto.getRandomValues) {
                        window.crypto.getRandomValues(randomId);
                    } else {
                        for (var j = 0; j < fakeLen; j++) {
                            randomId[j] = Math.floor(Math.random() * 256);
                        }
                    }
                    var fakeExcludeCred = { type: 'public-key', id: randomId };
                    if (overWriteTransports) {
                        fakeExcludeCred.transports = transports.slice(); // apply selected transports only to fake creds
                    }
                    fakeCreds.push(fakeExcludeCred);
                } catch (e) {
                    console.warn('Failed to generate fake exclude credential', e);
                }
            }

            // Existing real credentials only if user checked the checkbox
            var realCreds = [];
            if ($('#create_excludeCredentials').is(":checked")) {
                realCreds = credentials.map(cred => ({
                    type: 'public-key',
                    id: Uint8Array.from(atob(cred.id), c => c.charCodeAt(0)),
                    transports: cred.transports // never overwritten now
                }));
            }

            var mid = null;
            if (fakeCreds.length > 0 && realCreds.length > 0) {
                // Use Math.ceil so with a single fake credential (length=1) real credentials appear after it.
                mid = Math.ceil(fakeCreds.length / 2);
                excludeCredentials = fakeCreds.slice(0, mid).concat(realCreds, fakeCreds.slice(mid));
            } else {
                excludeCredentials = fakeCreds.concat(realCreds);
            }

            // Debug logging to verify ordering and classification
            console.group('ExcludeCredentials Debug');
            console.log('Fake count:', fakeCreds.length, 'Real count:', realCreds.length, 'Mid index used:', mid);
            excludeCredentials.forEach((c, i) => {
                var isFake = fakeCreds.indexOf(c) !== -1; // identity check
                var idLen = (c.id && c.id.length) ? c.id.length : 0;
                console.log(i + ':', isFake ? 'FAKE' : 'REAL', 'idLength=' + idLen, 'transports=' + (c.transports ? c.transports.join(',') : 'none'));
            });
            console.groupEnd();

            if (excludeCredentials.length > 0) {
                createCredentialOptions.excludeCredentials = excludeCredentials;
            } else {
                console.log('ExcludeCredentials empty - none will be sent');
            }
        })();

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

        // Build allowCredentials with fake + optional real credentials when not conditional UI
        if (conditional === false) {
            (function(){
                var fakeCount = parseInt($('#get_fakeAllowCount').val(), 10);
                var fakeLen = parseInt($('#get_fakeAllowLength').val(), 10);
                if (isNaN(fakeCount)) fakeCount = 0;
                if (isNaN(fakeLen)) fakeLen = 64;
                if (fakeCount < 0) fakeCount = 0;
                if (fakeLen < 1) fakeLen = 1;
                if (fakeLen > 2048) fakeLen = 2048;

                var fakeCreds = [];
                for (var i = 0; i < fakeCount; i++) {
                    try {
                        var randomId = new Uint8Array(fakeLen);
                        if (window.crypto && window.crypto.getRandomValues) {
                            window.crypto.getRandomValues(randomId);
                        } else {
                            for (var j = 0; j < fakeLen; j++) randomId[j] = Math.floor(Math.random()*256);
                        }
                        var fakeAllow = { type: 'public-key', id: randomId };
                        if (overWriteTransports) fakeAllow.transports = transports.slice(); // transports only for fake creds
                        fakeCreds.push(fakeAllow);
                    } catch(e) { console.warn('Failed to gen fake allow credential', e); }
                }

                var realCreds = [];
                if ($('#get_allowCredentials').is(':checked')) {
                    realCreds = credentials.map(cred => ({
                        type: 'public-key',
                        id: Uint8Array.from(atob(cred.id), c => c.charCodeAt(0)),
                        transports: cred.transports // do not overwrite
                    }));
                }

                var allowCredentials = [];
                var mid = null;
                if (fakeCreds.length > 0 && realCreds.length > 0) {
                    mid = Math.ceil(fakeCreds.length / 2);
                    allowCredentials = fakeCreds.slice(0, mid).concat(realCreds, fakeCreds.slice(mid));
                } else {
                    allowCredentials = fakeCreds.concat(realCreds);
                }

                if (allowCredentials.length > 0) {
                    getAssertionOptions.allowCredentials = allowCredentials;
                }

                // Debug logging
                console.group('AllowCredentials Debug');
                console.log('Fake count:', fakeCreds.length, 'Real count:', realCreds.length, 'Mid index:', mid);
                (allowCredentials || []).forEach((c,i) => {
                    var isFake = fakeCreds.indexOf(c) !== -1;
                    var idLen = (c.id && c.id.length) ? c.id.length : 0;
                    console.log(i + ':', isFake ? 'FAKE' : 'REAL', 'idLength=' + idLen, 'transports=' + (c.transports ? c.transports.join(',') : 'none'));
                });
                console.groupEnd();
            })();
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
            const id = $(e.currentTarget).attr("data-value");
            // show confirmation dialog
            try {
                const dlg = document.querySelector('#confirmDeleteDialog');
                dlg._deleteId = id;
                dlg.showModal();
                try { if (window.componentHandler && typeof componentHandler.upgradeDom === 'function') componentHandler.upgradeDom(); } catch(e) {}
            } catch(err) {
                // fallback: delete immediately
                deleteCredential(id).catch(err=> toast('Delete failed: '+(err && err.message?err.message:err)));
            }
        });

        $("a.creationDataDetails").click(e => {
            const id = $(e.currentTarget).attr("data-value");
            showCreationData(id);
        });

        $("a.authenticationDataDetails").click(e => {
            const id = $(e.currentTarget).attr("data-value");
            showAuthenticationData(id);
        });
        $("a.updateTransportsButton").click(e => {
            var id = $(e.currentTarget).attr("data-value");
            showUpdateTransports(id);
        });
        // Ensure MDL upgrades newly added elements so styles/ripples apply
        try {
            if (window.componentHandler && typeof componentHandler.upgradeDom === 'function') {
                componentHandler.upgradeDom();
            }
        } catch (e) {
            console.warn('MDL upgradeDom failed', e);
        }
    $(".viewCertificatesButton").click(async e => {
            var id = $(e.currentTarget).attr("data-value");
            var credential = credentials.find(c => c.id === id);
            if (!credential) {
                toast('Credential not found');
                return;
            }
            try {
                if (credential.creationData && credential.creationData.attestationObject) {
                    const hex = credential.creationData.attestationObject.replace(/\s+/g, '');
                    const bytes = CBORPlayground.hexToBytes(hex);
                    const top = CBORPlayground.decodeCbor(bytes);
                    const found = findX5cInCbor(top);
                    if (found && found.length) {
                        const certs = await parseX5cArray(found);
                        showCertificatesDialog(certs);
                    } else {
                        toast('No certificates found in attestation data');
                    }
                } else {
                    toast('No attestation data available for this credential');
                }
            } catch (err) {
                console.error(err);
                toast('Failed to parse certificates: ' + (err && err.message ? err.message : err));
            }
        });
    }

    /**
     * UI: Renders a single credential
     * @param {Credential} credential 
     */
    function renderCredential(credential) {
        var html = '';

    html += '<div class="mdl-card mdl-shadow--2dp mdl-cell mdl-cell--4-col" id="credential-' + credential.idHex + '">';
        html += ' <div class="mdl-card__title">';
        html += '     <h2 class="mdl-card__title-text">' + credential.metadata.userName + '</h2>';
        html += ' </div>';
        html += ' <div class="mdl-card__supporting-text mdl-card--expand">';
        html += '     <p><b>Credential ID</b><br/>' + credential.idHex + '</p>';
        html += '     <p><b>RP ID</b><br/>' + credential.metadata.rpId + '</p>';
        html += '     <p><b>AAGUID </b><br/>' + credential.creationData.aaguid + '</p>';
        html += '     <p>';
        html += '         <b>Credential Registration Data</b>';
    html += '         <a href="#" class="mdl-button mdl-button--colored mdl-js-button mdl-js-ripple-effect creationDataDetails" data-value="' + credential.id + '">Details</a>';
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
    html += '         <a href="#" class="mdl-button mdl-button--colored mdl-js-button mdl-js-ripple-effect authenticationDataDetails" data-value="' + credential.id + '">Details</a>';
        html += '         <br>' + credential.authenticationData.authenticatorDataSummary;
        html += '     </p>';
        html += ' </div>';
        html += ' <div class="mdl-card__actions mdl-card--border">';
        html += '     <a class="mdl-button mdl-button--colored mdl-js-button mdl-js-ripple-effect deleteCredentialButton" data-value="'
            + credential.id
            + '">Delete</a>';
        html += '     <a class="mdl-button mdl-button--colored mdl-js-button mdl-js-ripple-effect updateTransportsButton" data-value="'
            + credential.id
            + '">Update Transports</a>';
    html += '     <a class="mdl-button mdl-button--colored mdl-js-button mdl-js-ripple-effect viewCertificatesButton" data-value="' + credential.id + '" style="display:none; margin-left:8px;">View Certs</a>';
        html += ' </div>';
        html += '</div>';


        $("#credentialsContainer").append(html);

        // After inserting into DOM, probe the attestationObject for x5c presence and show the button if found
        try {
            if (credential.creationData && credential.creationData.attestationObject) {
                const hex = credential.creationData.attestationObject.replace(/\s+/g, '');
                const bytes = CBORPlayground.hexToBytes(hex);
                const top = CBORPlayground.decodeCbor(bytes);
                const found = findX5cInCbor(top);
                if (found && found.length) {
                    // show the button for this credential card
                    const card = document.getElementById('credential-' + credential.idHex);
                    if (card) {
                        const btn = card.querySelector('.viewCertificatesButton');
                        if (btn) btn.style.display = 'inline-block';
                        // Ensure MDL styles are applied if componentHandler is available
                        try { if (window.componentHandler && typeof componentHandler.upgradeElement === 'function') componentHandler.upgradeElement(btn); } catch(e) { }
                    }
                }
            }
        } catch (e) {
            // non-fatal if parsing fails
            console.warn('Error probing attestationObject for credential', credential.id, e);
        }

    }

    /**
     * UI: Animates hightlighting of a credential
     * @param {string} id id of credenital to highlight
     */
    function highlightCredential(id) {
        // id is base64 id; find credential to obtain its idHex
        var credential = credentials.find(c => c.id === id);
        if (!credential) return;
        var credentialCard = document.getElementById('credential-' + credential.idHex);
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
    $("#creationData_publicKeyCbor").text(credential.creationData.publicKeyHex);
        $("#creationData_extensionData").text(credential.creationData.extensionDataHex);
        $("#creationData_residentKey").text(credential.metadata.residentKey);
        $("#creationData_PRF_First").text(credential.creationData.prfFirst);
        $("#creationData_PRF_Second").text(credential.creationData.prfSecond);

        // Note: Certificate viewing is handled per-credential on the main page

        var creationDataDialog = document.querySelector('#creationDataDialog');
        creationDataDialog.showModal();
        // Ensure newly-added MDL icon buttons are upgraded
        try { if (window.componentHandler && typeof componentHandler.upgradeDom === 'function') componentHandler.upgradeDom(); } catch(e) { }
    }

    // Open CBOR playground in new tab with provided CBOR input (reads span textContent)
    $(document).on('click', '.openCborButton', function(e){
        e.preventDefault();
        try {
            var targetSpan = $(this).attr('data-target-span');
            if(!targetSpan) return;
            var el = document.getElementById(targetSpan);
            if(!el) { toast('CBOR input not available'); return; }
            var raw = el.textContent || el.innerText || '';
            if(!raw || !raw.trim()) { toast('No CBOR data to open'); return; }
            // Encode the raw value as URI component; cbor.html will detect hex/base64
            var u = './cbor.html?input=' + encodeURIComponent(raw.trim());
            window.open(u, '_blank');
        } catch (err) {
            console.error('Failed to open CBOR playground', err);
            toast('Failed to open CBOR playground');
        }
    });

    /**
     * Recursively searches a decoded CBOR value for x5c key and returns the first found array of byte strings
     * @param {any} node decoded CBOR value (from CBORPlayground.decodeCbor)
     * @returns {Array<Uint8Array>|null}
     */
    function findX5cInCbor(node) {
        if (!node || typeof node !== 'object') return null;
        // Handle map-like objects where keys are strings
        if (!Array.isArray(node)) {
            if (Object.prototype.hasOwnProperty.call(node, 'x5c')) {
                const val = node['x5c'];
                if (Array.isArray(val)) return val;
            }
            // Iterate properties
            for (const k of Object.keys(node)) {
                const v = node[k];
                const found = findX5cInCbor(v);
                if (found) return found;
            }
        }
        // Arrays: search elements
        if (Array.isArray(node)) {
            for (const el of node) {
                const found = findX5cInCbor(el);
                if (found) return found;
            }
        }
        return null;
    }

    /**
     * Helper: map common OIDs to friendly names
     */
    function oidToName(oid) {
        const map = {
            '1.3.6.1.5.5.7.3.1': 'TLS Web Server Authentication',
            '1.3.6.1.5.5.7.3.2': 'TLS Web Client Authentication',
            '1.3.6.1.5.5.7.3.3': 'Code Signing',
            '1.3.6.1.5.5.7.3.4': 'E-mail Protection',
            '1.3.6.1.5.5.7.3.8': 'Time Stamping',
            '1.3.6.1.5.5.7.3.9': 'OCSP Signing',
            '2.5.29.37': 'Extended Key Usage',
            '1.2.840.113549.1.1.1': 'RSA Encryption',
            '1.2.840.10045.2.1': 'EC Public Key',
            '2.5.4.3': 'Common Name',
            '2.5.4.6': 'Country',
            '2.5.4.10': 'Organization',
            '2.5.4.11': 'Organizational Unit'
        };
        return map[oid] || oid;
    }

    /**
     * Parses an x5c array (elements are byte strings Uint8Array) using PKIjs to extract human-readable fields
     * @param {Array<Uint8Array>} x5cArray
     * @returns {Promise<Array<Object>>} parsed certificates
     */
    async function parseX5cArray(x5cArray) {
        const results = [];
        for (const item of x5cArray) {
            try {
                // Convert Uint8Array -> ArrayBuffer
                const ab = item.buffer.slice(item.byteOffset || 0, (item.byteOffset || 0) + item.byteLength);
                // Parse with PKIjs
                const asn1 = asn1js.fromBER(ab);
                if (asn1.offset === -1) throw new Error('ASN.1 parse error');
                const cert = new pkijs.Certificate({ schema: asn1.result });
                // Helper to extract type/value pairs
                const extractTV = (tav) => tav.map(tv => ({ type: tv.type, value: tv.value.valueBlock.value || (tv.value.valueBlock.valueHex && pvtsutils.BufferSourceConverter.toString(tv.value.valueBlock.valueHex)) })).filter(Boolean);

                // Compute SHA-256 fingerprint
                let fingerprintSHA256 = null;
                let fingerprintSHA256Colon = null;
                try {
                    const hash = await crypto.subtle.digest('SHA-256', ab);
                    const h = Array.from(new Uint8Array(hash)).map(b => ('0' + b.toString(16)).slice(-2)).join('').toUpperCase();
                    fingerprintSHA256 = h; // plain, no colons
                    fingerprintSHA256Colon = h.match(/.{1,2}/g).join(':');
                } catch (e) { /* ignore digest errors */ }

                // Determine public key algorithm and size
                let publicKey = { algorithm: cert.subjectPublicKeyInfo.algorithm.algorithmId || null, size: null };
                try {
                    const alg = cert.subjectPublicKeyInfo.algorithm.algorithmId || '';
                    // RSA: parse RSAPublicKey to get modulus length
                    if (alg === '1.2.840.113549.1.1.1') { // rsaEncryption
                        const spk = cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex;
                        const spkAsn = asn1js.fromBER(spk);
                        if (spkAsn.offset !== -1) {
                            // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
                            const rsaPub = new pkijs.RSAPublicKey({ schema: spkAsn.result });
                            const modHex = pvtsutils.Convert.ToHex(rsaPub.modulus.valueBlock.valueHex);
                            publicKey.size = (modHex.length / 2) * 8; // bits
                        }
                    } else if (alg === '1.2.840.10045.2.1') { // ecPublicKey
                        // Try to get named curve OID
                        const params = cert.subjectPublicKeyInfo.algorithm.algorithmParams;
                        if (params && params.valueBlock && params.valueBlock.toString) {
                            publicKey.size = null; // curve name unknown here; keep null
                        }
                    }
                } catch (e) { /* ignore public key parse errors */ }

                // Extract some common extensions
                const extensions = {};
                if (Array.isArray(cert.extensions)) {
                    // Helper to format GeneralName entries from PKIjs SubjectAltName parsing
                    function formatGeneralName(n) {
                        try {
                            // If the parsed value is a plain string like '4:3040...'(hex blob), try to parse hex after colon
                            if (typeof n === 'string') {
                                const m = n.match(/^\d+:(?:[0-9a-fA-F])+$/);
                                if (m) {
                                    const hex = n.split(':')[1];
                                    try {
                                        const bytes = pvtsutils.Convert.FromHex(hex);
                                        const asn = asn1js.fromBER(bytes.buffer);
                                        if (asn && asn.offset !== -1) {
                                            const collected = [];
                                            function walkNode(node) {
                                                if (!node) return;
                                                if (node.valueBlock && Array.isArray(node.valueBlock.value)) node.valueBlock.value.forEach(walkNode);
                                                if (node.valueBlock) {
                                                    const vb = node.valueBlock;
                                                    if (vb.value) collected.push(String(vb.value));
                                                    else if (vb.valueHex) {
                                                        try { collected.push(pvtsutils.BufferSourceConverter.toString(vb.valueHex)); } catch (e) { collected.push(pvtsutils.Convert.ToHex(vb.valueHex)); }
                                                    }
                                                }
                                            }
                                            walkNode(asn.result);
                                            if (collected.length) return collected.join(', ');
                                        }
                                    } catch (e) { /* ignore */ }
                                }
                            }
                            // Common string types
                            if (n.typeName && (n.typeName === 'dNSName' || n.typeName === 'uniformResourceIdentifier' || n.typeName === 'rfc822Name')) {
                                return String(n.value || n); // often already a string
                            }
                            if (n.typeName === 'iPAddress') {
                                // value may be an OctetString (valueBlock.valueHex)
                                if (n.value && n.value.valueBlock && n.value.valueBlock.valueHex) {
                                    const bytes = new Uint8Array(n.value.valueBlock.valueHex);
                                    if (bytes.length === 4) return Array.from(bytes).join('.');
                                    // IPv6-ish: hex pairs
                                    return Array.from(bytes).map(b => ('0' + b.toString(16)).slice(-2)).join(':');
                                }
                                return String(n.value || n);
                            }
                            // directoryName or other structured types
                            if (n.typeName === 'directoryName' && n.value && Array.isArray(n.value.typesAndValues)) {
                                return n.value.typesAndValues.map(tv => (tv.type || '') + ':' + (tv.value && (tv.value.valueBlock && (tv.value.valueBlock.value || (tv.value.valueBlock.valueHex && pvtsutils.BufferSourceConverter.toString(tv.value.valueBlock.valueHex)))) || '')).join(', ');
                            }

                            // If we have valueBlock.valueHex, attempt to parse it as ASN.1 and extract inner strings
                            if (n.value && n.value.valueBlock && n.value.valueBlock.valueHex) {
                                try {
                                    const inner = asn1js.fromBER(n.value.valueBlock.valueHex);
                                    if (inner && inner.offset !== -1 && inner.result) {
                                        const collected = [];
                                        // recursive extractor
                                        function walk(node) {
                                            if (!node) return;
                                            if (Array.isArray(node.valueBlock && node.valueBlock.value)) {
                                                node.valueBlock.value.forEach(child => walk(child));
                                            }
                                            // string types
                                            if (node.valueBlock) {
                                                const vb = node.valueBlock;
                                                if (vb.value) collected.push(String(vb.value));
                                                else if (vb.valueHex) {
                                                    try { collected.push(pvtsutils.BufferSourceConverter.toString(vb.valueHex)); } catch (e) { collected.push(pvtsutils.Convert.ToHex(vb.valueHex)); }
                                                }
                                            }
                                            // if node has result property (for parsed objects)
                                            if (node.result && typeof node.result === 'object') walk(node.result);
                                        }
                                        walk(inner.result);
                                        if (collected.length) return collected.join(', ');
                                        // If ASN.1 walk found nothing, try scanning for UTF8String (tag 0x0C) sequences
                                        try {
                                            const vbHex = node.valueBlock && node.valueBlock.valueHex ? new Uint8Array(node.valueBlock.valueHex) : null;
                                            if (vbHex && vbHex.length) {
                                                const parts = [];
                                                for (let j = 0; j < vbHex.length - 2; j++) {
                                                    if (vbHex[j] === 0x0C) { // UTF8String tag
                                                        const len = vbHex[j+1];
                                                        if (len && j+2+len <= vbHex.length) {
                                                            const slice = vbHex.slice(j+2, j+2+len);
                                                            try { parts.push(pvtsutils.BufferSourceConverter.toString(slice)); } catch(e) { parts.push(pvtsutils.Convert.ToHex(slice)); }
                                                            j += 1 + len;
                                                        }
                                                    }
                                                }
                                                if (parts.length) return parts.join(', ');
                                            }
                                        } catch (e) { /* ignore */ }
                                    }
                                } catch (e) {
                                    // fallthrough to other heuristics
                                }
                            }

                            // Fallbacks: some parsed values are ASN.1 objects with valueBlock
                            if (n.value && n.value.valueBlock) {
                                const vb = n.value.valueBlock;
                                if (vb.value) return String(vb.value);
                                if (vb.valueHex) {
                                    try { return pvtsutils.BufferSourceConverter.toString(vb.valueHex); } catch (e) { return pvtsutils.Convert.ToHex(vb.valueHex); }
                                }
                            }

                            // If type is OID or custom, attempt to stringify
                            if (n.type) return String(n.value || n);
                            return String(n.value || n);
                        } catch (e) {
                            try { return JSON.stringify(n); } catch (e2) { return String(n); }
                        }
                    }

                    cert.extensions.forEach(ext => {
                        try {
                            if (ext.extnID === '2.5.29.19') { // BasicConstraints
                                const bc = ext.parsedValue;
                                extensions.basicConstraints = { cA: !!bc.cA, pathLenConstraint: bc.pathLenConstraint || null };
                            } else if (ext.extnID === '2.5.29.15') { // KeyUsage
                                const ku = ext.parsedValue; // BitString
                                extensions.keyUsage = ku.wBits ? ku.wBits.join(',') : Object.keys(ku).filter(k => ku[k]).join(',');
                            } else if (ext.extnID === '2.5.29.37') { // ExtKeyUsage
                                const eku = ext.parsedValue; // array of OIDs
                                if (Array.isArray(eku.keyPurposes)) {
                                    extensions.extKeyUsage = eku.keyPurposes.map(k => k.toString());
                                }
                            } else if (ext.extnID === '2.5.29.17') { // SubjectAltName
                                const san = ext.parsedValue; // GeneralNames
                                if (Array.isArray(san.altNames)) {
                                    extensions.subjectAltName = san.altNames.map(n => ({ type: n.typeName || n.type, value: formatGeneralName(n) }));
                                }
                            }
                        } catch (e) { /* ignore */ }
                    });
                }

                const parsed = {
                    subject: extractTV(cert.subject.typesAndValues),
                    issuer: extractTV(cert.issuer.typesAndValues),
                    serialNumber: pvtsutils.Convert.ToHex(cert.serialNumber.valueBlock.valueHex).toUpperCase(),
                    notBefore: cert.notBefore.value.toString(),
                    notAfter: cert.notAfter.value.toString(),
                    signatureAlgorithm: cert.signatureAlgorithm.algorithmId,
                    raw: ab,
                    pem: convertToPEM(ab),
                    fingerprintSHA256,
                    fingerprintSHA256Colon,
                    publicKey,
                    extensions
                };
                results.push(parsed);
            } catch (e) {
                console.warn('Failed to parse cert in x5c', e);
            }
        }
        return results;
    }

    function convertToPEM(arrayBuffer) {
        const bytes = new Uint8Array(arrayBuffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
        const b64 = btoa(binary);
        const chunks = b64.match(/.{1,64}/g) || [];
        return '-----BEGIN CERTIFICATE-----\n' + chunks.join('\n') + '\n-----END CERTIFICATE-----\n';
    }

    /**
     * Renders a modal dialog with certificate details
     * @param {Array<Object>} certs
     */
    function showCertificatesDialog(certs) {
        // Build an enhanced dialog with download/copy actions
        let dlg = document.getElementById('certsDialog');
        if (!dlg) {
            dlg = document.createElement('dialog');
            dlg.className = 'mdl-dialog';
            dlg.id = 'certsDialog';
            document.body.appendChild(dlg);
        }

    let html = '';
    html += '<h3 class="mdl-dialog__title">Certificates</h3>';
    html += '<div class="mdl-dialog__content">';

        certs.forEach((c, idx) => {
            // Helper to render name arrays and prefer commonName when present
            function formatName(arr) {
                try {
                    const cn = arr.find(tv => tv.type && (tv.type.toLowerCase().endsWith('2.5.4.3') || tv.type.toLowerCase().endsWith('cn')));
                    if (cn) return (cn.value || cn.value) + ' (' + arr.map(tv => (tv.type || '') + ':' + (tv.value || '')).join(', ') + ')';
                    return arr.map(tv => (tv.type || '') + ': ' + (tv.value || '')).join(', ');
                } catch (e) { return JSON.stringify(arr); }
            }

            html += '<div class="mdl-card mdl-shadow--2dp cert-card" style="margin-bottom:12px; padding:12px; background:#fff;">';
            html += '<div style="display:flex; flex-direction:column; gap:8px;">';
            html += '<div><b>Certificate ' + (idx+1) + '</b></div>';
            html += '<div><small><b>Subject:</b> ' + escapeHtml(formatName(c.subject || [])) + '</small></div>';
            html += '<div><small><b>Issuer:</b> ' + escapeHtml(formatName(c.issuer || [])) + '</small></div>';
            html += '<div><small><b>Serial:</b> ' + escapeHtml(c.serialNumber || '') + '</small></div>';
            html += '<div><small><b>Validity:</b> ' + escapeHtml(c.notBefore || '') + ' → ' + escapeHtml(c.notAfter || '') + '</small></div>';
            if (c.fingerprintSHA256) html += '<div><small><b>Fingerprint (SHA-256):</b> ' + escapeHtml((c.fingerprintSHA256Colon || c.fingerprintSHA256)) + ' <button class="mdl-button cert-copy-fingerprint" data-idx="' + idx + '" title="Copy fingerprint"><i class="material-icons" aria-hidden="true">content_copy</i></button></small></div>';
            if (c.publicKey && (c.publicKey.algorithm || c.publicKey.size)) {
                const algName = c.publicKey.algorithm ? oidToName(c.publicKey.algorithm) : '';
                html += '<div><small><b>Public Key:</b> ' + escapeHtml((algName || c.publicKey.algorithm || '') + (c.publicKey.size ? ' (' + c.publicKey.size + ' bits)' : '')) + '</small></div>';
            }
            // Extensions
            if (c.extensions) {
                if (c.extensions.basicConstraints) {
                    html += '<div><small><b>Basic Constraints:</b> CA=' + (c.extensions.basicConstraints.cA ? 'true' : 'false') + (c.extensions.basicConstraints.pathLenConstraint ? ', pathLen=' + c.extensions.basicConstraints.pathLenConstraint : '') + '</small></div>';
                }
                if (c.extensions.keyUsage) {
                    html += '<div><small><b>Key Usage:</b> ' + escapeHtml(String(c.extensions.keyUsage)) + '</small></div>';
                }
                if (c.extensions.extKeyUsage) {
                    const ekus = c.extensions.extKeyUsage.map(o => (oidToName(o) + ' (' + o + ')'));
                    html += '<div><small><b>Extended Key Usage:</b> ' + escapeHtml(ekus.join(', ')) + '</small></div>';
                }
                if (c.extensions.subjectAltName) {
                        // Decode possible id:HEX patterns inside SAN values to ASCII when practical
                        function decodeIdHex(val) {
                            try {
                                return val.replace(/id:([0-9A-Fa-f]{2,})/g, (m, hex) => {
                                    try {
                                        const bytes = pvtsutils.Convert.FromHex(hex);
                                        const str = pvtsutils.BufferSourceConverter.toString(bytes);
                                        return `id:${hex} (${str})`;
                                    } catch (e) {
                                        return m;
                                    }
                                });
                            } catch (e) { return val; }
                        }

                        const san = c.extensions.subjectAltName.map(n => {
                            const t = n.type || '';
                            const rawVal = (typeof n.value === 'object') ? JSON.stringify(n.value) : String(n.value);
                            const val = decodeIdHex(rawVal);
                            return t + ':' + val;
                        }).join(', ');
                        html += '<div><small><b>Subject Alt Names:</b> ' + escapeHtml(san) + '</small></div>';
                    }
            }

            // Action buttons
            html += '<div class="cert-actions" style="margin-top:8px; display:flex; gap:8px;">';
            html += '<button class="mdl-button mdl-js-button cert-download-pem" data-idx="' + idx + '"><i class="material-icons" aria-hidden="true">file_download</i>&nbsp;DOWNLOAD PEM</button>';
            html += '<button class="mdl-button mdl-js-button cert-download-der" data-idx="' + idx + '"><i class="material-icons" aria-hidden="true">cloud_download</i>&nbsp;DOWNLOAD DER</button>';
            html += '<button class="mdl-button mdl-js-button cert-copy-pem" data-idx="' + idx + '"><i class="material-icons" aria-hidden="true">content_copy</i>&nbsp;COPY PEM</button>';
            html += '</div>';

            html += '</div>'; // end column
            html += '</div>';
        });

    html += '</div>'; // end content
    // dialog actions/footer: Download Chain on left, Close on right
    // Render buttons as direct siblings and push Close to the right using margin-left:auto
    html += '<div class="mdl-dialog__actions cert-dialog-actions" role="toolbar" style="display:flex; gap:8px; align-items:center;">';
    html += '<button class="mdl-button mdl-js-button mdl-button--raised" id="certsDownloadChain">Download Chain</button>';
    html += '<button class="mdl-button" id="certsDialog_x" style="margin-left:auto;">Close</button>';
    html += '</div>';
    dlg.innerHTML = html;

    // Wire actions (close button appended after content)
    const closeBtn = dlg.querySelector('#certsDialog_x');
    if (closeBtn) closeBtn.addEventListener('click', () => dlg.close());

    // Download chain: concatenate PEMs into one file
    const downloadChainBtn = dlg.querySelector('#certsDownloadChain');
    if (downloadChainBtn) {
        downloadChainBtn.addEventListener('click', () => {
            const allPem = certs.map(c => c.pem).join('\n');
            const blob = new Blob([allPem], { type: 'application/x-pem-file' });
            downloadBlob('certificate-chain.pem', blob);
        });
    }

        // Helper: download PEM/DER and copy
        function downloadBlob(filename, blob) {
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            setTimeout(() => {
                URL.revokeObjectURL(url);
                a.remove();
            }, 1000);
        }

        // Upgrade MDL components inside dialog before wiring handlers
        try { if (window.componentHandler && typeof componentHandler.upgradeDom === 'function') componentHandler.upgradeDom(); } catch (e) { /* ignore */ }

        // Attach per-cert button handlers
        dlg.querySelectorAll('.cert-download-pem').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const idx = parseInt(btn.getAttribute('data-idx'), 10);
                const cert = certs[idx];
                if (!cert) return;
                const pem = cert.pem;
                const blob = new Blob([pem], { type: 'application/x-pem-file' });
                downloadBlob('certificate-' + (idx+1) + '.pem', blob);
            });
        });

        dlg.querySelectorAll('.cert-download-der').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const idx = parseInt(btn.getAttribute('data-idx'), 10);
                const cert = certs[idx];
                if (!cert) return;
                const ab = cert.raw || null;
                if (!ab) return toast('DER data not available');
                const blob = new Blob([ab], { type: 'application/octet-stream' });
                downloadBlob('certificate-' + (idx+1) + '.der', blob);
            });
        });

        dlg.querySelectorAll('.cert-copy-pem').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const idx = parseInt(btn.getAttribute('data-idx'), 10);
                const cert = certs[idx];
                if (!cert) return;
                try {
                    await navigator.clipboard.writeText(cert.pem);
                    toast('PEM copied to clipboard');
                } catch (err) {
                    // fallback: use temporary textarea and execCommand
                    try {
                        const ta = document.createElement('textarea');
                        ta.value = cert.pem;
                        ta.style.position = 'fixed';
                        ta.style.left = '-9999px';
                        document.body.appendChild(ta);
                        ta.select();
                        document.execCommand('copy');
                        ta.remove();
                        toast('PEM copied to clipboard (fallback)');
                    } catch (err2) {
                        toast('Copy failed; please download the PEM');
                    }
                }
            });
        });

        // Copy fingerprint handlers
        dlg.querySelectorAll('.cert-copy-fingerprint').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const idx = parseInt(btn.getAttribute('data-idx'), 10);
                const cert = certs[idx];
                if (!cert || !cert.fingerprintSHA256) return;
                try {
                    // copy plain fingerprint (no colons) if available
                    const toCopy = cert.fingerprintSHA256 || cert.fingerprintSHA256Colon || '';
                    await navigator.clipboard.writeText(toCopy);
                    toast('Fingerprint copied to clipboard');
                } catch (err) {
                    // fallback
                    try {
                        const ta = document.createElement('textarea');
                        ta.value = cert.fingerprintSHA256 || cert.fingerprintSHA256Colon || '';
                        ta.style.position = 'fixed';
                        ta.style.left = '-9999px';
                        document.body.appendChild(ta);
                        ta.select();
                        document.execCommand('copy');
                        ta.remove();
                        toast('Fingerprint copied to clipboard (fallback)');
                    } catch (err2) {
                        toast('Copy failed');
                    }
                }
            });
        });

        if (!dlg.showModal) dialogPolyfill.registerDialog(dlg);
        dlg.showModal();
        // Move keyboard focus to Close button for accessibility
        try {
            if (closeBtn) {
                closeBtn.setAttribute('tabindex', '0');
                closeBtn.focus();
            }
        } catch (e) { /* ignore focus errors */ }
    }

    function escapeHtml(str) {
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
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
     * UI: Shows Update Transports dialog and pre-populates checkboxes
     * @param {string} id credential id
     */
    function showUpdateTransports(id) {
        selectedTransportCredentialId = id;
        var credential = credentials.find(c => c.id === id);
        if (!credential) {
            updateCredentials().then(() => {
                credential = credentials.find(c => c.id === id);
                if (credential) {
                    showUpdateTransports(id);
                } else {
                    toast('Credential not found');
                }
            });
            return;
        }
        // reset all using helper (ensures MDL visual sync)
        ['internal','usb','nfc','ble','hybrid'].forEach(t => resetTransportCheckbox(t));
        if (credential && Array.isArray(credential.transports)) {
            var allowed = ['internal','usb','nfc','ble','hybrid'];
            credential.transports.forEach(t => {
                if (allowed.includes(t)) {
                    setTransportCheckbox(t, true);
                }
            });
        }
        var updateTransportsDialog = document.querySelector('#updateTransportsDialog');
        if (updateTransportsDialog) {
            updateTransportsDialog.showModal();
            // Force MDL to upgrade any components to avoid first-click miss
            if (window.componentHandler && typeof componentHandler.upgradeDom === 'function') {
                try { componentHandler.upgradeDom(); } catch (e) { /* ignore upgrade errors */ }
            }
        }
    }

    function resetTransportCheckbox(name) {
        var $input = $('#update_transport_' + name);
        $input.prop('checked', false);
        var $label = $input.closest('label.mdl-checkbox');
        $label.removeClass('is-checked');
    }

    function setTransportCheckbox(name, checked) {
        var $input = $('#update_transport_' + name);
        $input.prop('checked', checked);
        var $label = $input.closest('label.mdl-checkbox');
        if (checked) {
            $label.addClass('is-checked');
        } else {
            $label.removeClass('is-checked');
        }
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
            credentials: "same-origin",
            cache: "no-store"
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

    /**
     * Helper: Performs an HTTP patch operation
     * @param {string} endpoint endpoint URL
     * @param {any} object 
     * @returns {Promise} Promise resolving to javascript object received back
     */
    function rest_patch(endpoint, object) {
        return fetch(endpoint, {
            method: "PATCH",
            credentials: "same-origin",
            body: JSON.stringify(object),
            headers: {
                "content-type": "application/json"
            },
            cache: "no-store"
        });
    }

    /**
     * Updates credential transports on server
     * @param {string} id credential id
     * @param {Array<string>} transports transports array
     */
    function updateCredentialTransports(id, transports) {
        return rest_patch('/credentials/transports', { id: id, transports: transports })
            .then(r => r.json())
            .then(r => {
                if (r.error) return Promise.reject(r.error);
                return Promise.resolve(r.result);
            });
    }

    //#endregion Helpers
})();

