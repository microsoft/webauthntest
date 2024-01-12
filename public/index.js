



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

    //#region Event Handling

    $(window).on('load', function () {
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

        $('#getButton').click(() => {
            getDialog.showModal();
        });

        $('#moreButton').click(() => {
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
                PublicKeyCredential.isConditionalMediationAvailable().then(supported => {
                    $("#moreDialog_autofillUiSupported").text(supported ? "Supported" : "Not supported");
                }).catch(e => {
                    $("#moreDialog_autofillUiSupported").text("Error");
                });
            }

            if (!PublicKeyCredential || typeof PublicKeyCredential.isExternalCTAP2SecurityKeySupported !== "function") {
                $("#moreDialog_ctap2Supported").text("Not defined");
            } else {
                PublicKeyCredential.isExternalCTAP2SecurityKeySupported().then(supported => {
                    $("#moreDialog_ctap2Supported").text(supported ? "Supported" : "Not supported");
                }).catch(e => {
                    $("#moreDialog_ctap2Supported").text("Error");
                });
            }

            moreDialog.showModal();
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
                return getAssertion(challenge)
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
    });


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

        if ($('#create_ES256').is(":checked")) {
            createCredentialOptions.pubKeyCredParams.push({
                type: "public-key",
                alg: -7
            });
        }
        if ($('#create_ES384').is(":checked")) {
            createCredentialOptions.pubKeyCredParams.push({
                type: "public-key",
                alg: -35
            });
        }
        if ($('#create_ES512').is(":checked")) {
            createCredentialOptions.pubKeyCredParams.push({
                type: "public-key",
                alg: -36
            });
        }
        if ($('#create_RS256').is(":checked")) {
            createCredentialOptions.pubKeyCredParams.push({
                type: "public-key",
                alg: -257
            });
        }
        if ($('#create_EdDSA').is(":checked")) {
            createCredentialOptions.pubKeyCredParams.push({
                type: "public-key",
                alg: -8
            });
        }

        if ($('#create_excludeCredentials').is(":checked")) {
            var excludeCredentials = credentials.map(cred => {
                return {
                    type: "public-key",
                    id: Uint8Array.from(atob(cred.id), c => c.charCodeAt(0))
                };
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
            var credential = {
                id: base64encode(attestation.rawId),
                clientDataJSON: arrayBufferToString(attestation.response.clientDataJSON),
                attestationObject: base64encode(attestation.response.attestationObject),
                transports: attestation.response.getTransports(),
                metadata: {
                    rpId: createCredentialOptions.rp.id,
                    userName: createCredentialOptions.user.name,
                    residentKey: createCredentialOptions.authenticatorSelection.requireResidentKey
                },
            };

            console.log("=== Attestation response ===");
            logVariable("id (base64)", credential.id);
            logVariable("clientDataJSON", credential.clientDataJSON);
            logVariable("attestationObject (base64)", credential.attestationObject);

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
    * @return {any} server response object
    */
    function getAssertion(challenge) {
        var largeBlobPresent = false;

        if (typeof(PublicKeyCredential) === "undefined")
            return Promise.reject("Error: WebAuthn APIs are not present on this device");

        var getAssertionOptions = {
            rpId: undefined,
            timeout: 180000,
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

        if ($('#get_allowCredentials').is(":checked")) {
            var allowCredentials = credentials.map(cred => {
                return {
                    type: "public-key",
                    id: Uint8Array.from(atob(cred.id), c => c.charCodeAt(0))
                };
            });

            getAssertionOptions.allowCredentials = allowCredentials;
        }

        if ($('#get_userVerification').val() !== "undefined") {
            getAssertionOptions.userVerification = $('#get_userVerification').val();
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

        return navigator.credentials.get({
            publicKey: getAssertionOptions
        }).then(assertion => {
            /** @type {EncodedAssertionResponse} */
            var credential = {
                id: base64encode(assertion.rawId),
                clientDataJSON: arrayBufferToString(assertion.response.clientDataJSON),
                userHandle: base64encode(assertion.response.userHandle),
                signature: base64encode(assertion.response.signature),
                authenticatorData: base64encode(assertion.response.authenticatorData),
                metadata: {
                    rpId: getAssertionOptions.rpId
                }
            };

            console.log("=== Assertion response ===");
            logVariable("id (base64)", credential.id);
            logVariable("userHandle (base64)", credential.userHandle);
            logVariable("authenticatorData (base64)", credential.authenticatorData);
            logVariable("clientDataJSON", credential.clientDataJSON);
            logVariable("signature (base64)", credential.signature);

            return rest_put("/assertion", credential);
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
        html += '         <br>Key Type: ' + credential.creationData.publicKeySummary;
        html += '         <br>Discoverable Credential: ' + credential.metadata.residentKey;
        html += '         <br>Attestation Type: ' + credential.creationData.attestationStatementSummary;
        if (credential.hasOwnProperty('transports')) {
            html += '         <br>Transports: [' + credential.transports.join(', ') + ']';
        }
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

        $("#creationData_attestationStatementHex").text(credential.creationData.attestationStatementHex);
        $("#creationData_attestationStatementChainJSON").text(credential.creationData.attestationStatementChainJSON);
        $("#creationData_authenticatorData").text(credential.creationData.authenticatorDataSummary);
        $("#creationData_authenticatorDataHex").text(credential.creationData.authenticatorDataHex);
        $("#creationData_publicKey").text(credential.creationData.publicKeySummary + " key: " + credential.creationData.publicKeyHex);
        $("#creationData_extensionData").text(credential.creationData.extensionDataHex);
        $("#creationData_residentKey").text(credential.metadata.residentKey);

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
        $("#authenticationData_clientDataJSONHex").text(credential.authenticationData.clientDataJSONHex);
        $("#authenticationData_signatureHex").text(credential.authenticationData.signatureHex);

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
    function base64encode(arrayBuffer) {
        if (!arrayBuffer || arrayBuffer.byteLength == 0)
            return undefined;

        return btoa(String.fromCharCode.apply(null, new Uint8Array(arrayBuffer)));
    }

    /**
     * Helper: Converts an array buffer to a UTF-8 string
     * @param {ArrayBuffer} arrayBuffer 
     * @returns {string}
     */
    function arrayBufferToString(arrayBuffer) {
        return String.fromCharCode.apply(null, new Uint8Array(arrayBuffer));
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

    /**
     * Helper: logs a variable
     */
    function logVariable(name, text) {
        console.log(name + ": " + text);
    }

    //#endregion Helpers
})();

