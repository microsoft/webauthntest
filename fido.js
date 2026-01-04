const crypto = require('crypto');
const cbor = require('cbor');
// Using raw random challenges instead of JWT
const url = require('url');
const storage = require('./storage.js');
const fidoAttestation = require('./fidoAttestation.js');
const {sha256, coseToJwk, coseToHex, defaultTo} = require('./utils.js');

const env_hostname = process.env.HOSTNAME;
const custom_domain = process.env.CUSTOM_DOMAIN;

// In-memory challenge store: map uid -> {challengeBase64, expiresAt}
const challengeStore = new Map();

const CHALLENGE_EXPIRY_MS = 2 * 60 * 1000; // 2 minutes

const fido = {};


/**
 * @typedef {import('./public/types').AuthenticatorData} AuthenticatorData
 * @typedef {import('./public/types').AttestedCredentialData} AttestedCredentialData
 * @typedef {import('./public/types').Credential} Credential 
 * @typedef {import('./public//types').EncodedAttestationResponse} EncodedAttestationResponse
 * @typedef {import('./public//types').EncodedAssertionResponse} EncodedAssertionResponse
 */

/**
 * Gets an opaque challenge for the client.
 * Internally, this challenge is a JWT with a timeout.
 * @returns {string} challenge
 */
fido.getChallenge = (uid, clientHostname) => {
    // Generate 32 random bytes and store base64-encoded challenge per user with expiry
    const raw = crypto.randomBytes(32);
    // Use base64url encoding for safe transport in URLs and JSON
    let b64 = raw.toString('base64');
    b64 = b64.split('+').join('-').split('/').join('_');
    while (b64.endsWith('=')) b64 = b64.slice(0, -1);
    const expiresAt = Date.now() + CHALLENGE_EXPIRY_MS;
    // Store base64url (no padding) to make it safe for URLs and JSON
    challengeStore.set(uid, { challengeBase64: b64, expiresAt, clientHostname });
    // Debug log to help trace mismatches during development
    try {
        console.log(`[fido] setChallenge uid=${uid} challenge=${b64}`);
    } catch (e) {
        // ignore logging errors
    }
    return b64; // client will convert string -> ArrayBuffer
};

/**
 * Creates a FIDO credential and stores it
 * @param {String} uid user id
 * @param {EncodedAttestationResponse} attestation AuthenticatorAttestationResponse received from client
 */
fido.makeCredential = async (uid, attestation) => {
    //https://w3c.github.io/webauthn/#registering-a-new-credential

    if (!attestation.id)
        throw new Error("id is missing");

    if (!attestation.attestationObject)
        throw new Error("attestationObject is missing")

    if (!attestation.clientDataJSON)
        throw new Error("clientDataJSON is missing");

    //Step 1-2: Let C be the parsed the client data claimed as collected during
    //the credential creation
    let clientData;
    try {
        clientData = JSON.parse(attestation.clientDataJSON);
    } catch (e) {
        throw new Error("clientDataJSON could not be parsed");
    }

    let origin;
    try {
        origin = url.parse(clientData.origin);
    } catch (e) {
        throw new Error("Invalid origin in collectedClientData");
    }
    // Valid hostnames
    let validHostnames = [custom_domain, env_hostname, 'localhost'].filter(Boolean);
    // Find hostname by matching origin.hostname in validHostnames
    let hostname = validHostnames.find(h => h === origin.hostname);
    // fail if no match
    if (!hostname)
        throw new Error("Invalid origin in collectedClientData. Expected hostname " + validHostnames.join(', '));
    // For non-localhost, require HTTPS
    if (hostname !== "localhost" && origin.protocol !== "https:")
        throw new Error("Invalid origin in collectedClientData. Expected HTTPS protocol.");

    //Step 3-6: Verify client data
    await validateClientData(clientData, uid, hostname, "webauthn.create");
    //Step 7: Compute the hash of response.clientDataJSON using SHA-256.
    const clientDataHash = sha256(attestation.clientDataJSON);

    //Step 8: Perform CBOR decoding on the attestationObject
    let attestationObject;
    try {
        attestationObject = cbor.decodeFirstSync(Buffer.from(attestation.attestationObject, 'base64'));
    } catch (e) {
        throw new Error("attestationObject could not be decoded");
    }
    //Step 8.1: Parse authData data inside the attestationObject
    const authenticatorData = parseAuthenticatorData(attestationObject.authData);
    //Step 8.2: authenticatorData should contain attestedCredentialData
    if (!authenticatorData.attestedCredentialData)
        throw new Error("Did not see AD flag in authenticatorData");

    //Step 9: Verify that the RP ID hash in authData is indeed the SHA-256 hash
    //of the RP ID expected by the RP.
    const expectedRpId = defaultTo(attestation.metadata.rpId, hostname)
    if (!authenticatorData.rpIdHash.equals(sha256(expectedRpId))) {
        throw new Error("RPID hash does not match expected value: sha256(" + expectedRpId + ")");
    }

    //Step 10: Verify that the User Present bit of the flags in authData is set
    if ((authenticatorData.flags & 0b00000001) == 0) {
        throw new Error("User Present bit was not set.");
    }

    //Ignore step 11-12 since this is a test site

    //Step 13-17: Attestation
    const attestationStatement = fidoAttestation.parse(attestationObject, authenticatorData, clientDataHash);

    /** @type {Credential} */
    const credential = {
        uid: uid,
        id: authenticatorData.attestedCredentialData.credentialId.toString('base64'),
        idHex: authenticatorData.attestedCredentialData.credentialId.toString('hex').toUpperCase(),
        transports: attestation.transports,
        metadata: {
            rpId: defaultTo(attestation.metadata.rpId, hostname),
            userName: attestation.metadata.userName,
            residentKey: !!attestation.metadata.residentKey
        },
        creationData: {
            publicKey: JSON.stringify(authenticatorData.attestedCredentialData.publicKey),
            publicKeySummary: authenticatorData.attestedCredentialData.publicKey.kty,
            publicKeyHex: authenticatorData.attestedCredentialData.publicKeyHex,
            aaguid: authenticatorData.attestedCredentialData.aaguid,
            attestationStatementHex: attestationStatement.hex,
            attestationStatementSummary: attestationStatement.summary,
            attestationStatementChainJSON: attestationStatement.chainJSON,
            authenticatorDataSummary: summarizeAuthenticatorData(authenticatorData),
            authenticatorDataHex: attestationObject.authData.toString('hex').toUpperCase(),
            extensionDataHex: defaultTo(authenticatorData.extensionDataHex, "No extension data"),
            authenticatorData: attestation.authenticatorData,
            attestationObject: attestation.attestationObjectHex,
            clientDataJSON: attestation.clientDataJSON,
            clientDataJSONHex: Buffer.from(attestation.clientDataJSON, 'utf8').toString('hex').toUpperCase(),
            publicKey2: attestation.publicKey,
            publicKeyAlgorithm: attestation.publicKeyAlgorithm,
            authenticatorAttachment: attestation.authenticatorAttachment,
            prfEnabled: attestation.prfEnabled,
            prfFirst: attestation.prfFirst,
            prfSecond: attestation.prfSecond,
        },
        authenticationData: {
            authenticatorDataSummary: "No authentications",
            signCount: authenticatorData.signCount,
            userHandleHex: "none",
            authenticatorDataHex: "none",
            clientDataJSON: "none",
            clientDataJSONHex: "none",
            signatureHex: "none",
            extensionDataHex: "No extension data",
            authenticatorAttachment: "none",
            prfFirst: "none",
            prfSecond: "none",
        }
    };
    // Ensure new credentials are enabled by default
    credential.enabled = true;

    await storage.Credentials.create(credential);

    return credential;
};

/**
 * Verifies a FIDO assertion
 * @param {String} uid user id
 * @param {EncodedAssertionResponse} assertion AuthenticatorAssertionResponse received from client
 * @return {Promise<Credential>} credential object that the assertion verified
 */
fido.verifyAssertion = async (uid, assertion) => {

    // https://w3c.github.io/webauthn/#verifying-assertion

    // Step 1 and 2 are skipped because this is a sample app

    // Step 3: Using credential’s id attribute look up the corresponding
    // credential public key.
    /** @typeof {Credential} */
    const credential = await storage.Credentials.findOne({
        uid: uid,
        id: assertion.id
    });


    // Step 4: Let cData, authData and sig denote the value of credential’s
    // response's clientDataJSON, authenticatorData, and signature respectively
    const cData = assertion.clientDataJSON;
    const authData = Buffer.from(assertion.authenticatorData, 'base64');
    const sig = Buffer.from(assertion.signature, 'base64');

    // Step 5 and 6: Let C be the decoded client data claimed by the signature.
    let clientData;
    try {
        clientData = JSON.parse(cData);
    } catch (e) {
        throw new Error("clientDataJSON could not be parsed");
    }

    let origin;
    try {
        origin = url.parse(clientData.origin);
    } catch (e) {
        throw new Error("Invalid origin in collectedClientData");
    }
    // Valid hostnames
    let validHostnames = [custom_domain, env_hostname, 'localhost'].filter(Boolean);
    // Find hostname by matching origin.hostname in validHostnames
    let hostname = validHostnames.find(h => h === origin.hostname);
    // fail if no match
    if (!hostname)
        throw new Error("Invalid origin in collectedClientData. Expected hostname " + validHostnames.join(', '));
    // For non-localhost, require HTTPS
    if (hostname !== "localhost" && origin.protocol !== "https:")
        throw new Error("Invalid origin in collectedClientData. Expected HTTPS protocol.");

    //Step 7-10: Verify client data
    await validateClientData(clientData, uid, hostname, "webauthn.get");

    //Parse authenticator data used for the next few steps
    const authenticatorData = parseAuthenticatorData(authData);

    //Step 11: Verify that the rpIdHash in authData is the SHA-256 hash of the
    //RP ID expected by the Relying Party.
    const expectedRpId = defaultTo(assertion.metadata.rpId, hostname)
    if (!authenticatorData.rpIdHash.equals(sha256(expectedRpId))) {
        throw new Error("RPID hash does not match expected value: sha256(" + expectedRpId + ")");
    }

    //Step 12: Verify that the User Present bit of the flags in authData is set
    if ((authenticatorData.flags & 0b00000001) == 0) {
        throw new Error("User Present bit was not set.");
    }

    //Step 13-14 are skipped because this is a test site

    //Step 15: Let hash be the result of computing a hash over the cData using
    //SHA-256.
    const hash = sha256(cData);

    //Step 16: Using the credential public key looked up in step 3, verify
    //that sig is a valid signature over the binary concatenation of authData
    //and hash.
    const publicKey = JSON.parse(credential.creationData.publicKey);
    const publicKeyEd = publicKey.key;

    var verify;
    if (publicKey.kty === "RSA")
    {
        verify = crypto.createVerify('RSA-SHA256');
        verify.update(authData);
        verify.update(hash);
        const pubKeyObj = crypto.createPublicKey({ key: publicKey, format: 'jwk' });
        if (!verify.verify(pubKeyObj, sig))
            throw new Error("Could not verify signature");
    }
    else if (publicKey.kty === "EC")
    {
        let algo = 'sha256';
        if (publicKey.crv === "P-384") algo = 'sha384';
        if (publicKey.crv === "P-521") algo = 'sha512';
        verify = crypto.createVerify(algo);
        verify.update(authData);
        verify.update(hash);
        const pubKeyObj = crypto.createPublicKey({ key: publicKey, format: 'jwk' });
        if (!verify.verify(pubKeyObj, sig))
            throw new Error("Could not verify signature");
    }
    else if (publicKey.kty === "AKP")
    {
        // TODO: Implement AKP signature verification
        // This is a placeholder for the AKP signature verification logic.
    }
    else if (publicKeyEd.kty === "OKP")
    {
        if (publicKeyEd.crv === "Ed25519")
        {
            var data = [authData, hash];
            var dataBuf = Buffer.concat(data);
            var pubKey = crypto.createPublicKey(publicKey);
            if (!crypto.verify(null, dataBuf, pubKey, sig))
                throw new Error("Could not verify signature");
        }
    }

    //Step 17: verify signCount
    if (authenticatorData.signCount != 0 &&
        authenticatorData.signCount < credential.signCount) {
        throw new Error("Received signCount of " + authenticatorData.signCount +
            " expected signCount > " + credential.signCount);
    }

    //Update signCount
    const updatedCredential = await storage.Credentials.findOneAndUpdate({
        uid: credential.uid,
        id: credential.id
    }, {
            authenticationData: {
                authenticatorDataSummary: summarizeAuthenticatorData(authenticatorData),
                signCount: authenticatorData.signCount,
                userHandleHex: assertion.userHandle ?
                    Buffer.from(assertion.userHandle, 'base64').toString('hex').toUpperCase() : 'none',
                authenticatorDataHex: Buffer.from(assertion.authenticatorData, 'base64').toString('hex').toUpperCase(),
                clientDataJSON: assertion.clientDataJSON,
                clientDataJSONHex: Buffer.from(assertion.clientDataJSON, 'utf8').toString('hex').toUpperCase(),
                signatureHex: Buffer.from(assertion.signature, 'base64').toString('hex').toUpperCase(),
                extensionDataHex: authenticatorData.extensionDataHex,
                authenticatorAttachment: assertion.authenticatorAttachment,
                prfFirst: assertion.prfFirst,
                prfSecond: assertion.prfSecond,
            }
        }, { new: true });

    return updatedCredential;
};

fido.getCredentials = async (uid, clientHostname) => {

    // Valid hostnames
    let validHostnames = [custom_domain, env_hostname, 'localhost'].filter(Boolean);
    // Find hostname by matching origin.hostname in validHostnames
    let hostname = validHostnames.find(h => h === clientHostname);
    // fail if no match
    if (!hostname)
        throw new Error("No valid relying party ID is configured.");

    const credentials = await storage.Credentials.find({
        uid: uid,
        "metadata.rpId": hostname
    }).lean();

    return credentials;
};

fido.deleteCredential = async (uid, id) => {
    await storage.Credentials.deleteOne({ uid: uid, id: id });
};

/**
 * Validates CollectedClientData
 * @param {any} clientData JSON parsed client data object received from client
 * @param {string} uid user id (used to validate challenge)
 * @param {string} clientHostname expected client hostname (used to validate origin)
 * @param {string} type Operation type: webauthn.create or webauthn.get
 */
const validateClientData = async (clientData, uid, clientHostname, type) => {
    if (clientData.type !== type)
        throw new Error("collectedClientData type was expected to be " + type);

    try {
        // clientData.challenge is base64url-encoded; normalize base64url and compare to stored base64url
        function normalizeBase64Url(b64u) {
            // Remove whitespace
            let s = (b64u || '').trim();
            // Convert standard base64 to base64url by replacing chars
            s = s.split('+').join('-').split('/').join('_');
            // Strip trailing padding
            while (s.endsWith('=')) s = s.slice(0, -1);
            return s;
        }
        const clientB64Url = normalizeBase64Url(clientData.challenge);
        const stored = challengeStore.get(uid);
        if (!stored) throw new Error('No challenge stored');
        if (stored.clientHostname !== clientHostname) throw new Error('Client hostname mismatch');
        if (Date.now() > stored.expiresAt) {
            challengeStore.delete(uid);
            throw new Error('Challenge expired');
        }
        // Compare raw bytes to be robust against minor encoding differences
        function base64UrlToBuffer(b64u) {
            // convert base64url to base64 using safe string ops
            let b64 = (b64u || '').split('-').join('+').split('_').join('/');
            while (b64.length % 4) b64 += '=';
            return Buffer.from(b64, 'base64');
        }
        const clientBuf = base64UrlToBuffer(clientB64Url);
        const storedBuf = base64UrlToBuffer(stored.challengeBase64);
        if (!clientBuf.equals(storedBuf)) {
            console.error('[fido] challenge mismatch', { uid, clientB64Url, storedB64Url: stored.challengeBase64, clientHex: clientBuf.toString('hex'), storedHex: storedBuf.toString('hex') });
            throw new Error('Invalid challenge in collectedClientData');
        }
        // one-time use
        challengeStore.delete(uid);
    } catch (err) {
        throw new Error("Invalid challenge in collectedClientData");
    }
};

const byteToHex = [];

for (let i = 0; i < 256; ++i) {
  byteToHex.push((i + 0x100).toString(16).slice(1));
}

function unsafeStringify(arr, offset = 0) {
  // Note: Be careful editing this code!  It's been tuned for performance
  // and works in ways you may not expect. See https://github.com/uuidjs/uuid/pull/434
  return byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + '-' + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + '-' + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + '-' + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + '-' + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]];
}


/**
 * Parses authData buffer and returns an authenticator data object
 * @param {Buffer} authData
 * @returns {AuthenticatorData} Parsed AuthenticatorData object
 */
function parseAuthenticatorData(authData) {
    try {
        const rpIdHash = authData.subarray(0, 32);
        const flags = authData[32];
        const signCount = (authData[33] << 24) | (authData[34] << 16) | (authData[35] << 8) | (authData[36]);

        /** @type {AuthenticatorData} */
        const authenticatorData = {
            rpIdHash,
            flags,
            signCount,
            attestedCredentialData: undefined,
            extensionDataHex: undefined
        };

        if (flags & 64) {
            //has attestation data
            const aaguidBuffer = authData.subarray(37, 53);
            const aaguid = unsafeStringify(aaguidBuffer).toUpperCase();
            const credentialIdLength = (authData[53] << 8) | authData[54];
            const credentialId = authData.subarray(55, 55 + credentialIdLength);
            const publicKeyBuffer = authData.subarray(55 + credentialIdLength, authData.length);
            const publicKeyHex = coseToHex(publicKeyBuffer);
            //convert public key to JWK for storage
            const publicKey = coseToJwk(publicKeyBuffer);

            authenticatorData.attestedCredentialData = {
                aaguid,
                credentialId,
                credentialIdLength,
                publicKeyHex,
                publicKey
            };
        }

        if (flags & 128) {
            //has extension data
            let extensionDataCbor;

            if (authenticatorData.attestedCredentialData) {
                extensionDataCbor = cbor.decodeAllSync(authData.subarray(55 + authenticatorData.attestedCredentialData.credentialIdLength, authData.length));
                extensionDataCbor = extensionDataCbor[1]; //second element
            } else {
                extensionDataCbor = cbor.decodeFirstSync(authData.subarray(37, authData.length));
            }

            authenticatorData.extensionDataHex = cbor.encode(extensionDataCbor).toString('hex').toUpperCase();
        }
        else
        {
            authenticatorData.extensionDataHex = "No extension data";
        }

        return authenticatorData;
    } catch (e) {
        console.error(`[fido] ${e.message}`);
        throw new Error("Authenticator Data could not be parsed")
    }
}


/**
 * Generates a human readable representation of authenticator data
 * @param {AuthenticatorData} authenticatorData 
 * @returns {String}
 */
const summarizeAuthenticatorData = authenticatorData => {
    try {
        let str = "";

        str += "UP=" + ((authenticatorData.flags & 1) ? "1" : "0");
        str += ", ";
        str += "UV=" + ((authenticatorData.flags & 4) ? "1" : "0");
        str += ", ";
        str += "BE=" + ((authenticatorData.flags & 8) ? "1" : "0");
        str += ", ";
        str += "BS=" + ((authenticatorData.flags & 16) ? "1" : "0");
        str += ", ";
        str += "AT=" + ((authenticatorData.flags & 64) ? "1" : "0");
        str += ", ";
        str += "ED=" + ((authenticatorData.flags & 128) ? "1" : "0");
        str += ", ";
        str += "SignCount=" + authenticatorData.signCount;

        return str;
    } catch (e) {
        throw new Error("Failed to interpret authenticator data.");
    }
}

module.exports = fido;