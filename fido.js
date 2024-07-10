const crypto = require('crypto');
const cbor = require('cbor');
const jwt = require('jsonwebtoken');
const url = require('url');
const base64url = require('base64-url');
const uuid = require('uuid-parse');
const storage = require('./storage.js');
const fidoAttestation = require('./fidoAttestation.js');
const {sha256, jwkToPem, coseToJwk, coseToHex, defaultTo} = require('./utils.js');

const hostname = process.env.HOSTNAME || "localhost";
const jwt_secret = process.env.JWTSECRET || "defaultsecret";

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
fido.getChallenge = (uid) => {
    return jwt.sign({}, jwt_secret, {
        subject: uid, 
        expiresIn: 120 * 1000
    });
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
    let C;
    try {
        C = JSON.parse(attestation.clientDataJSON);
    } catch (e) {
        throw new Error("clientDataJSON could not be parsed");
    }

    //Step 3-6: Verify client data
    validateClientData(C, uid, "webauthn.create");
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
            clientDataJSONHex: "none",
            signatureHex: "none",
            extensionDataHex: defaultTo(authenticatorData.extensionDataHex, "No extension data"),
            authenticatorAttachment: "none",
            prfFirst: "none",
            prfSecond: "none",
        }
    };

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
    let C;
    try {
        C = JSON.parse(cData);
    } catch (e) {
        throw new Error("clientDataJSON could not be parsed");
    }
    //Step 7-10: Verify client data
    validateClientData(C, uid, "webauthn.get");

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
        if (!verify.verify(jwkToPem(publicKey), sig))
            throw new Error("Could not verify signature");
    }
    else if (publicKey.kty === "EC")
    {
        if (publicKey.crv === "P-256")
        {
            verify = crypto.createVerify('sha256');
            verify.update(authData);
            verify.update(hash);
            if (!verify.verify(jwkToPem(publicKey), sig))
                throw new Error("Could not verify signature");
        }
        else if (publicKey.crv === "P-384")
        {
            verify = crypto.createVerify('sha384');
            verify.update(authData);
            verify.update(hash);
            if (!verify.verify(jwkToPem(publicKey), sig))
                throw new Error("Could not verify signature");
        }
        else if (publicKey.crv === "P-521")
        {
            verify = crypto.createVerify('sha512');
            verify.update(authData);
            verify.update(hash);
            if (!verify.verify(jwkToPem(publicKey), sig))
                throw new Error("Could not verify signature");
        }
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

fido.getCredentials = async (uid) => {
    const credentials = await storage.Credentials.find({ uid: uid }).lean();
    return credentials;
};

fido.deleteCredential = async (uid, id) => {
    await storage.Credentials.deleteOne({ uid: uid, id: id });
};

/**
 * Validates CollectedClientData
 * @param {any} clientData JSON parsed client data object received from client
 * @param {string} uid user id (used to validate challenge)
 * @param {string} type Operation type: webauthn.create or webauthn.get
 */
const validateClientData = (clientData, uid, type) => {
    if (clientData.type !== type)
        throw new Error("collectedClientData type was expected to be " + type);

    let origin;
    try {
        origin = url.parse(clientData.origin);
    } catch (e) {
        throw new Error("Invalid origin in collectedClientData");
    }

    if (origin.hostname !== hostname)
        throw new Error("Invalid origin in collectedClientData. Expected hostname " + hostname);

    if (hostname !== "localhost" && origin.protocol !== "https:")
        throw new Error("Invalid origin in collectedClientData. Expected HTTPS protocol.");

    try {
        jwt.verify(base64url.decode(clientData.challenge), jwt_secret, {subject: uid});
    } catch (err) {
        throw new Error("Invalid challenge in collectedClientData");
    }
};


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
            const aaguid = uuid.unparse(authData.subarray(37, 53)).toUpperCase();
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