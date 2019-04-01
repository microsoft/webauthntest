const {derToPEM} = require('./utils.js');
const jsrsasign = require('jsrsasign');
const crypto = require('crypto');
const cbor = require('cbor');

const fidoAttestation = {};


/**
 * @typedef {import('./public/types').AuthenticatorData} AuthenticatorData
 * @typedef {import('./public/types').AttestedCredentialData} AttestedCredentialData
 * @typedef {import('./public/types').AttestationStatement} AttestationStatement 
 */

/**
 * Parses and verifies an attestation statement
 * @param {*} attestationObject cbor decoded attestation object received from the authenticator
 * @param {AuthenticatorData} authenticatorData 
 * @param {Buffer} clientDataHash 
 * @returns {AttestationStatement}
 */
fidoAttestation.parse = (attestationObject, authenticatorData, clientDataHash) => {

    switch (attestationObject.fmt) {
        case "tpm":
            return parseTPMAttestation(attestationObject, authenticatorData, clientDataHash);
        case "fido-u2f":
            return parseU2FAttestation(attestationObject, authenticatorData, clientDataHash);
        case "packed":
            return parsePackedAttestation(attestationObject, authenticatorData, clientDataHash);
        case "android-safetynet":
            return parseAndroidSafetyNetAttestation(attestationObject, authenticatorData, clientDataHash);
        case "android-key":
            return parseAndroidKeyAttestation(attestationObject, authenticatorData, clientDataHash);
        case "none":
            return {
                summary:"none",
                chainJSON: "none",
                hex: "none"
            };
        default:
            throw new Error("Unknown attestation format");
    }

}

/**
 * Parses TPM attestation statement
 * @param {*} attestationObject 
 * @param {AuthenticatorData} authenticatorData 
 * @param {Buffer} clientDataHash 
 * @returns {AttestationStatement}
 */
const parseTPMAttestation = (attestationObject, authenticatorData, clientDataHash) => {    
    return {
        summary: "tpm (unverified)",
        chainJSON: "none",
        hex: cbor.encode(attestationObject.attStmt).toString('hex').toUpperCase()
    }
};

/**
 * Parses U2F attestation statement
 * @param {*} attestationObject 
 * @param {AuthenticatorData} authenticatorData 
 * @param {Buffer} clientDataHash 
 * @returns {AttestationStatement}
 */
const parseU2FAttestation = (attestationObject, authenticatorData, clientDataHash) => {
    const summary = "fido-u2f";

    //Check that x5c has exactly one element and let attCert be that element. 
    if (attestationObject.attStmt.x5c.length !== 1)
        throw new Error("Expected only one elementh in x5c");

    const attCert = attestationObject.attStmt.x5c[0];

    //Convert the COSE_KEY formatted credentialPublicKey (see Section 7 of [RFC8152]) to Raw ANSI X9.62 public key format
    //Let publicKeyU2F be the concatenation 0x04 || x || y.
    const publicKeyU2F = Buffer.concat([
        Buffer.from('04', 'hex'),
        Buffer.from(authenticatorData.attestedCredentialData.publicKey.x, 'base64'),
        Buffer.from(authenticatorData.attestedCredentialData.publicKey.y, 'base64'),
    ]);

    //Let verificationData be the concatenation of (0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F)
    const verificationData = Buffer.concat([
        Buffer.from('00', 'hex'),
        authenticatorData.rpIdHash,
        clientDataHash,
        authenticatorData.attestedCredentialData.credentialId,
        publicKeyU2F
    ]);

    //Verify the sig using verificationData and certificate public key per [SEC1].
    const pem = derToPEM(attCert.toString('base64'));
    const verify = crypto.createVerify('sha256');
    verify.update(verificationData);
    if (!verify.verify(pem, attestationObject.attStmt.sig)) {
        throw new Error("Attestation signature did not verify");
    }

    const c = new jsrsasign.X509();
    c.readCertPEM(pem);
    const chainJSON = JSON.stringify([{
        version: c.getVersion(),
        subject: c.getSubjectString(),
        issuer: c.getIssuerString()
    }]);

    const hex = cbor.encode(attestationObject.attStmt).toString('hex').toUpperCase();

    return {
        summary,
        chainJSON,
        hex
    };
}

/**
 * Parses packed attestation statement. Only x5c and alg=-7 is supported.
 * @param {*} attestationObject 
 * @param {AuthenticatorData} authenticatorData 
 * @param {Buffer} clientDataHash 
 * @returns {AttestationStatement}
 */
const parsePackedAttestation = (attestationObject, authenticatorData, clientDataHash) => {
    const summary = "packed";

    //https://www.w3.org/TR/webauthn/#packed-attestation

    if (!attestationObject.attStmt.x5c)
        throw new Error("Self and ECDAA attestation statements are not supported")

    //Verify that sig is a valid signature over the concatenation of 
    //authenticatorData and clientDataHash using the attestation public
    //key in attestnCert with the algorithm specified in alg.
    if (attestationObject.attStmt.alg !== -7)
        throw new Error("Packed attestation statement with alg != ES256 not supported")
    const attCert = attestationObject.attStmt.x5c[0];
    const pem = derToPEM(attCert.toString('base64'));
    const verify = crypto.createVerify('sha256');
    verify.update(attestationObject.authData);
    verify.update(clientDataHash);
    if (!verify.verify(pem, attestationObject.attStmt.sig)) {
        throw new Error("Attestation signature did not verify");
    }

    const chain = attestationObject.attStmt.x5c.map(x5c => {
        const p = derToPEM(x5c.toString('base64'));
        const c = new jsrsasign.X509();
        c.readCertPEM(p);
        return {
            version: c.getVersion(),
            subject: c.getSubjectString(),
            issuer: c.getIssuerString(),
            extAaguid: c.getExtInfo("1.3.6.1.4.1.45724.1.1.4")
        };
    });

    const chainJSON = JSON.stringify(chain);    
    const hex = cbor.encode(attestationObject.attStmt).toString('hex').toUpperCase();

    return {
        summary,
        chainJSON,
        hex
    };
}

/**
 * Parses Android safetynet attestation statement.
 * @param {*} attestationObject 
 * @param {AuthenticatorData} authenticatorData 
 * @param {Buffer} clientDataHash 
 * @returns {AttestationStatement}
 */
const parseAndroidSafetyNetAttestation = (attestationObject, authenticatorData, clientDataHash) => {
    return {
        summary: "android-safetynet (unverified)",
        chainJSON: "none",
        hex: cbor.encode(attestationObject.attStmt).toString('hex').toUpperCase()
    }
};

/**
 * Parses android key attestation statement.
 * @param {*} attestationObject 
 * @param {AuthenticatorData} authenticatorData 
 * @param {Buffer} clientDataHash 
 * @returns {AttestationStatement}
 */
const parseAndroidKeyAttestation = (attestationObject, authenticatorData, clientDataHash) => {
    return {
        summary: "android-key (unverified)",
        chainJSON: "none",
        hex: cbor.encode(attestationObject.attStmt).toString('hex').toUpperCase()
    }
};

module.exports = fidoAttestation;