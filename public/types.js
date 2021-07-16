

/**
 * @typedef {Object} EncodedAttestationResponse
 * @property {string} id
 * @property {string} clientDataJSON
 * @property {string} attestationObject
 * @property {Object} metadata
 * @property {string} metadata.rpId
 * @property {boolean} metadata.residentKey
 * @property {string} metadata.userName
 */

 /**
  * @typedef {Object} EncodedAssertionResponse
  * @property {string} id
  * @property {string} clientDataJSON
  * @property {string} signature
  * @property {string} userHandle
  * @property {string} authenticatorData
  * @property {Object} metadata
  * @property {string} metadata.rpId
  */

/**
 * @typedef {Object} Credential
 * @property {string} uid  user id associated with this credential
 * @property {string} id base64 encoded credential id
 * @property {string} idHex hex encoded credential id
 * @property {Object} metadata
 * @property {string} metadata.userName user.name assigned to this credenital
 * @property {string} metadata.rpId rp.id assigned to this credential
 * @property {boolean} metadata.residentKey whether this is a resident key
 * @property {Object} creationData
 * @property {Object} creationData.publicKey JWK represetation of cred public key
 * @property {string} creationData.publicKeySummary human readable summary of credential public key
 * @property {string} creationData.publicKeyHex raw credential public key, hex encoded
 * @property {string} creationData.aaguid AAGUID of the authenticator
 * @property {string} creationData.attestationStatementHex raw attestation statement, hex encoded
 * @property {string} creationData.attestationStatementSummary human readable summary of attestation statement
 * @property {string} creationData.attestationStatementChainJSON JSON encoded attestation chain
 * @property {string} creationData.authenticatorDataSummary human readable summary of authenticator data at credential creation time
 * @property {string} creationData.authenticatorDataHex raw authenticator at credential creation time
 * @property {string} creationData.extensionDataHex raw extension data at credential creation time
 * @property {Object} authenticationData
 * @property {string} authenticationData.authenticatorDataSummary human readable summary of last authenticator data
 * @property {number} authenticationData.signCount sign count of last authentication
 * @property {string} authenticationData.authenticatorDataHex raw authenticator data of last authentication
 * @property {string} authenticationData.signatureHex raw signature of last authentication
 * @property {string} authenticationData.clientDataJSONHex raw clientDataJSON of last authentication
 * @property {string} authenticationData.userHandleHex raw userHandle of last authentication
 * @property {string} authenticationData.extensionDataHex raw extension data of last authentication
 */

/** 
 * @typedef {Object} AuthenticatorData
 * @property {Buffer} rpIdHash rpId hash
 * @property {number} flags flags indicating UP, UV, ED
 * @property {number} signCount sign count
 * @property {AttestedCredentialData} attestedCredentialData
 * @property {string} extensionDataHex 
 */

 /** 
 * @typedef {Object} AttestedCredentialData
 * @property {string} aaguid AAGUID of the authenticator
 * @property {Object} publicKey JWK representation of public key
 * @property {string} publicKeyHex raw credential public key, hex encoded
 * @property {Buffer} credentialId raw credential id buffer
 * @property {number} credentialIdLength Length of the credential ID
 */ 

  /** 
 * @typedef {Object} AttestationStatement
 * @property {string} summary Human readable summary of the attestation statement
 * @property {string} chainJSON Attestation statement chain represented in JSON
 * @property {string} hex hex representation of attestation statement chain
 */ 



 module.exports = {};