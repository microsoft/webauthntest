
const mongoose = require('mongoose');

mongoose.connect(process.env.AZURE_COSMOS_CONNECTIONSTRING || 'mongodb://localhost/fido');

var storage = {};


storage.Credentials = mongoose.model('Credential', new mongoose.Schema({
    uid: {type: String, index: true},
    id: {type: String, index: true},
    idHex: String,
    transports: [{type: String}],
    // enabled flag for credential state; if missing on older records, treat as enabled
    enabled: { type: Boolean, default: true },
    metadata: {
        rpId: String,
        userName: String,
        residentKey: String
    },
    creationData: {
        publicKey: String,
        publicKeySummary: String,
        publicKeyHex: String,
        aaguid: String,
        attestationStatementHex: String,
        attestationStatementSummary: String,
        attestationStatementChainJSON : String,
        authenticatorDataSummary: String,
        authenticatorDataHex: String,
        extensionDataHex: String,
        authenticatorData: String,
        attestationObject: String,
        clientDataJSON: String,
        clientDataJSONHex: String,
        publicKey2: String,
        publicKeyAlgorithm: Number,
        authenticatorAttachment: String,
        prfEnabled: Boolean,
        prfFirst: String,
        prfSecond: String,
    },
    authenticationData: {
        authenticatorDataSummary: String,
        signCount: Number,
        userHandleHex: String,
        authenticatorDataHex: String,
        clientDataJSON: String,
        clientDataJSONHex: String,
        signatureHex: String,
        extensionDataHex: String,
        authenticatorAttachment: String,
        prfFirst: String,
        prfSecond: String,
    }
}));



module.exports = storage;