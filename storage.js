
const mongoose = require('mongoose');

mongoose.connect(process.env.MONGODB_URL || 'mongodb://localhost/fido');

var storage = {};


storage.Credentials = mongoose.model('Credential', new mongoose.Schema({
    uid: {type: String, index: true},
    id: {type: String, index: true},
    idHex: String,
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
    },
    authenticationData: {
        authenticatorDataSummary: String,
        signCount: Number,
        userHandleHex: String,
        authenticatorDataHex: String,
        clientDataJSONHex: String,
        signatureHex: String
    }
}));



module.exports = storage;