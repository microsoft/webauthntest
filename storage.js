
const mongoose = require('mongoose');

const connectPromise = mongoose.connect(process.env.MONGODB_URL || 'mongodb://localhost/fido');

var storage = {};


storage.Credentials = mongoose.model('Credential', new mongoose.Schema({
    uid: {type: String, index: true},
    id: {type: String, index: true},
    idHex: String,
    transports: [{type: String}],
    // Used by MongoDB TTL index to expire documents after 7 days.
    createdAt: { type: Date, default: Date.now, expires: 7 * 24 * 60 * 60 },
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

// Ensure indexes (including TTL) exist once connected.
// Note: if `autoIndex` is disabled in production, this still creates the indexes.
connectPromise
    .then(() => storage.Credentials.createIndexes())
    .catch(() => {
        // Ignore connection/index errors here; request handlers will surface DB issues.
    });



module.exports = storage;