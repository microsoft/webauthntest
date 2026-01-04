const express = require("express");
const app = express();
const fido = require('./fido.js');
const cookieParser = require('cookie-parser');
const enforce = require('express-sslify');

if (process.env.ENFORCE_SSL_AZURE === "true") {
    app.use(enforce.HTTPS({ trustAzureHeader: true }));
}

const appVersion = `${process.env.npm_package_version}` || 'unknown';

app.use(express.static('public'));
app.use(cookieParser());
app.use(express.json());

app.get('/metadata', (req, res) => {
    res.status(200).json({ appVersion });
  });

app.get('/credentials', async (req, res) => {
    try {
        const uid = getUser(req);
        const clientHostname = req.query.clientHostname;
        const credentials = await fido.getCredentials(uid, clientHostname);
        res.json({
            result: credentials
        });
    } catch (e) {
        res.json({
            error: e.message
        })
    };
});

app.put('/credentials', async (req, res) => {
    try {
        const uid = getUser(req);
        const credential = await fido.makeCredential(uid, req.body);
        res.json({
            result: {
                id: credential.id
            }
        });
    } catch (e) {
        res.json({
            error: e.message
        });
    }
});

app.delete('/credentials', async (req, res) => {
    try {
        const uid = getUser(req);
        await fido.deleteCredential(uid, req.body.id);
        res.json({});
    } catch (e) {
        res.json({
            error: e.message
        });
    }

});

// Updates the transports array for a credential
app.patch('/credentials/transports', async (req, res) => {
    try {
        const uid = getUser(req);
        const { id, transports } = req.body;
        if (!id) {
            throw new Error('id is required');
        }
        if (!Array.isArray(transports)) {
            throw new Error('transports must be an array');
        }
        const allowed = new Set(['internal','usb','nfc','ble','hybrid']);
        const clean = [];
        transports.forEach(t => {
            if (allowed.has(t) && !clean.includes(t)) clean.push(t);
        });
        const updated = await require('./storage').Credentials.findOneAndUpdate({ uid, id }, { transports: clean }, { new: true });
        if (!updated) {
            throw new Error('Credential not found');
        }
        res.json({ result: { id: updated.id, transports: updated.transports } });
    } catch (e) {
        res.json({ error: e.message });
    }
});

// Updates the enabled state for a credential
app.patch('/credentials/enabled', async (req, res) => {
    try {
        const uid = getUser(req);
        const { id, enabled } = req.body;
        if (!id) throw new Error('id is required');
        if (typeof id !== 'string') throw new Error('id must be a string');
        if (typeof enabled !== 'boolean') throw new Error('enabled must be boolean');
        const updated = await require('./storage').Credentials.findOneAndUpdate({ uid, id }, { enabled: enabled }, { new: true });
        if (!updated) throw new Error('Credential not found');
        res.json({ result: { id: updated.id, enabled: updated.enabled } });
    } catch (e) {
        res.json({ error: e.message });
    }
});

app.get('/challenge', async (req, res) => {
    try {
        const uid = getUser(req);
        const clientHostname = req.query.clientHostname;
        const challenge = await fido.getChallenge(uid, clientHostname);
        res.json({
            result: challenge
        });
    } catch (e) {
        res.json({
            error: e.message
        });
    };
});

app.put('/assertion', async (req, res) => {
    try {
        const uid = getUser(req);
        const credential = await fido.verifyAssertion(uid, req.body);
        res.json({
            result: credential
        });
    } catch (e) {
        res.json({
            error: e.message
        });
    }
});

function getUser(req) {
    if (req.cookies.uid) {
        return req.cookies.uid;
    } else {
        throw new Error("You need to sign out and sign back in again.");
    }
}

app.listen(process.env.PORT || 3000, () => console.log('App launched.'));
