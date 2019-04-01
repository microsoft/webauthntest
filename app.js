const express = require("express");
const app = express();
const fido = require('./fido.js');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const enforce = require('express-sslify');

if (process.env.ENFORCE_SSL_AZURE === "true") {
    app.use(enforce.HTTPS({ trustAzureHeader: true }));
}
app.use(express.static('public'));
app.use(cookieParser());
app.use(bodyParser.json());

app.get('/credentials', async (req, res) => {
    try {
        const uid = getUser(req);
        const credentials = await fido.getCredentials(uid);
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

app.get('/challenge', async (req, res) => {
    try {
        const uid = getUser(req);
        const challenge = await fido.getChallenge(uid);
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
