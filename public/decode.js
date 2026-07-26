// WebAuthn Decoder page.
// Auto-detects and renders attestation objects, authenticator data, and X.509
// certificates pasted as hex / base64 / base64url / PEM. CBOR decoding is reused
// from cbor.js (window.CBORPlayground); certificate parsing uses PKIJS.

import * as asn1js from 'https://cdn.skypack.dev/asn1js@3.0.6';
import * as pvutils from 'https://cdn.skypack.dev/pvutils@1.1.3';
import * as pvtsutils from 'https://cdn.skypack.dev/pvtsutils@1.3.6';
import * as pkijs from 'https://cdn.skypack.dev/pkijs@3.3.0';

window.asn1js = asn1js;
window.pvutils = pvutils;
window.pvtsutils = pvtsutils;
window.pkijs = pkijs;

try {
    if (pkijs && typeof pkijs.setEngine === 'function' && typeof pkijs.CryptoEngine === 'function') {
        const engine = new pkijs.CryptoEngine({ name: 'webcrypto', crypto: window.crypto });
        pkijs.setEngine('webcrypto', engine);
    }
} catch (e) {
    console.warn('PKIJS engine init failed:', e);
}

(function () {
    const CBOR = window.CBORPlayground;

    // ---------------------------------------------------------------- helpers
    function escapeHtml(str) {
        return String(str == null ? '' : str)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function bytesToHex(u8) {
        return Array.from(u8).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    function debounce(fn, ms) {
        let t = null;
        return function () {
            const args = arguments;
            if (t) clearTimeout(t);
            t = setTimeout(() => { t = null; fn.apply(null, args); }, ms || 120);
        };
    }

    // Choose the largest bytes-per-row (from 4/8/16/32) whose colon-hex line fits
    // the element's current width. Mirrors the responsive hex used elsewhere.
    function bytesPerRowFor(el, maxBytes) {
        try {
            const options = [4, 8, 16, 32].filter(n => n <= (maxBytes || 32)).sort((a, b) => b - a);
            const rect = el.getBoundingClientRect();
            const elWidth = rect.width || el.clientWidth || 400;
            const cs = window.getComputedStyle(el);
            const pl = parseFloat(cs.paddingLeft) || 0;
            const pr = parseFloat(cs.paddingRight) || 0;
            const avail = Math.max(0, elWidth - pl - pr - 8);
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            ctx.font = cs.font || ((cs.fontSize || '12.5px') + ' ' + (cs.fontFamily || 'monospace'));
            for (const opt of options) {
                const sample = new Array(opt).fill('00').join(':');
                if (ctx.measureText(sample).width + 2 <= avail) return opt;
            }
            return options[options.length - 1] || 8;
        } catch (e) { return 16; }
    }

    // Responsively (re)format every hex block under `root`, wrapping colon-hex to
    // fit the current width (max 32 bytes/row) and re-applying on resize.
    function formatHexBlocks(root) {
        const pres = (root || document).querySelectorAll('pre.decode-hex[data-hex]');
        pres.forEach(pre => {
            const hex = pre.getAttribute('data-hex') || '';
            const pairs = hex.match(/.{1,2}/g) || [];
            const apply = () => {
                const per = bytesPerRowFor(pre, 32);
                const lines = [];
                for (let i = 0; i < pairs.length; i += per) lines.push(pairs.slice(i, i + per).join(':'));
                pre.textContent = lines.join('\n');
            };
            apply();
            try {
                if (typeof ResizeObserver !== 'undefined') {
                    if (pre._ro) { try { pre._ro.disconnect(); } catch (e) { /* ignore */ } }
                    const ro = new ResizeObserver(debounce(apply, 120));
                    ro.observe(pre);
                    if (pre.parentElement) ro.observe(pre.parentElement);
                    pre._ro = ro;
                }
            } catch (e) { /* ignore */ }
        });
    }

    function toast(message) {
        const container = document.getElementById('toast');
        if (!container) return;
        const el = document.createElement('div');
        el.className = 'alert alert-info py-2 px-3 text-sm';
        el.textContent = message;
        container.appendChild(el);
        setTimeout(() => { el.remove(); }, 2500);
    }

    // Parse the pasted text into bytes. Accepts PEM, hex (optionally 0x-prefixed),
    // base64, and base64url.
    function parseInput(text) {
        let raw = String(text || '').trim();
        if (!raw) throw new Error('Nothing to decode');

        // PEM: strip header/footer and decode the base64 body.
        const pemMatch = raw.match(/-----BEGIN [^-]+-----([\s\S]*?)-----END [^-]+-----/);
        if (pemMatch) {
            return CBOR.base64ToBytes(pemMatch[1].replace(/\s+/g, ''));
        }

        const compact = raw.replace(/\s+/g, '');
        const hexCandidate = compact.replace(/^0x/i, '');
        if (/^[0-9a-fA-F]+$/.test(hexCandidate) && hexCandidate.length % 2 === 0) {
            return CBOR.hexToBytes(hexCandidate);
        }
        // Fall back to base64 / base64url.
        return CBOR.base64ToBytes(compact);
    }

    function looksLikeCbor(value) {
        return value && typeof value === 'object' && !ArrayBuffer.isView(value) && !Array.isArray(value);
    }

    // ------------------------------------------------------------- detection
    function detect(bytes) {
        // 1) X.509 certificate: DER starts with SEQUENCE (0x30) and parses with PKIJS.
        if (bytes.length > 2 && bytes[0] === 0x30) {
            try {
                const ab = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
                const asn1 = asn1js.fromBER(ab);
                if (asn1.offset !== -1) {
                    // eslint-disable-next-line no-new
                    new pkijs.Certificate({ schema: asn1.result });
                    return { type: 'certificate', bytes };
                }
            } catch (e) { /* not a cert */ }
        }

        // 2) Attestation object: CBOR map with fmt + authData (+ attStmt).
        try {
            const decoded = CBOR.decodeCbor(bytes);
            if (looksLikeCbor(decoded) && decoded.authData && (decoded.fmt !== undefined)) {
                return { type: 'attestationObject', bytes, decoded };
            }
            // Generic CBOR fallback (still useful).
            return { type: 'cbor', bytes, decoded };
        } catch (e) { /* not top-level CBOR */ }

        // 3) Authenticator data: at least rpIdHash(32) + flags(1) + signCount(4).
        if (bytes.length >= 37) {
            return { type: 'authenticatorData', bytes };
        }

        throw new Error('Could not detect data type. Provide an attestation object, authenticator data, or X.509 certificate.');
    }

    // ---------------------------------------------------- authenticator data
    function formatUuid(u8) {
        const h = bytesToHex(u8);
        return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
    }

    function coseAlgName(alg) {
        const names = {
            '-7': 'ES256', '-35': 'ES384', '-36': 'ES512',
            '-257': 'RS256', '-258': 'RS384', '-259': 'RS512',
            '-37': 'PS256', '-38': 'PS384', '-39': 'PS512',
            '-8': 'EdDSA', '-65535': 'RS1',
            '-48': 'ML-DSA-44', '-49': 'ML-DSA-65', '-50': 'ML-DSA-87',
        };
        return names[String(alg)] || null;
    }

    // Convert a decoded COSE_Key map (string keys, Uint8Array values) into a
    // display object where byte strings are shown as hex, like the Yubico tool.
    function coseMapToDisplay(map) {
        const out = {};
        Object.keys(map).forEach(k => {
            const v = map[k];
            out[k] = ArrayBuffer.isView(v) ? bytesToHex(new Uint8Array(v.buffer, v.byteOffset, v.byteLength)).toUpperCase() : v;
        });
        return out;
    }

    function parseAuthenticatorData(authData) {
        if (authData.length < 37) throw new Error('Authenticator data too short');
        const rpIdHash = authData.slice(0, 32);
        const flags = authData[32];
        const signCount = (authData[33] << 24) | (authData[34] << 16) | (authData[35] << 8) | authData[36];

        const out = { rpIdHash, flags, signCount, attested: null, extensions: null };

        let offset = 37;
        if (flags & 0x40) { // AT
            const aaguid = authData.slice(offset, offset + 16); offset += 16;
            const credIdLen = (authData[offset] << 8) | authData[offset + 1]; offset += 2;
            const credentialId = authData.slice(offset, offset + credIdLen); offset += credIdLen;
            const rest = authData.slice(offset);

            let coseKey = null, extensions = null, coseKeyBytes = null, extBytes = null;
            try {
                // Determine the exact COSE key byte length so we can split off any
                // trailing extension map (present when the ED flag is set).
                let len = rest.length;
                for (let n = 1; n <= rest.length; n++) {
                    try { coseKey = CBOR.decodeCbor(rest.slice(0, n)); len = n; break; } catch (e) { /* keep growing */ }
                }
                coseKeyBytes = rest.slice(0, len);
                if ((flags & 0x80) && len < rest.length) {
                    extBytes = rest.slice(len);
                    try { extensions = CBOR.decodeCbor(extBytes); } catch (e) { /* ignore */ }
                }
            } catch (e) { /* leave null */ }

            out.attested = { aaguid, credentialId, credIdLen, coseKey, coseKeyBytes };
            if (extensions) { out.extensions = extensions; out.extensionsBytes = extBytes; }
        } else if (flags & 0x80) { // ED without AT
            try {
                out.extensions = CBOR.decodeCbor(authData.slice(37));
                out.extensionsBytes = authData.slice(37);
            } catch (e) { /* ignore */ }
        }

        return out;
    }

    function flagsSummary(flags) {
        const bin = flags.toString(2).padStart(8, '0');
        const bit = (mask) => (flags & mask) ? '1' : '0';
        return `0x${flags.toString(16).padStart(2, '0').toUpperCase()} = 0b${bin} = `
            + `UP:${bit(0x01)}  UV:${bit(0x04)}  BE:${bit(0x08)}  BS:${bit(0x10)}  AT:${bit(0x40)}  ED:${bit(0x80)}`;
    }

    // ---------------------------------------------------------- rendering DOM
    function kvRow(label, valueHtml, opts) {
        opts = opts || {};
        const copy = opts.copy
            ? `<button class="btn btn-ghost btn-xs btn-square decode-copy" data-copy="${escapeHtml(opts.copy)}" title="Copy"><span class="material-symbols-outlined" aria-hidden="true">content_copy</span></button>`
            : '';
        const extra = opts.extra || '';
        // Actions (extra then copy) are pinned to the right edge so the copy icon
        // aligns with the hex-block copy icons.
        const actions = (copy || extra) ? `<span class="decode-actions">${extra}${copy}</span>` : '';
        return `<div class="decode-row"><span class="decode-label">${escapeHtml(label)}</span>`
            + `<div class="decode-value"><div class="decode-value-content">${valueHtml}</div>${actions}</div></div>`;
    }

    function mono(text) { return `<span class="decode-mono">${escapeHtml(text)}</span>`; }
    function preBlock(text) { return `<pre class="decode-block">${escapeHtml(text)}</pre>`; }

    // A responsive hex block (colon-separated uppercase, wrapped to fit width) with
    // a copy button pinned to the top-right (aligned with the first line).
    function hexBlock(u8) {
        const hex = plainHexUpper(u8); // uppercase, no separators (also the copy value)
        return '<div class="decode-hexblock">'
            + `<pre class="decode-block decode-hex" data-hex="${hex}">${escapeHtml(hexColonUpperWrapped(u8, 16))}</pre>`
            + `<button class="btn btn-ghost btn-xs btn-square decode-copy decode-hexcopy" data-copy="${hex}" title="Copy"><span class="material-symbols-outlined" aria-hidden="true">content_copy</span></button>`
            + '</div>';
    }

    function renderAuthenticatorDataSection(ad) {
        let html = '';
        html += kvRow('RP ID Hash', hexBlock(ad.rpIdHash));
        html += kvRow('Flags', mono(flagsSummary(ad.flags)));
        html += kvRow('Counter', mono(`0x${(ad.signCount >>> 0).toString(16).padStart(8, '0').toUpperCase()} = ${ad.signCount >>> 0}`));

        if (ad.attested) {
            const a = ad.attested;
            const uuid = formatUuid(a.aaguid).toUpperCase();
            const mdsBtn = `<a class="btn btn-ghost btn-xs btn-square" href="./mds.html?aaguid=${encodeURIComponent(uuid)}" target="_blank" rel="noopener" title="View Authenticator Metadata"><span class="material-symbols-outlined" aria-hidden="true">badge</span></a>`;
            html += kvRow('AAGUID', mono(uuid), { copy: uuid, extra: mdsBtn });
            html += kvRow('Credential ID', hexBlock(a.credentialId));
            if (a.coseKey && looksLikeCbor(a.coseKey)) {
                const alg = a.coseKey['3'];
                const algName = coseAlgName(alg);
                html += kvRow('Key Algorithm', mono(algName ? `${algName} (${alg})` : `alg ${alg}`));
                const pkHex = a.coseKeyBytes ? hexBlock(a.coseKeyBytes) : '';
                html += kvRow('Public Key', pkHex + preBlock(JSON.stringify(coseMapToDisplay(a.coseKey), null, 2)));
            }
        }
        const extHex = ad.extensionsBytes ? hexBlock(ad.extensionsBytes) : '';
        html += kvRow('Authenticator Extensions', ad.extensions
            ? (extHex + preBlock(JSON.stringify(ad.extensions, jsonReplacer, 2)))
            : mono('(none)'));
        return html;
    }

    function jsonReplacer(key, value) {
        if (ArrayBuffer.isView(value)) return bytesToHex(new Uint8Array(value.buffer, value.byteOffset, value.byteLength)).toUpperCase();
        return value;
    }

    // Authenticator-data section from a decoded attestation object.
    function attestationAuthDataHtml(decoded) {
        const authData = decoded.authData instanceof Uint8Array ? decoded.authData : new Uint8Array(decoded.authData);
        try {
            return renderAuthenticatorDataSection(parseAuthenticatorData(authData));
        } catch (e) {
            return kvRow('Authenticator Data', mono('Failed to parse: ' + e.message));
        }
    }

    // Attestation format + statement fields + certificates from a decoded attestation object.
    async function attestationFormatAndCertsHtml(decoded) {
        let html = kvRow('Attestation Format', mono(String(decoded.fmt)));
        const att = decoded.attStmt || {};
        const labels = {
            alg: 'Attestation Algorithm', sig: 'Attestation Signature',
            ver: 'TPM Version', certInfo: 'TPM certInfo', pubArea: 'TPM pubArea',
            response: 'Response', ecdaaKeyId: 'ECDAA Key ID'
        };
        // Render every statement field except x5c (shown as certificates below).
        Object.keys(att).forEach(k => {
            if (k === 'x5c') return;
            const v = att[k];
            const label = labels[k] || k;
            if (k === 'alg' && typeof v === 'number') {
                const nm = coseAlgName(v);
                html += kvRow(label, mono(nm ? `${nm} (${v})` : `alg ${v}`));
            } else if (ArrayBuffer.isView(v)) {
                html += kvRow(label, hexBlock(new Uint8Array(v.buffer, v.byteOffset, v.byteLength)));
            } else if (v && typeof v === 'object') {
                html += kvRow(label, preBlock(JSON.stringify(v, jsonReplacer, 2)));
            } else {
                html += kvRow(label, mono(String(v)));
            }
        });
        const x5c = att.x5c;
        if (Array.isArray(x5c) && x5c.length > 0) {
            html += '<div class="decode-subheading">Attestation Certificates</div>';
            for (let i = 0; i < x5c.length; i++) {
                const der = x5c[i] instanceof Uint8Array ? x5c[i] : new Uint8Array(x5c[i]);
                html += await renderCertificateSection(der);
            }
        }
        return html;
    }

    // Renders the body of an attestation object (authenticator data + format +
    // certificates), without a section heading.
    async function attestationBodyHtml(decoded) {
        return attestationAuthDataHtml(decoded) + await attestationFormatAndCertsHtml(decoded);
    }

    async function renderAttestationObject(decoded, bytes) {
        let html = '<div class="decode-heading">Attestation Object</div>';
        html += await attestationBodyHtml(decoded);
        return { html, raw: CBOR.formatDiagnostic(decoded) };
    }

    // Is this parsed JSON a PublicKeyCredential (toJSON) registration/assertion object?
    function isPublicKeyCredentialJSON(obj) {
        if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return false;
        const resp = obj.response;
        if (!resp || typeof resp !== 'object') return false;
        return typeof resp.attestationObject === 'string'
            || (typeof resp.authenticatorData === 'string' && typeof resp.clientDataJSON === 'string');
    }

    function clientExtensionsHtml(cred) {
        const cext = cred.clientExtensionResults;
        return kvRow('Client Extensions', (cext && typeof cext === 'object' && Object.keys(cext).length)
            ? preBlock(JSON.stringify(cext, null, 2))
            : mono('(none)'));
    }

    function clientDataHtml(resp) {
        if (typeof resp.clientDataJSON !== 'string') return '';
        try {
            const cdObj = JSON.parse(new TextDecoder().decode(CBOR.base64ToBytes(resp.clientDataJSON)));
            return kvRow('Client Data', preBlock(JSON.stringify(cdObj, null, 2)));
        } catch (e) { return ''; }
    }

    // Renders a PublicKeyCredential JSON object (the result of navigator.credentials
    // .create()/.get() .toJSON()): registration or assertion.
    async function renderPublicKeyCredentialJSON(cred) {
        let html = '<div class="decode-heading">PublicKeyCredential</div>';
        const resp = cred.response || {};
        const b64 = (s) => CBOR.base64ToBytes(s);

        // Top-level credential field.
        if (cred.id) html += kvRow('Credential ID (Base64URL)', mono(String(cred.id)), { copy: String(cred.id) });

        if (typeof resp.attestationObject === 'string') {
            // Registration. Group credential/key summary fields together (near the
            // top-level metadata), then authenticator data, then Client Extensions +
            // Client Data, and finally Attestation Format + Certificates.
            if (cred.authenticatorAttachment) html += kvRow('Authenticator Attachment', mono(String(cred.authenticatorAttachment)));
            if (Array.isArray(resp.transports) && resp.transports.length) {
                html += kvRow('Transports', mono(resp.transports.join(', ')));
            }
            if (typeof resp.publicKeyAlgorithm === 'number') {
                const nm = coseAlgName(resp.publicKeyAlgorithm);
                html += kvRow('Public Key Algorithm', mono(nm ? `${nm} (${resp.publicKeyAlgorithm})` : `alg ${resp.publicKeyAlgorithm}`));
            }
            if (typeof resp.publicKey === 'string' && resp.publicKey) {
                html += kvRow('Public Key (DER)', hexBlock(b64(resp.publicKey)));
            }
            html += clientDataHtml(resp);
            html += clientExtensionsHtml(cred);
            try {
                const decoded = CBOR.decodeCbor(b64(resp.attestationObject));
                html += attestationAuthDataHtml(decoded);
                html += await attestationFormatAndCertsHtml(decoded);
            } catch (e) {
                html += kvRow('Attestation Object', mono('Failed to parse: ' + e.message));
            }
        } else if (typeof resp.authenticatorData === 'string') {
            // Assertion.
            if (typeof resp.userHandle === 'string' && resp.userHandle) html += kvRow('User Handle', hexBlock(b64(resp.userHandle)));
            if (cred.authenticatorAttachment) html += kvRow('Authenticator Attachment', mono(String(cred.authenticatorAttachment)));
            html += clientDataHtml(resp);
            html += clientExtensionsHtml(cred);
            try {
                const ad = parseAuthenticatorData(b64(resp.authenticatorData));
                html += renderAuthenticatorDataSection(ad);
            } catch (e) {
                html += kvRow('Authenticator Data', mono('Failed to parse: ' + e.message));
            }
            if (typeof resp.signature === 'string') html += kvRow('Signature', hexBlock(b64(resp.signature)));
        }

        return { html };
    }

    async function renderAuthenticatorDataOnly(bytes) {
        const ad = parseAuthenticatorData(bytes);
        let html = '<div class="decode-heading">Authenticator Data</div>';
        html += renderAuthenticatorDataSection(ad);
        return { html, raw: bytesToHex(bytes) };
    }

    // Is this parsed JSON a WebAuthn request-options object (the argument passed to
    // navigator.credentials.create()/get(), as captured for the request preview)?
    function isWebAuthnRequestOptions(obj) {
        if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return false;
        const pk = obj.publicKey;
        if (!pk || typeof pk !== 'object' || Array.isArray(pk)) return false;
        return typeof pk.challenge === 'string' && pk.challenge.length > 0;
    }

    // Render a hex string as a hex block, falling back to mono text if not valid hex.
    function hexStringBlock(hexStr) {
        try {
            const s = String(hexStr || '').trim();
            if (s && /^[0-9a-fA-F]*$/.test(s) && s.length % 2 === 0) {
                return hexBlock(CBOR.hexToBytes(s));
            }
        } catch (e) { /* fall through */ }
        return mono(String(hexStr));
    }

    // Render a list of PublicKeyCredentialDescriptors (exclude/allow credentials).
    function credentialDescriptorsHtml(label, list) {
        if (!Array.isArray(list) || list.length === 0) return '';
        let html = '';
        list.forEach((d, i) => {
            const id = d && typeof d.id === 'string' ? d.id : '';
            const transports = d && Array.isArray(d.transports) && d.transports.length ? ' [' + d.transports.join(', ') + ']' : '';
            html += kvRow(label + ' #' + (i + 1) + transports, id ? hexStringBlock(id) : mono('(no id)'));
        });
        return html;
    }

    // Renders a WebAuthn request-options object (create() or get() argument).
    async function renderWebAuthnRequestOptions(obj) {
        const pk = obj.publicKey || {};
        const isCreate = !!(pk.pubKeyCredParams || pk.user || pk.rp);
        let html = '<div class="decode-heading">' + (isCreate
            ? 'PublicKeyCredential Creation Request'
            : 'PublicKeyCredential Request (Assertion)') + '</div>';

        html += kvRow('Operation', mono(isCreate ? 'navigator.credentials.create()' : 'navigator.credentials.get()'));
        if (typeof obj.mediation === 'string') html += kvRow('Mediation', mono(obj.mediation));
        if (typeof pk.challenge === 'string') html += kvRow('Challenge', hexStringBlock(pk.challenge));

        if (isCreate) {
            if (pk.rp && typeof pk.rp === 'object') {
                if (pk.rp.id) html += kvRow('RP ID', mono(String(pk.rp.id)));
                if (pk.rp.name) html += kvRow('RP Name', mono(String(pk.rp.name)));
            }
            if (pk.user && typeof pk.user === 'object') {
                if (typeof pk.user.id === 'string') html += kvRow('User ID', hexStringBlock(pk.user.id));
                if (pk.user.name) html += kvRow('User Name', mono(String(pk.user.name)));
                if (pk.user.displayName) html += kvRow('User Display Name', mono(String(pk.user.displayName)));
            }
            if (Array.isArray(pk.pubKeyCredParams) && pk.pubKeyCredParams.length) {
                const lines = pk.pubKeyCredParams.map(p => {
                    const alg = p && typeof p.alg === 'number' ? p.alg : null;
                    const nm = alg !== null ? coseAlgName(alg) : null;
                    return nm ? `${nm} (${alg})` : (alg !== null ? `alg ${alg}` : 'unknown');
                });
                html += kvRow('Pub Key Cred Params', preBlock(lines.join('\n')));
            }
            if (pk.authenticatorSelection && typeof pk.authenticatorSelection === 'object') {
                html += kvRow('Authenticator Selection', preBlock(JSON.stringify(pk.authenticatorSelection, null, 2)));
            }
            if (typeof pk.attestation === 'string') html += kvRow('Attestation', mono(pk.attestation));
            html += credentialDescriptorsHtml('Exclude Credentials', pk.excludeCredentials);
        } else {
            if (typeof pk.rpId === 'string') html += kvRow('RP ID', mono(pk.rpId));
            if (typeof pk.userVerification === 'string') html += kvRow('User Verification', mono(pk.userVerification));
            html += credentialDescriptorsHtml('Allow Credentials', pk.allowCredentials);
        }

        if (typeof pk.timeout === 'number') html += kvRow('Timeout', mono(String(pk.timeout) + ' ms'));
        if (pk.extensions && typeof pk.extensions === 'object' && Object.keys(pk.extensions).length) {
            html += kvRow('Extensions', preBlock(JSON.stringify(pk.extensions, null, 2)));
        }

        return { html };
    }

    // -------------------------------------------------------- certificate
    function oidToName(oid) {
        const map = {
            '1.3.6.1.5.5.7.3.1': 'TLS Web Server Authentication',
            '1.3.6.1.5.5.7.3.2': 'TLS Web Client Authentication',
            '1.3.6.1.5.5.7.3.3': 'Code Signing',
            '1.2.840.113549.1.1.1': 'RSA Encryption',
            '1.2.840.10045.2.1': 'EC Public Key',
            '1.3.101.112': 'Ed25519',
            '2.16.840.1.101.3.4.3.17': 'ML-DSA-44',
            '2.16.840.1.101.3.4.3.18': 'ML-DSA-65',
            '2.16.840.1.101.3.4.3.19': 'ML-DSA-87',
            '2.5.4.3': 'Common Name', '2.5.4.6': 'Country',
            '2.5.4.10': 'Organization', '2.5.4.11': 'Organizational Unit',
        };
        return map[oid] || oid;
    }

    function convertToPEM(bytes) {
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
        const b64 = btoa(binary);
        const chunks = b64.match(/.{1,64}/g) || [];
        return '-----BEGIN CERTIFICATE-----\n' + chunks.join('\n') + '\n-----END CERTIFICATE-----\n';
    }

    function formatName(tavs) {
        try {
            const parts = tavs.map(tv => {
                const val = tv.value && tv.value.valueBlock ? (tv.value.valueBlock.value || '') : '';
                return `${oidToName(tv.type)}=${val}`;
            });
            const cn = tavs.find(tv => tv.type === '2.5.4.3');
            const cnVal = cn && cn.value && cn.value.valueBlock ? cn.value.valueBlock.value : null;
            return cnVal ? `${cnVal} (${parts.join(', ')})` : parts.join(', ');
        } catch (e) { return ''; }
    }

    function keyUsageNames(bitString) {
        try {
            const vb = bitString && bitString.valueBlock ? bitString.valueBlock : null;
            const hex = vb && vb.valueHex ? vb.valueHex : null;
            const unused = vb && typeof vb.unusedBits === 'number' ? vb.unusedBits : 0;
            if (!hex) return '';
            const bytes = new Uint8Array(hex);
            const totalBits = (bytes.length * 8) - unused;
            const names = ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment',
                'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly'];
            const out = [];
            for (let i = 0; i < Math.min(totalBits, names.length); i++) {
                if ((bytes[Math.floor(i / 8)] & (1 << (7 - (i % 8)))) !== 0) out.push(names[i]);
            }
            return out.join(', ');
        } catch (e) { return ''; }
    }

    // ---- OpenSSL-style ("x509 -text") full dump helpers ----------------------
    const SIG_ALG_NAMES = {
        '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
        '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
        '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
        '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
        '1.2.840.113549.1.1.10': 'rsassaPss',
        '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
        '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
        '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
        '1.3.101.112': 'Ed25519',
        '2.16.840.1.101.3.4.3.17': 'ML-DSA-44',
        '2.16.840.1.101.3.4.3.18': 'ML-DSA-65',
        '2.16.840.1.101.3.4.3.19': 'ML-DSA-87',
    };
    const DN_SHORT = {
        '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST',
        '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.5': 'serialNumber',
        '1.2.840.113549.1.9.1': 'emailAddress',
    };
    const EXT_NAMES = {
        '2.5.29.14': 'X509v3 Subject Key Identifier',
        '2.5.29.15': 'X509v3 Key Usage',
        '2.5.29.17': 'X509v3 Subject Alternative Name',
        '2.5.29.19': 'X509v3 Basic Constraints',
        '2.5.29.31': 'X509v3 CRL Distribution Points',
        '2.5.29.32': 'X509v3 Certificate Policies',
        '2.5.29.35': 'X509v3 Authority Key Identifier',
        '2.5.29.37': 'X509v3 Extended Key Usage',
        '1.3.6.1.5.5.7.1.1': 'Authority Information Access',
        '1.3.6.1.4.1.45724.1.1.4': 'id-fido-gen-ce-aaguid',
    };
    const EC_CURVE_NAMES = {
        '1.2.840.10045.3.1.7': 'prime256v1 (P-256)',
        '1.3.132.0.34': 'secp384r1 (P-384)',
        '1.3.132.0.35': 'secp521r1 (P-521)',
    };

    function sigAlgName(oid) { return SIG_ALG_NAMES[oid] ? `${SIG_ALG_NAMES[oid]} (${oid})` : oid; }

    function u8FromHexBuf(buf) {
        if (!buf) return new Uint8Array(0);
        return buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    }

    // Wrap bytes as colon-separated uppercase hex, 32 bytes per line, indented.
    function wrapHexColon(u8, indent) {
        const per = 32;
        const out = [];
        for (let i = 0; i < u8.length; i += per) {
            const slice = Array.from(u8.slice(i, i + per)).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(':');
            out.push(indent + slice + (i + per < u8.length ? ':' : ''));
        }
        return out.length ? out.join('\n') : (indent + '(empty)');
    }

    function hexColonStr(hex) { return (hex.match(/.{1,2}/g) || []).join(':').toUpperCase(); }
    // Uppercase colon-separated hex, wrapped to `perLine` bytes per line (default 16).
    function hexColonUpperWrapped(u8, perLine) {
        perLine = perLine || 16;
        const lines = [];
        for (let i = 0; i < u8.length; i += perLine) {
            lines.push(Array.from(u8.slice(i, i + perLine)).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(':'));
        }
        return lines.join('\n');
    }
    function plainHexUpper(u8) { return Array.from(u8).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase(); }
    function bufToHexLower(buf) { return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join(''); }

    function dnString(tavs) {
        try {
            const parts = (tavs || []).map(tv => {
                const nm = DN_SHORT[tv.type] || tv.type;
                const val = tv.value && tv.value.valueBlock ? (tv.value.valueBlock.value || '') : '';
                return `${nm}=${val}`;
            });
            return parts.join(', ');
        } catch (e) { return ''; }
    }

    function isoOrRaw(v) {
        try { return v.toISOString().replace('.000Z', 'Z'); } catch (e) { return String(v); }
    }

    // Compact MD5 (Web Crypto lacks MD5). Returns lowercase hex.
    function md5Hex(input) {
        function rl(x, c) { return ((x << c) | (x >>> (32 - c))) >>> 0; }
        const s = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
            5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
        const K = new Uint32Array(64);
        for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) >>> 0;
        let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
        const msgLen = input.length;
        const total = ((msgLen + 8) >> 6) * 64 + 64; // multiple of 64 leaving room for 0x80 + length
        const bytes = new Uint8Array(total);
        bytes.set(input);
        bytes[msgLen] = 0x80;
        const dv = new DataView(bytes.buffer);
        const bitLen = msgLen * 8;
        dv.setUint32(total - 8, bitLen >>> 0, true);
        dv.setUint32(total - 4, Math.floor(bitLen / 4294967296) >>> 0, true);
        for (let off = 0; off < total; off += 64) {
            const M = new Uint32Array(16);
            for (let i = 0; i < 16; i++) M[i] = dv.getUint32(off + i * 4, true);
            let A = a0, B = b0, C = c0, D = d0;
            for (let i = 0; i < 64; i++) {
                let F, g;
                if (i < 16) { F = (B & C) | (~B & D); g = i; }
                else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
                else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
                else { F = C ^ (B | ~D); g = (7 * i) % 16; }
                F = (F + A + K[i] + M[g]) >>> 0;
                A = D; D = C; C = B;
                B = (B + rl(F, s[i])) >>> 0;
            }
            a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
        }
        const toHex = (n) => { let h = ''; for (let i = 0; i < 4; i++) h += ((n >>> (i * 8)) & 0xff).toString(16).padStart(2, '0'); return h; };
        return toHex(a0) + toHex(b0) + toHex(c0) + toHex(d0);
    }

    function certCopyBtn(val) {
        return `<button class="btn btn-ghost btn-xs btn-square decode-copy cert-inline-copy" data-copy="${escapeHtml(val)}" title="Copy value"><span class="material-symbols-outlined" aria-hidden="true">content_copy</span></button>`;
    }

    // Builds an `openssl x509 -text`-style dump of a parsed certificate.
    // Returns { text, html }: `text` is the plain dump (for "Copy all"); `html`
    // is the same layout with an inline copy button on every hex value.
    function buildCertDump(cert, md5, sha1, sha256) {
        const I = '    ';
        const esc = escapeHtml;
        const T = []; // plain-text lines
        const H = []; // html fragments (joined with \n; container is white-space: pre)

        function emitText(line) { T.push(line); H.push(esc(line)); }
        // Label line (with trailing copy button) followed by indented wrapped hex.
        // Copy value is plain uppercase hex (no separators, no line breaks).
        function emitHex(labelLine, indent, u8) {
            const wrapped = wrapHexColon(u8, indent);
            T.push(labelLine);
            T.push(wrapped);
            H.push(esc(labelLine) + ' ' + certCopyBtn(plainHexUpper(u8)));
            H.push(esc(wrapped));
        }
        // Single line "prefix<hex>" with a trailing copy button (fingerprints).
        // `rawHex` is the plain (colon-free) hex string.
        function emitInlineHex(prefix, rawHex) {
            const display = hexColonStr(rawHex);
            T.push(prefix + display);
            H.push(esc(prefix) + esc(display) + ' ' + certCopyBtn(rawHex.toUpperCase()));
        }

        emitText('Certificate');
        emitText(I + `Version: ${cert.version + 1} (0x${cert.version.toString(16)})`);
        emitHex(I + 'Serial Number:', I + I, u8FromHexBuf(cert.serialNumber.valueBlock.valueHex));
        emitText(I + 'Signature Algorithm: ' + sigAlgName(cert.signatureAlgorithm.algorithmId));
        emitText(I + 'Issuer: ' + dnString(cert.issuer.typesAndValues));
        emitText(I + 'Validity');
        emitText(I + I + 'Not Before: ' + isoOrRaw(cert.notBefore.value));
        emitText(I + I + 'Not After : ' + isoOrRaw(cert.notAfter.value));
        emitText(I + 'Subject: ' + dnString(cert.subject.typesAndValues));
        emitText(I + 'Subject Public Key Info:');
        const alg = cert.subjectPublicKeyInfo.algorithm.algorithmId || '';
        if (alg === '1.2.840.113549.1.1.1') {
            emitText(I + I + 'Public Key Algorithm: rsaEncryption');
            try {
                const spk = cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex;
                const spkAsn = asn1js.fromBER(spk);
                const rsaPub = new pkijs.RSAPublicKey({ schema: spkAsn.result });
                const mod = u8FromHexBuf(rsaPub.modulus.valueBlock.valueHex);
                const bits = (mod[0] === 0 ? mod.length - 1 : mod.length) * 8;
                emitText(I + I + I + `RSA Public-Key: (${bits} bit)`);
                emitHex(I + I + I + 'Modulus:', I + I + I + I, mod);
                const exp = u8FromHexBuf(rsaPub.publicExponent.valueBlock.valueHex);
                let e = 0n; for (const b of exp) e = (e << 8n) | BigInt(b);
                emitText(I + I + I + `Exponent: ${e.toString()} (0x${e.toString(16)})`);
            } catch (err) { /* ignore */ }
        } else if (alg === '1.2.840.10045.2.1') {
            emitText(I + I + 'Public Key Algorithm: id-ecPublicKey');
            let curveOid = null;
            try {
                const params = cert.subjectPublicKeyInfo.algorithm.algorithmParams;
                if (params && params.valueBlock && typeof params.valueBlock.toString === 'function') curveOid = params.valueBlock.toString();
            } catch (e) { /* ignore */ }
            if (curveOid) emitText(I + I + I + `Curve: ${EC_CURVE_NAMES[curveOid] || curveOid}`);
            emitHex(I + I + I + 'pub:', I + I + I + I, u8FromHexBuf(cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex));
        } else {
            emitText(I + I + 'Public Key Algorithm: ' + (oidToName(alg) || alg));
            emitHex(I + I + I + 'pub:', I + I + I + I, u8FromHexBuf(cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex));
        }
        if (Array.isArray(cert.extensions) && cert.extensions.length) {
            emitText(I + 'X509v3 extensions:');
            for (const ext of cert.extensions) {
                const oid = ext.extnID;
                const nm = EXT_NAMES[oid];
                const oidLabel = I + I + oid + (nm ? ` (${nm})` : '') + (ext.critical ? ' critical' : '') + ':';
                const B = I + I + I;
                try {
                    if (oid === '2.5.29.15') {
                        emitText(oidLabel);
                        emitText(B + (keyUsageNames(ext.parsedValue) || '(none)'));
                    } else if (oid === '2.5.29.19') {
                        emitText(oidLabel);
                        const bc = ext.parsedValue || {};
                        emitText(B + 'CA:' + (bc.cA ? 'TRUE' : 'FALSE') + (bc.pathLenConstraint != null ? ', pathlen:' + bc.pathLenConstraint : ''));
                    } else if (oid === '2.5.29.37' && ext.parsedValue && Array.isArray(ext.parsedValue.keyPurposes)) {
                        emitText(oidLabel);
                        emitText(B + ext.parsedValue.keyPurposes.map(o => `${oidToName(o) || o} (${o})`).join(', '));
                    } else if (oid === '2.5.29.14') {
                        const v = ext.parsedValue && ext.parsedValue.valueBlock ? ext.parsedValue.valueBlock.valueHex : ext.extnValue.valueBlock.valueHex;
                        emitHex(oidLabel, B, u8FromHexBuf(v));
                    } else if (oid === '2.5.29.35') {
                        const aki = ext.parsedValue;
                        const v = aki && aki.keyIdentifier ? aki.keyIdentifier.valueBlock.valueHex : ext.extnValue.valueBlock.valueHex;
                        emitHex(oidLabel, B, u8FromHexBuf(v));
                    } else {
                        emitHex(oidLabel, B, u8FromHexBuf(ext.extnValue.valueBlock.valueHex));
                    }
                } catch (err) {
                    try { emitHex(oidLabel, B, u8FromHexBuf(ext.extnValue.valueBlock.valueHex)); } catch (e2) { /* ignore */ }
                }
            }
        }
        emitText(I + 'Signature Algorithm: ' + sigAlgName(cert.signatureAlgorithm.algorithmId));
        emitHex(I + 'Signature Value:', I + I, u8FromHexBuf(cert.signatureValue.valueBlock.valueHex));
        emitText(I + 'Fingerprints:');
        emitInlineHex(I + I + 'MD5:    ', md5);
        emitInlineHex(I + I + 'SHA1:   ', sha1);
        emitInlineHex(I + I + 'SHA256: ', sha256);

        return { text: T.join('\n'), html: H.join('\n') };
    }

    async function parseCertificate(bytes) {
        const ab = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
        const asn1 = asn1js.fromBER(ab);
        if (asn1.offset === -1) throw new Error('ASN.1 parse error');
        const cert = new pkijs.Certificate({ schema: asn1.result });

        const derU8 = new Uint8Array(ab);
        const [sha256Buf, sha1Buf] = await Promise.all([
            crypto.subtle.digest('SHA-256', ab),
            crypto.subtle.digest('SHA-1', ab),
        ]);
        const dump = buildCertDump(cert, md5Hex(derU8), bufToHexLower(sha1Buf), bufToHexLower(sha256Buf));
        return { text: dump.text, html: dump.html };
    }

    async function renderCertificateSection(bytes) {
        let c;
        try { c = await parseCertificate(bytes); }
        catch (e) { return kvRow('Certificate', mono('Failed to parse: ' + e.message)); }
        if (c.html) {
            return '<div class="cert-dump-toolbar">'
                + `<button class="btn btn-ghost btn-xs btn-square decode-copy" data-copy="${escapeHtml(c.text)}" title="Copy all"><span class="material-symbols-outlined" aria-hidden="true">content_copy</span></button></div>`
                + `<div class="cert-dump">${c.html}</div>`;
        }
        return kvRow('Certificate', mono('Could not render certificate'));
    }

    async function renderCertificate(bytes) {
        const html = await renderCertificateSection(bytes);
        return { html };
    }

    function renderRawCbor(decoded, bytes) {
        let html = '<div class="decode-heading">CBOR</div>';
        html += `<div class="decode-value"><div class="decode-value-content">${preBlock(CBOR.formatDiagnostic(decoded))}</div></div>`;
        return { html };
    }

    // ------------------------------------------------------------- controller
    async function runDecode() {
        const input = document.getElementById('decodeInput');
        const errEl = document.getElementById('decodeError');
        const card = document.getElementById('decodeResultCard');
        const result = document.getElementById('decodeResult');
        errEl.style.display = 'none';

        // A PublicKeyCredential JSON (toJSON output) is handled before byte parsing.
        const rawInput = (input.value || '').trim();
        if (rawInput.charAt(0) === '{') {
            let obj = null;
            try { obj = JSON.parse(rawInput); } catch (e) { obj = null; }
            if (obj && isPublicKeyCredentialJSON(obj)) {
                try {
                    const rendered = await renderPublicKeyCredentialJSON(obj);
                    result.innerHTML = rendered.html;
                    card.style.display = 'block';
                    formatHexBlocks(result);
                } catch (e) {
                    errEl.textContent = 'Failed to render: ' + e.message; errEl.style.display = 'inline';
                    card.style.display = 'none';
                }
                return;
            }
            if (obj && isWebAuthnRequestOptions(obj)) {
                try {
                    const rendered = await renderWebAuthnRequestOptions(obj);
                    result.innerHTML = rendered.html;
                    card.style.display = 'block';
                    formatHexBlocks(result);
                } catch (e) {
                    errEl.textContent = 'Failed to render: ' + e.message; errEl.style.display = 'inline';
                    card.style.display = 'none';
                }
                return;
            }
        }

        let bytes;
        try {
            bytes = parseInput(input.value);
        } catch (e) {
            errEl.textContent = e.message; errEl.style.display = 'inline';
            card.style.display = 'none';
            return;
        }

        let detected;
        try {
            detected = detect(bytes);
        } catch (e) {
            errEl.textContent = e.message; errEl.style.display = 'inline';
            card.style.display = 'none';
            return;
        }

        try {
            let rendered;
            if (detected.type === 'attestationObject') rendered = await renderAttestationObject(detected.decoded, bytes);
            else if (detected.type === 'authenticatorData') rendered = await renderAuthenticatorDataOnly(bytes);
            else if (detected.type === 'certificate') rendered = await renderCertificate(bytes);
            else rendered = renderRawCbor(detected.decoded, bytes);

            result.innerHTML = rendered.html;
            card.style.display = 'block';
            formatHexBlocks(result);
        } catch (e) {
            errEl.textContent = 'Failed to render: ' + e.message; errEl.style.display = 'inline';
            card.style.display = 'none';
        }
    }

    // ------------------------------------------------------------------ wiring
    document.addEventListener('DOMContentLoaded', () => {
        const input = document.getElementById('decodeInput');
        const cborEncodeBtn = document.getElementById('cborEncodeBtn');
        const decodeBtn = document.getElementById('decodeBtn');
        const clearBtn = document.getElementById('clearBtn');
        const copyBtn = document.getElementById('copyInputBtn');
        const pasteBtn = document.getElementById('pasteInputBtn');
        const saveBtn = document.getElementById('saveInputBtn');
        const savePdfBtn = document.getElementById('savePdfBtn');

        // Returns the trimmed input if it parses as JSON, else null.
        function inputAsJsonText() {
            const trimmed = (input.value || '').trim();
            if (!trimmed || (trimmed.charAt(0) !== '{' && trimmed.charAt(0) !== '[')) return null;
            try { JSON.parse(trimmed); return trimmed; } catch (e) { return null; }
        }

        // Toggle button visibility based on whether the input has content. Decode /
        // Clear / Copy (and CBOR Encode) only make sense with content; Paste only
        // when empty.
        // Clipboard-read permission: when denied, disable the Paste button.
        let pasteDenied = false;
        function applyPasteDenied() {
            if (!pasteBtn) return;
            pasteBtn.disabled = pasteDenied;
            pasteBtn.classList.toggle('btn-disabled', pasteDenied);
            pasteBtn.title = pasteDenied ? 'Clipboard read is blocked for this site — paste manually (Ctrl+V)' : '';
        }
        (function watchClipboardPermission() {
            try {
                if (navigator.permissions && navigator.permissions.query) {
                    navigator.permissions.query({ name: 'clipboard-read' }).then((status) => {
                        pasteDenied = (status.state === 'denied');
                        applyPasteDenied();
                        status.onchange = () => { pasteDenied = (status.state === 'denied'); applyPasteDenied(); };
                    }).catch(() => { /* permission name unsupported; leave enabled */ });
                }
            } catch (e) { /* ignore */ }
        })();

        function updateButtons() {
            const hasContent = !!(input.value || '').trim();
            if (decodeBtn) decodeBtn.style.display = hasContent ? '' : 'none';
            if (clearBtn) clearBtn.style.display = hasContent ? '' : 'none';
            if (copyBtn) copyBtn.style.display = hasContent ? '' : 'none';
            if (saveBtn) saveBtn.style.display = hasContent ? '' : 'none';
            if (savePdfBtn) savePdfBtn.style.display = hasContent ? '' : 'none';
            if (pasteBtn) { pasteBtn.style.display = hasContent ? 'none' : ''; applyPasteDenied(); }
            if (cborEncodeBtn) cborEncodeBtn.style.display = (hasContent && inputAsJsonText()) ? '' : 'none';
        }

        // Grow/shrink the input textarea to fit its content (bounded).
        function autoResize() {
            input.style.height = 'auto';
            const max = Math.max(200, Math.floor(window.innerHeight * 0.6));
            input.style.height = Math.min(input.scrollHeight + 2, max) + 'px';
        }

        // Set the textarea content: pretty-print JSON when possible, then resize.
        function setInputContent(val) {
            let text = String(val == null ? '' : val);
            const trimmed = text.trim();
            if (trimmed && (trimmed.charAt(0) === '{' || trimmed.charAt(0) === '[')) {
                try { text = JSON.stringify(JSON.parse(trimmed), null, 2); } catch (e) { /* keep as-is */ }
            }
            input.value = text;
            autoResize();
            updateButtons();
        }

        input.addEventListener('input', () => { autoResize(); updateButtons(); });
        window.addEventListener('resize', autoResize);
        autoResize();
        updateButtons();

        decodeBtn.addEventListener('click', runDecode);
        clearBtn.addEventListener('click', () => {
            input.value = '';
            autoResize();
            updateButtons();
            document.getElementById('decodeResultCard').style.display = 'none';
            document.getElementById('decodeError').style.display = 'none';
        });
        input.addEventListener('paste', () => setTimeout(() => { autoResize(); updateButtons(); runDecode(); }, 0));
        copyBtn.addEventListener('click', () => {
            const val = input.value || '';
            if (!val) { toast('Nothing to copy'); return; }
            navigator.clipboard.writeText(val).then(() => toast('Copied to clipboard')).catch(() => toast('Copy failed'));
        });
        if (pasteBtn) {
            pasteBtn.addEventListener('click', async () => {
                try {
                    if (!navigator.clipboard || !navigator.clipboard.readText) {
                        toast('Clipboard read not supported; paste manually (Ctrl+V)');
                        input.focus();
                        return;
                    }
                    const text = await navigator.clipboard.readText();
                    if (!text) { toast('Clipboard is empty'); return; }
                    setInputContent(text);
                    runDecode();
                } catch (e) {
                    // If the read was blocked, reflect that by disabling the button.
                    if (e && (e.name === 'NotAllowedError' || e.name === 'SecurityError')) {
                        pasteDenied = true;
                        applyPasteDenied();
                    }
                    toast('Paste failed; paste manually (Ctrl+V)');
                    input.focus();
                }
            });
        }

        // Open the CBOR Playground to encode the current JSON input into CBOR.
        if (cborEncodeBtn) {
            cborEncodeBtn.addEventListener('click', () => {
                const jsonText = inputAsJsonText();
                if (!jsonText) { toast('Input is not valid JSON'); return; }
                try {
                    const key = 'cbor_encode_payload_' + Math.random().toString(36).slice(2, 10);
                    sessionStorage.setItem(key, jsonText);
                    window.open('./cbor.html?mode=encode&key=' + encodeURIComponent(key), '_blank');
                } catch (e) {
                    try { window.open('./cbor.html?mode=encode&input=' + encodeURIComponent(jsonText), '_blank'); }
                    catch (e2) { toast('Failed to open CBOR encoder'); }
                }
            });
        }

        // ---- Save: write the input to a file in a format matching its content ----
        async function sha256Hex(bytesOrText) {
            const data = (bytesOrText instanceof Uint8Array) ? bytesOrText : new TextEncoder().encode(String(bytesOrText));
            const buf = await crypto.subtle.digest('SHA-256', data);
            return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
        }
        function triggerDownload(blob, filename) {
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url; a.download = filename;
            document.body.appendChild(a); a.click();
            setTimeout(() => { try { URL.revokeObjectURL(url); a.remove(); } catch (e) { /* ignore */ } }, 1000);
        }

        async function saveInput() {
            const raw = input.value || '';
            const trimmed = raw.trim();
            if (!trimmed) { toast('Nothing to save'); return; }
            try {
                // 1. JSON → pretty-printed .json
                const jsonText = inputAsJsonText();
                if (jsonText) {
                    const pretty = JSON.stringify(JSON.parse(jsonText), null, 2);
                    const hash = (await sha256Hex(pretty)).slice(0, 12);
                    triggerDownload(new Blob([pretty], { type: 'application/json' }), 'WebAuthn_' + hash + '.json');
                    return;
                }
                // 2. PEM certificate → .pem (named by fingerprint)
                const pemMatch = trimmed.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
                if (pemMatch) {
                    try {
                        const der = CBOR.base64ToBytes(pemMatch[0].replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''));
                        const fp = (await sha256Hex(der)).slice(0, 16).toUpperCase();
                        triggerDownload(new Blob([trimmed + '\n'], { type: 'application/x-pem-file' }), 'Certificate_' + fp + '.pem');
                        return;
                    } catch (e) { /* fall through to text */ }
                }
                // 3. Parse to bytes and classify.
                let bytes = null;
                try { bytes = parseInput(raw); } catch (e) { bytes = null; }
                if (!bytes) {
                    const hash = (await sha256Hex(raw)).slice(0, 12);
                    triggerDownload(new Blob([raw], { type: 'text/plain' }), 'Decoded_' + hash + '.txt');
                    return;
                }
                let det = null;
                try { det = detect(bytes); } catch (e) { det = null; }
                const type = det ? det.type : 'bytes';
                if (type === 'certificate') {
                    const fp = (await sha256Hex(bytes)).slice(0, 16).toUpperCase();
                    triggerDownload(new Blob([bytes], { type: 'application/octet-stream' }), 'Certificate_' + fp + '.der');
                } else if (type === 'attestationObject' || type === 'cbor') {
                    const hash = (await sha256Hex(bytes)).slice(0, 12);
                    triggerDownload(new Blob([bytes], { type: 'application/cbor' }), 'CBOR_' + hash + '.cbor');
                } else {
                    const hash = (await sha256Hex(bytes)).slice(0, 12);
                    triggerDownload(new Blob([bytes], { type: 'application/octet-stream' }), 'Bytes_' + hash + '.bin');
                }
            } catch (e) {
                toast('Save failed: ' + (e && e.message ? e.message : e));
            }
        }
        if (saveBtn) saveBtn.addEventListener('click', saveInput);

        // ---- Save as PDF (pdfmake, loaded on demand) ----
        const PDF_CONTENT_WIDTH = 523; // A4 width (595.28) minus 36pt margins each side
        function loadScript(src) {
            return new Promise((resolve, reject) => {
                const s = document.createElement('script');
                s.src = src; s.onload = resolve; s.onerror = () => reject(new Error('Failed to load ' + src));
                document.head.appendChild(s);
            });
        }
        async function ensurePdfMake() {
            if (!(window.pdfMake && window.pdfMake.createPdf)) {
                await loadScript('https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.2.7/pdfmake.min.js');
                await loadScript('https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.2.7/vfs_fonts.js');
            }
            return ensureMonoFont();
        }
        // ArrayBuffer -> base64 (chunked to avoid call-stack limits).
        function abToBase64(buf) {
            const bytes = new Uint8Array(buf);
            let binary = '';
            const chunk = 0x8000;
            for (let i = 0; i < bytes.length; i += chunk) {
                binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
            }
            return btoa(binary);
        }
        // Loads the self-hosted Roboto Mono TTFs into pdfmake's VFS and registers a
        // 'RobotoMono' font family. Returns the font name to use for monospace text,
        // or 'Roboto' (proportional) if the fonts couldn't be loaded.
        let monoFontReady = null;
        async function ensureMonoFont() {
            if (monoFontReady) return monoFontReady;
            try {
                window.pdfMake.vfs = window.pdfMake.vfs || {};
                window.pdfMake.fonts = window.pdfMake.fonts || {};
                // Ensure the default Roboto family stays registered.
                window.pdfMake.fonts.Roboto = window.pdfMake.fonts.Roboto || {
                    normal: 'Roboto-Regular.ttf', bold: 'Roboto-Medium.ttf',
                    italics: 'Roboto-Italic.ttf', bolditalics: 'Roboto-MediumItalic.ttf'
                };
                if (!window.pdfMake.vfs['RobotoMono-Regular.ttf']) {
                    const [reg, bold] = await Promise.all([
                        fetch('./fonts/RobotoMono-Regular.ttf').then(r => { if (!r.ok) throw new Error('font ' + r.status); return r.arrayBuffer(); }),
                        fetch('./fonts/RobotoMono-Bold.ttf').then(r => { if (!r.ok) throw new Error('font ' + r.status); return r.arrayBuffer(); })
                    ]);
                    window.pdfMake.vfs['RobotoMono-Regular.ttf'] = abToBase64(reg);
                    window.pdfMake.vfs['RobotoMono-Bold.ttf'] = abToBase64(bold);
                }
                window.pdfMake.fonts.RobotoMono = {
                    normal: 'RobotoMono-Regular.ttf',
                    bold: 'RobotoMono-Bold.ttf',
                    italics: 'RobotoMono-Regular.ttf',
                    bolditalics: 'RobotoMono-Bold.ttf'
                };
                monoFontReady = 'RobotoMono';
            } catch (e) {
                monoFontReady = 'Roboto'; // graceful fallback (proportional)
            }
            return monoFontReady;
        }
        // Wrap long lines for pdfmake. Breaks at word boundaries (spaces) when
        // possible so URLs/words aren't split mid-token; falls back to a hard
        // character break only for single tokens longer than the available width.
        // Leading indentation is preserved on continuation lines.
        function hardWrap(text, width) {
            width = width || 95;
            const wrapLine = (line) => {
                if (line.length <= width) return line;
                const indent = (line.match(/^[ \t]*/) || [''])[0];
                const avail = Math.max(8, width - indent.length);
                const words = line.slice(indent.length).split(' ');
                const lines = [];
                let cur = '';
                const flush = () => { lines.push(indent + cur); cur = ''; };
                for (let word of words) {
                    while (word.length > avail) {
                        if (cur.length > 0) flush();
                        cur = word.slice(0, avail);
                        word = word.slice(avail);
                        flush();
                    }
                    if (cur.length === 0) cur = word;
                    else if (cur.length + 1 + word.length <= avail) cur += ' ' + word;
                    else { flush(); cur = word; }
                }
                if (cur.length > 0 || lines.length === 0) flush();
                return lines.join('\n');
            };
            return String(text == null ? '' : text).split('\n').map(wrapLine).join('\n');
        }
        // textContent with icon glyphs / copy buttons / action controls removed.
        function cleanText(node) {
            if (!node) return '';
            const clone = node.cloneNode(true);
            clone.querySelectorAll('.material-symbols-outlined, button, .decode-copy, .decode-actions, .decode-hexcopy, .cert-inline-copy, .cert-dump-toolbar').forEach(el => el.remove());
            return clone.textContent.replace(/\u00a0/g, ' ');
        }
        // Reformat plain hex to uppercase space-separated (no colons), `perLine`
        // bytes per line. Used for value-cell hex in the exported PDF.
        function formatHexSpaced(hex, perLine) {
            const pairs = (String(hex || '').match(/.{1,2}/g) || []);
            const lines = [];
            for (let i = 0; i < pairs.length; i += perLine) lines.push(pairs.slice(i, i + perLine).join(' ').toUpperCase());
            return lines.join('\n');
        }
        // Reformat the colon-separated hex runs inside an OpenSSL-style certificate
        // dump into space-separated, `perLine` bytes-per-row hex (preserving each
        // block's indentation). Non-hex lines (labels, fingerprints) are untouched.
        function reformatCertDumpHex(text, perLine) {
            perLine = perLine || 32;
            const lines = String(text || '').split('\n');
            const hexLineRe = /^(\s+)((?:[0-9A-Fa-f]{2}:)*[0-9A-Fa-f]{2}:?)\s*$/;
            // Inline labeled hex on one line, e.g. "        SHA256: AA:BB:CC".
            const inlineHexRe = /^(.*?:[ \t]*)((?:[0-9A-Fa-f]{2}:)+[0-9A-Fa-f]{2})[ \t]*$/;
            const out = [];
            let i = 0;
            while (i < lines.length) {
                const m = lines[i].match(hexLineRe);
                if (m) {
                    const indent = m[1];
                    const bytes = [];
                    while (i < lines.length) {
                        const mm = lines[i].match(hexLineRe);
                        if (!mm || mm[1] !== indent) break;
                        mm[2].replace(/:$/, '').split(':').forEach(b => bytes.push(b.toUpperCase()));
                        i++;
                    }
                    for (let j = 0; j < bytes.length; j += perLine) {
                        out.push(indent + bytes.slice(j, j + perLine).join(' '));
                    }
                    continue;
                }
                const inl = lines[i].match(inlineHexRe);
                if (inl) {
                    const spaced = inl[2].split(':').map(b => b.toUpperCase()).join(' ');
                    out.push(inl[1] + spaced);
                    i++;
                    continue;
                }
                out.push(lines[i]);
                i++;
            }
            return out.join('\n');
        }
        // Reformat long continuous hex runs (e.g. COSE key values in pretty JSON)
        // into aligned, fixed 32-bytes-per-row space-separated hex. The JSON key
        // and opening quote stay on their own line; the bytes then start fresh on
        // the next line (indented to the JSON nesting) so a full 32 bytes fit per
        // row and every row aligns. Avoids both the enlarged line spacing of an
        // over-wide unbreakable token and pdfmake's ragged re-wrapping.
        function wrapLongHexInJson(text, perRow) {
            perRow = perRow || 32;
            return String(text == null ? '' : text).split('\n').map(line => {
                const m = line.match(/[0-9A-Fa-f]{64,}/);
                if (!m) return line;
                const before = line.slice(0, m.index);          // e.g. '  "-1": "'
                const after = line.slice(m.index + m[0].length); // e.g. '",'
                const bytes = m[0].toUpperCase().match(/.{1,2}/g) || [];
                const indent = (line.match(/^\s*/) || [''])[0] + '  ';
                const rows = [];
                for (let i = 0; i < bytes.length; i += perRow) rows.push(indent + bytes.slice(i, i + perRow).join(' '));
                if (rows.length) rows[rows.length - 1] += after;
                return before + '\n' + rows.join('\n');
            }).join('\n');
        }
        // Extract a value cell's text for the PDF. Hex blocks are re-wrapped to
        // 32 bytes/line (from their raw data-hex) so they align and fill the column;
        // other content is taken as cleaned text.
        function valueToPdfText(valContent) {
            if (!valContent) return '';
            const parts = [];
            Array.from(valContent.childNodes).forEach(ch => {
                if (ch.nodeType === 3) { const t = ch.textContent.replace(/\u00a0/g, ' ').trim(); if (t) parts.push(t); return; }
                if (ch.nodeType !== 1) return;
                let hexPre = null;
                if (ch.classList && ch.classList.contains('decode-hexblock')) hexPre = ch.querySelector('.decode-hex[data-hex]');
                else if (ch.matches && ch.matches('.decode-hex[data-hex]')) hexPre = ch;
                if (hexPre) {
                    parts.push(formatHexSpaced(hexPre.getAttribute('data-hex') || '', 32));
                } else {
                    const t = wrapLongHexInJson(cleanText(ch));
                    if (t.replace(/\s+$/, '')) parts.push(t.replace(/\s+$/, ''));
                }
            });
            return parts.join('\n');
        }
        // A subtle key/value table layout: light horizontal separators only.
        const kvLayout = {
            hLineWidth: (i, node) => (i === 0 || i === node.table.body.length) ? 0 : 0.5,
            vLineWidth: () => 0,
            hLineColor: () => '#e8e8e8',
            paddingLeft: () => 0,
            paddingRight: () => 6,
            paddingTop: () => 3,
            paddingBottom: () => 3
        };
        function kvTable(rows) {
            return {
                table: { widths: [88, '*'], body: rows },
                layout: kvLayout,
                margin: [0, 2, 0, 6]
            };
        }
        function sectionDivider(color) {
            return { canvas: [{ type: 'line', x1: 0, y1: 0, x2: PDF_CONTENT_WIDTH, y2: 0, lineWidth: 0.7, lineColor: color || '#dddddd' }], margin: [0, 2, 0, 6] };
        }

        // Build pdfmake content from the rendered decode output. Consecutive
        // key/value rows are grouped into a single table for a clean look.
        function pdfFromResult() {
            const out = [];
            const result = document.getElementById('decodeResult');
            if (!result) return out;
            let kvBuffer = [];
            const flush = () => { if (kvBuffer.length) { out.push(kvTable(kvBuffer)); kvBuffer = []; } };

            Array.from(result.children).forEach(node => {
                const cls = node.classList;
                if (cls.contains('decode-row')) {
                    const label = node.querySelector('.decode-label');
                    const valContent = node.querySelector('.decode-value-content') || node.querySelector('.decode-value');
                    kvBuffer.push([
                        { text: label ? label.textContent.trim() : '', style: 'label' },
                        { text: hardWrap(valueToPdfText(valContent), 100), style: 'mono', preserveLeadingSpaces: true }
                    ]);
                    return;
                }
                flush();
                if (cls.contains('decode-heading')) {
                    out.push({ text: cleanText(node).trim(), style: 'h2', margin: [0, 10, 0, 2] });
                    out.push(sectionDivider('#c9c9c9'));
                } else if (cls.contains('decode-subheading')) {
                    out.push({ text: cleanText(node).trim(), style: 'h3', margin: [0, 8, 0, 3] });
                } else if (cls.contains('decode-cert-index')) {
                    out.push({ text: cleanText(node).trim(), bold: true, margin: [0, 4, 0, 2] });
                } else if (cls.contains('cert-dump')) {
                    out.push({ text: hardWrap(reformatCertDumpHex(cleanText(node).replace(/\s+$/, ''), 32), 114), style: 'monoBlock', preserveLeadingSpaces: true, margin: [0, 0, 0, 6] });
                } else if (cls.contains('decode-value')) {
                    out.push({ text: hardWrap(cleanText(node), 114), style: 'monoBlock', preserveLeadingSpaces: true });
                } else {
                    const t = cleanText(node).trim();
                    if (t) out.push({ text: t });
                }
            });
            flush();
            return out;
        }

        // Derive a context-specific document title from the decoded result + input.
        function derivePdfTitle() {
            const result = document.getElementById('decodeResult');
            const headingEl = result ? result.querySelector('.decode-heading') : null;
            const heading = headingEl ? headingEl.textContent.trim() : '';
            if (heading === 'PublicKeyCredential') {
                const jsonText = inputAsJsonText();
                if (jsonText) {
                    try {
                        const resp = (JSON.parse(jsonText) || {}).response || {};
                        if (typeof resp.attestationObject === 'string') return 'WebAuthn Registration Response';
                        if (typeof resp.authenticatorData === 'string') return 'WebAuthn Authentication Response';
                    } catch (e) { /* ignore */ }
                }
                return 'WebAuthn PublicKeyCredential';
            }
            if (heading === 'Attestation Object') return 'WebAuthn Attestation Object';
            if (heading === 'Authenticator Data') return 'WebAuthn Authenticator Data';
            if (heading === 'X.509 certificate' || heading === 'Certificate') return 'X.509 Certificate';
            if (heading === 'CBOR') return 'CBOR Structure';
            return heading || 'WebAuthn Decoder Output';
        }

        // Derive a PDF filename. Uses the credential ID when known:
        //   WebAuthn_<CredId16>_Registration.pdf
        //   WebAuthn_<CredId16>_Authentication_<Sig8>.pdf
        //   WebAuthn_<CredId16>_AttestationObject.pdf
        //   WebAuthn_<CredId16>_AuthenticatorData.pdf
        // Fallbacks: Certificate_<Fingerprint16>.pdf, WebAuthn_AuthenticatorData_<hash12>.pdf,
        // WebAuthnDecode_<hash12>.pdf.
        async function derivePdfFilename(raw) {
            const first16 = (u8) => Array.from(u8).slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
            // 1. PublicKeyCredential JSON.
            const jsonText = inputAsJsonText();
            if (jsonText) {
                try {
                    const cred = JSON.parse(jsonText);
                    if (isPublicKeyCredentialJSON(cred)) {
                        const resp = cred.response || {};
                        let credId16 = '';
                        if (cred.id) { try { credId16 = first16(CBOR.base64ToBytes(cred.id)); } catch (e) { /* ignore */ } }
                        if (typeof resp.attestationObject === 'string' && credId16) {
                            return 'WebAuthn_' + credId16 + '_Registration.pdf';
                        }
                        if (typeof resp.authenticatorData === 'string' && credId16) {
                            let sig8 = '';
                            if (typeof resp.signature === 'string') {
                                try { sig8 = (await sha256Hex(CBOR.base64ToBytes(resp.signature))).slice(0, 8).toUpperCase(); } catch (e) { /* ignore */ }
                            }
                            return 'WebAuthn_' + credId16 + '_Authentication' + (sig8 ? '_' + sig8 : '') + '.pdf';
                        }
                    }
                } catch (e) { /* ignore */ }
            }
            // 2. Byte-based inputs.
            let bytes = null;
            try { bytes = parseInput(raw); } catch (e) { bytes = null; }
            if (bytes) {
                let det = null;
                try { det = detect(bytes); } catch (e) { det = null; }
                const type = det ? det.type : null;
                if (type === 'certificate') {
                    const fp = (await sha256Hex(bytes)).slice(0, 16).toUpperCase();
                    return 'Certificate_' + fp + '.pdf';
                }
                if (type === 'attestationObject' && det.decoded) {
                    try {
                        const authData = det.decoded.authData instanceof Uint8Array ? det.decoded.authData : new Uint8Array(det.decoded.authData);
                        const ad = parseAuthenticatorData(authData);
                        if (ad.attested && ad.attested.credentialId) return 'WebAuthn_' + first16(ad.attested.credentialId) + '_AttestationObject.pdf';
                    } catch (e) { /* ignore */ }
                }
                if (type === 'authenticatorData') {
                    try {
                        const ad = parseAuthenticatorData(bytes);
                        if (ad.attested && ad.attested.credentialId) return 'WebAuthn_' + first16(ad.attested.credentialId) + '_AuthenticatorData.pdf';
                    } catch (e) { /* ignore */ }
                    return 'WebAuthn_AuthenticatorData_' + (await sha256Hex(bytes)).slice(0, 12) + '.pdf';
                }
            }
            // 3. Generic fallback.
            return 'WebAuthnDecode_' + (await sha256Hex(raw)).slice(0, 12) + '.pdf';
        }

        async function saveAsPdf() {
            const raw = input.value || '';
            if (!raw.trim()) { toast('Nothing to save'); return; }
            try {
                await runDecode();
                const monoFont = await ensurePdfMake();
                const title = derivePdfTitle();
                const body = pdfFromResult();
                const pageUrl = window.location.origin + window.location.pathname;
                const docDefinition = {
                    info: { title: title },
                    pageSize: 'A4',
                    pageMargins: [36, 44, 36, 40],
                    footer: (currentPage, pageCount) => ({
                        columns: [
                            { text: pageUrl, fontSize: 7, color: '#aaaaaa', margin: [36, 0, 0, 0] },
                            { text: currentPage + ' / ' + pageCount, alignment: 'right', fontSize: 7, color: '#aaaaaa', margin: [0, 0, 36, 0] }
                        ],
                        margin: [0, 8, 0, 0]
                    }),
                    content: [
                        { text: title, style: 'title' },
                        { text: 'Generated ' + new Date().toLocaleString(), style: 'meta' },
                        { canvas: [{ type: 'line', x1: 0, y1: 0, x2: PDF_CONTENT_WIDTH, y2: 0, lineWidth: 1.4, lineColor: '#4f46e5' }], margin: [0, 6, 0, 12] },
                        { text: 'Input', style: 'h2', margin: [0, 0, 0, 2] },
                        sectionDivider('#c9c9c9'),
                        { text: hardWrap(raw, 114), style: 'monoBlock', preserveLeadingSpaces: true, margin: [0, 0, 0, 14] },
                        { text: 'Decoded Output', style: 'h2', margin: [0, 0, 0, 2] },
                        sectionDivider('#c9c9c9')
                    ].concat(body),
                    styles: {
                        title: { fontSize: 17, bold: true, color: '#1f2937' },
                        meta: { fontSize: 8, color: '#9ca3af' },
                        h2: { fontSize: 12.5, bold: true, color: '#4f46e5' },
                        h3: { fontSize: 10, bold: true, color: '#374151' },
                        label: { fontSize: 8, bold: true, color: '#374151' },
                        mono: { fontSize: 7, font: monoFont, color: '#1f2937' },
                        monoBlock: { fontSize: 7.5, font: monoFont, color: '#374151' }
                    },
                    defaultStyle: { font: 'Roboto', fontSize: 9, lineHeight: 1.15 }
                };
                const filename = await derivePdfFilename(raw);
                window.pdfMake.createPdf(docDefinition).download(filename);
            } catch (e) {
                toast('PDF export failed: ' + (e && e.message ? e.message : e));
            }
        }
        if (savePdfBtn) savePdfBtn.addEventListener('click', saveAsPdf);

        // Import a file: text-like files (JSON / PEM / hex / base64) are used as-is;
        // binary files (CBOR / DER / raw bytes) are converted to hex. Then decoded.
        const importFileInput = document.getElementById('importDecodeFile');
        importFileInput.addEventListener('change', (e) => {
            const file = e.target.files && e.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = () => {
                try {
                    const bytes = new Uint8Array(reader.result);
                    let controlCount = 0;
                    for (let i = 0; i < bytes.length; i++) {
                        const b = bytes[i];
                        if (b === 0) { controlCount = bytes.length; break; } // NUL → binary
                        if (b < 0x09 || (b > 0x0d && b < 0x20)) controlCount++;
                    }
                    const isBinary = bytes.length > 0 && (controlCount / bytes.length) > 0.01;
                    if (isBinary) {
                        setInputContent(bytesToHex(bytes).toUpperCase());
                    } else {
                        setInputContent(new TextDecoder('utf-8', { fatal: false }).decode(bytes).trim());
                    }
                    runDecode();
                } catch (err) {
                    document.getElementById('decodeError').textContent = 'Import failed: ' + err.message;
                    document.getElementById('decodeError').style.display = 'inline';
                }
            };
            reader.onerror = () => {
                document.getElementById('decodeError').textContent = 'File read failed.';
                document.getElementById('decodeError').style.display = 'inline';
            };
            reader.readAsArrayBuffer(file);
            importFileInput.value = '';
        });

        // Accept a payload from an opener window (e.g. the certificate dialog) or
        // via ?key= / ?input= and auto-decode it. Mirrors the CBOR playground flow.
        (function receiveIncoming() {
            try {
                const params = new URLSearchParams(window.location.search);
                const decodeWith = (val) => {
                    if (typeof val !== 'string') return;
                    setInputContent(val);
                    setTimeout(runDecode, 50);
                };
                const pm = params.get('pm');
                const nonceParam = params.get('nonce');
                if (pm && window.opener) {
                    try { window.opener.postMessage({ type: 'decode-ready', nonce: nonceParam || null }, window.location.origin); } catch (e) { /* ignore */ }
                    const onMsg = (ev) => {
                        try {
                            if (ev.origin !== window.location.origin) return;
                            if (ev.source !== window.opener) return;
                            const d = ev.data || {};
                            if (d && d.type === 'decode-payload' && typeof d.payload === 'string') {
                                if (nonceParam && d.nonce !== nonceParam) return;
                                decodeWith(d.payload);
                                window.removeEventListener('message', onMsg);
                            }
                        } catch (e) { /* ignore */ }
                    };
                    window.addEventListener('message', onMsg);
                }
                const key = params.get('key');
                if (key) {
                    try {
                        const stored = sessionStorage.getItem(key);
                        if (stored) { try { sessionStorage.removeItem(key); } catch (e) { /* ignore */ } decodeWith(stored); return; }
                    } catch (e) { /* ignore */ }
                }
                const inp = params.get('input');
                if (inp) { try { decodeWith(decodeURIComponent(inp)); } catch (e) { decodeWith(inp); } }
            } catch (e) { /* ignore */ }
        })();

        // Delegated copy-to-clipboard.
        document.addEventListener('click', (e) => {
            const btn = e.target.closest ? e.target.closest('.decode-copy') : null;
            if (!btn) return;
            const val = btn.getAttribute('data-copy') || '';
            if (!val) return;
            navigator.clipboard.writeText(val).then(() => toast('Copied to clipboard')).catch(() => toast('Copy failed'));
        });
    });
})();
