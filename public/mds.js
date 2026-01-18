// Client-side AAGUID lookup: fetches the public dataset from GitHub and
// provides an interactive Name/AAGUID search. No local caching.

// Certificates dialog uses PKIjs (loaded via CDN) to parse X.509 certificates.
import * as asn1js from 'https://cdn.skypack.dev/asn1js@3.0.6';
import * as pvutils from 'https://cdn.skypack.dev/pvutils@1.1.3';
import * as pvtsutils from 'https://cdn.skypack.dev/pvtsutils@1.3.6';
import * as pkijs from 'https://cdn.skypack.dev/pkijs@3.3.0';

// Expose libs on window for compatibility (mirrors index.js pattern).
try {
    window.asn1js = asn1js;
    window.pvutils = pvutils;
    window.pvtsutils = pvtsutils;
    window.pkijs = pkijs;
} catch { /* ignore */ }

// Initialize PKIjs engine to use browser WebCrypto.
try {
    if (pkijs && typeof pkijs.setEngine === 'function' && typeof pkijs.CryptoEngine === 'function') {
        const engine = new pkijs.CryptoEngine({ name: 'webcrypto', crypto: window.crypto });
        pkijs.setEngine('webcrypto', engine);
    }
} catch (e) {
    console.warn('PKIjs engine init failed:', e);
}

const AAGUIDS_URL = 'https://raw.githubusercontent.com/akshayku/passkey-aaguids/main/aaguids.json';
const RAW_BASE = 'https://raw.githubusercontent.com/akshayku/passkey-aaguids/main';

const els = {
    aaguidInput: document.getElementById('aaguidInput'),
    clearBtn: document.getElementById('clearBtn'),
    suggestions: document.getElementById('suggestions'),
    selectedLabelCard: document.getElementById('selectedLabelCard'),
    detailsCard: document.getElementById('detailsCard'),
    selectedLabel: document.getElementById('selectedLabel'),
    selectedIconLight: document.getElementById('selectedIconLight'),
    selectedIconDark: document.getElementById('selectedIconDark'),
    viewCertsButton: document.getElementById('mdsViewCertsButton'),
    certsDialog: document.getElementById('mdsCertsDialog'),
    certsDialogBody: document.getElementById('mdsCertsDialogBody'),
    certsDialogCloseButton: document.getElementById('mdsCertsDialog_closeButton'),
    certsDialogXButton: document.getElementById('mdsCertsDialog_xButton'),
    entryDetails: document.getElementById('entryDetails')
};

let aaguids = [];
let indexed = [];
const metadataCache = new Map();
let activeSuggestionIndex = -1;
let selectedAaguid = '';
let currentMetadata = null;
let currentAttestationRootCerts = [];

function oidToName(oid) {
    const map = {
        '1.3.6.1.5.5.7.3.1': 'TLS Web Server Authentication',
        '1.3.6.1.5.5.7.3.2': 'TLS Web Client Authentication',
        '1.3.6.1.5.5.7.3.3': 'Code Signing',
        '1.3.6.1.5.5.7.3.4': 'E-mail Protection',
        '1.3.6.1.5.5.7.3.8': 'Time Stamping',
        '1.3.6.1.5.5.7.3.9': 'OCSP Signing',
        '2.5.29.37': 'Extended Key Usage',
        '1.2.840.113549.1.1.1': 'RSA Encryption',
        '1.2.840.10045.2.1': 'EC Public Key',
        '2.5.4.3': 'Common Name',
        '2.5.4.6': 'Country',
        '2.5.4.10': 'Organization',
        '2.5.4.11': 'Organizational Unit'
    };
    return map[oid] || oid;
}

function escapeHtml(s) {
    return String(s ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function getAttestationRootCertificates(metadata) {
    try {
        // Common shapes we may encounter:
        // - metadata.mds_entry.attestationRootCertificates
        // - metadata.mds_entry.metadataStatement.attestationRootCertificates
        // - metadata.metadataStatement.attestationRootCertificates
        // - metadata.attestationRootCertificates
        const entry = metadata && metadata.mds_entry ? metadata.mds_entry : null;

        if (entry && Array.isArray(entry.attestationRootCertificates)) return entry.attestationRootCertificates;

        const ms1 = entry && entry.metadataStatement ? entry.metadataStatement : null;
        if (ms1 && Array.isArray(ms1.attestationRootCertificates)) return ms1.attestationRootCertificates;

        const ms2 = metadata && metadata.metadataStatement ? metadata.metadataStatement : null;
        if (ms2 && Array.isArray(ms2.attestationRootCertificates)) return ms2.attestationRootCertificates;

        if (metadata && Array.isArray(metadata.attestationRootCertificates)) return metadata.attestationRootCertificates;

        // Last-resort: deep scan for any property named attestationRootCertificates.
        const found = findAttestationRootCertificatesDeep(metadata);
        if (found && Array.isArray(found)) return found;
    } catch { /* ignore */ }
    return [];
}

function findAttestationRootCertificatesDeep(root) {
    try {
        if (!root || (typeof root !== 'object')) return null;

        const seen = new Set();
        const stack = [root];

        while (stack.length) {
            const cur = stack.pop();
            if (!cur || (typeof cur !== 'object')) continue;
            if (seen.has(cur)) continue;
            seen.add(cur);

            // Direct hit
            if (Object.prototype.hasOwnProperty.call(cur, 'attestationRootCertificates')) {
                const v = cur.attestationRootCertificates;
                if (Array.isArray(v)) return v;
            }

            if (Array.isArray(cur)) {
                for (const item of cur) {
                    if (item && typeof item === 'object') stack.push(item);
                }
                continue;
            }

            for (const k of Object.keys(cur)) {
                const v = cur[k];
                if (v && typeof v === 'object') stack.push(v);
            }
        }
    } catch { /* ignore */ }
    return null;
}

function updateViewCertsButtonFromMetadata(metadata) {
    currentMetadata = metadata || null;
    currentAttestationRootCerts = getAttestationRootCertificates(currentMetadata);
    if (!els.viewCertsButton) return;
    const has = Array.isArray(currentAttestationRootCerts) && currentAttestationRootCerts.length > 0;
    els.viewCertsButton.hidden = !has;
}

function bytesToHexUpper(bytes) {
    return Array.from(bytes).map(b => ('0' + b.toString(16)).slice(-2)).join('').toUpperCase();
}

function convertToPEM(arrayBuffer) {
    const bytes = new Uint8Array(arrayBuffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    const b64 = btoa(binary);
    const chunks = b64.match(/.{1,64}/g) || [];
    return '-----BEGIN CERTIFICATE-----\n' + chunks.join('\n') + '\n-----END CERTIFICATE-----\n';
}

function pemToArrayBuffer(pem) {
    const text = String(pem || '');
    const b64 = text
        .replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g, '')
        .replace(/\s+/g, '');
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
}

function base64ToArrayBuffer(b64) {
    let compact = String(b64 || '').trim();
    // Support base64url and tolerate whitespace.
    compact = compact.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
    // Pad to 4-char boundary.
    while (compact.length % 4 !== 0) compact += '=';
    const bin = atob(compact);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
}

function extractTV(tav) {
    try {
        return tav.map(tv => {
            let value = '';
            try {
                value = tv.value && tv.value.valueBlock ? (tv.value.valueBlock.value ?? '') : '';
                if (!value && tv.value && tv.value.valueBlock && tv.value.valueBlock.valueHex) {
                    value = pvtsutils.BufferSourceConverter.toString(tv.value.valueBlock.valueHex);
                }
            } catch { value = ''; }
            return { type: tv.type, value: String(value) };
        }).filter(x => x && x.type);
    } catch {
        return [];
    }
}

function formatName(tvArr) {
    try {
        const arr = Array.isArray(tvArr) ? tvArr : [];
        const cn = arr.find(tv => String(tv.type || '').endsWith('2.5.4.3'));
        if (cn && cn.value) return String(cn.value);
        return arr.map(tv => `${tv.type}:${tv.value}`).join(', ');
    } catch {
        return '';
    }
}

async function parseCertificateString(certString) {
    const raw = String(certString || '').trim();
    if (!raw) throw new Error('Empty certificate');

    const isPem = raw.includes('BEGIN CERTIFICATE');
    const der = isPem ? pemToArrayBuffer(raw) : base64ToArrayBuffer(raw);
    const asn1 = asn1js.fromBER(der);
    if (asn1.offset === -1) throw new Error('ASN.1 parse error');
    const cert = new pkijs.Certificate({ schema: asn1.result });

    let fingerprintSHA256 = '';
    let fingerprintSHA256Colon = '';
    try {
        const hash = await crypto.subtle.digest('SHA-256', der);
        fingerprintSHA256 = bytesToHexUpper(new Uint8Array(hash));
        fingerprintSHA256Colon = fingerprintSHA256.match(/.{1,2}/g).join(':');
    } catch { /* ignore */ }

    let serialNumber = '';
    try {
        serialNumber = pvtsutils.Convert.ToHex(cert.serialNumber.valueBlock.valueHex).toUpperCase();
    } catch { /* ignore */ }

    // Extract subjectPublicKey raw bytes (hex) when available
    let publicKeyHex = '';
    try {
        const spkVal = cert.subjectPublicKeyInfo && cert.subjectPublicKeyInfo.subjectPublicKey && cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock && cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex;
        if (spkVal) publicKeyHex = pvtsutils.Convert.ToHex(spkVal).toUpperCase();
    } catch { /* ignore */ }

    // Determine public key algorithm and size
    let publicKey = { algorithm: null, size: null };
    try {
        publicKey.algorithm = cert.subjectPublicKeyInfo && cert.subjectPublicKeyInfo.algorithm ? (cert.subjectPublicKeyInfo.algorithm.algorithmId || null) : null;
        const alg = publicKey.algorithm || '';
        if (alg === '1.2.840.113549.1.1.1') { // rsaEncryption
            const spk = cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex;
            const spkAsn = asn1js.fromBER(spk);
            if (spkAsn.offset !== -1) {
                const rsaPub = new pkijs.RSAPublicKey({ schema: spkAsn.result });
                const modHex = pvtsutils.Convert.ToHex(rsaPub.modulus.valueBlock.valueHex);
                publicKey.size = (modHex.length / 2) * 8;
            }
        }
    } catch { /* ignore */ }

    // Extract some common extensions
    const extensions = {};
    try {
        if (Array.isArray(cert.extensions)) {
            function formatGeneralName(n) {
                try {
                    if (n.typeName && (n.typeName === 'dNSName' || n.typeName === 'uniformResourceIdentifier' || n.typeName === 'rfc822Name')) {
                        return String(n.value || n);
                    }
                    if (n.typeName === 'iPAddress') {
                        if (n.value && n.value.valueBlock && n.value.valueBlock.valueHex) {
                            const bytes = new Uint8Array(n.value.valueBlock.valueHex);
                            if (bytes.length === 4) return Array.from(bytes).join('.');
                            return Array.from(bytes).map(b => ('0' + b.toString(16)).slice(-2)).join(':');
                        }
                        return String(n.value || n);
                    }
                    if (n.typeName === 'directoryName' && n.value && Array.isArray(n.value.typesAndValues)) {
                        return n.value.typesAndValues.map(tv => (tv.type || '') + ':' + (tv.value && (tv.value.valueBlock && (tv.value.valueBlock.value || (tv.value.valueBlock.valueHex && pvtsutils.BufferSourceConverter.toString(tv.value.valueBlock.valueHex)))) || '')).join(', ');
                    }
                    if (n.value && n.value.valueBlock) {
                        const vb = n.value.valueBlock;
                        if (vb.value) return String(vb.value);
                        if (vb.valueHex) {
                            try { return pvtsutils.BufferSourceConverter.toString(vb.valueHex); } catch { return pvtsutils.Convert.ToHex(vb.valueHex); }
                        }
                    }
                    return String(n.value || n);
                } catch {
                    try { return JSON.stringify(n); } catch { return String(n); }
                }
            }

            cert.extensions.forEach(ext => {
                try {
                    if (ext.extnID === '2.5.29.19') {
                        const bc = ext.parsedValue;
                        extensions.basicConstraints = { cA: !!bc.cA, pathLenConstraint: bc.pathLenConstraint || null };
                    } else if (ext.extnID === '2.5.29.15') {
                        const ku = ext.parsedValue;
                        extensions.keyUsage = ku.wBits ? ku.wBits.join(',') : Object.keys(ku).filter(k => ku[k]).join(',');
                    } else if (ext.extnID === '2.5.29.37') {
                        const eku = ext.parsedValue;
                        if (Array.isArray(eku.keyPurposes)) {
                            extensions.extKeyUsage = eku.keyPurposes.map(k => k.toString());
                        }
                    } else if (ext.extnID === '2.5.29.17') {
                        const san = ext.parsedValue;
                        if (Array.isArray(san.altNames)) {
                            extensions.subjectAltName = san.altNames.map(n => ({ type: n.typeName || n.type, value: formatGeneralName(n) }));
                        }
                    }
                } catch { /* ignore */ }
            });
        }
    } catch { /* ignore */ }

    return {
        subject: extractTV(cert.subject.typesAndValues),
        issuer: extractTV(cert.issuer.typesAndValues),
        serialNumber,
        notBefore: cert.notBefore && cert.notBefore.value ? cert.notBefore.value.toString() : '',
        notAfter: cert.notAfter && cert.notAfter.value ? cert.notAfter.value.toString() : '',
        fingerprintSHA256,
        fingerprintSHA256Colon,
        publicKeyHex,
        publicKey,
        extensions,
        raw: der,
        pem: isPem ? raw : convertToPEM(der)
    };
}

function closeDialog(dlg) {
    try {
        if (!dlg) return;
        if (typeof dlg.close === 'function') dlg.close();
        else dlg.removeAttribute('open');
    } catch { /* ignore */ }
}

function formatHexBytesForDisplay(hex, bytesPerLine) {
    const raw = String(hex || '').replace(/\s+/g, '').toUpperCase();
    if (!raw) return '';
    const pairs = raw.match(/.{1,2}/g) || [];
    const lines = [];
    const bpl = Math.max(4, Number(bytesPerLine) || 16);
    for (let i = 0; i < pairs.length; i += bpl) {
        lines.push(pairs.slice(i, i + bpl).join(':'));
    }
    return lines.join('\n');
}

function attachResponsiveHexForElement(el, rawHex) {
    if (!el) return;
    const raw = String(rawHex || '').trim();
    if (!raw) {
        el.textContent = '';
        return;
    }

    const render = () => {
        const width = (el.getBoundingClientRect && el.getBoundingClientRect().width) ? el.getBoundingClientRect().width : 0;
        // Match index.html behavior: 16-byte rows when narrow, 32-byte rows when wider.
        const bytesPerLine = width && width < 520 ? 16 : 32;
        el.textContent = formatHexBytesForDisplay(raw, bytesPerLine);
    };

    // Initial render
    render();

    // Cleanup any previous observers/listeners
    try { if (el._hexObserver) { el._hexObserver.disconnect(); delete el._hexObserver; } } catch { /* ignore */ }
    try { if (el._hexResizeListener) { window.removeEventListener('resize', el._hexResizeListener); delete el._hexResizeListener; } } catch { /* ignore */ }

    // Prefer ResizeObserver (more accurate than window resize)
    try {
        if (typeof ResizeObserver !== 'undefined') {
            const ro = new ResizeObserver(() => {
                try { render(); } catch { /* ignore */ }
            });
            ro.observe(el);
            el._hexObserver = ro;
            return;
        }
    } catch { /* ignore */ }

    // Fallback: window resize
    const onResize = () => {
        try { render(); } catch { /* ignore */ }
    };
    window.addEventListener('resize', onResize);
    el._hexResizeListener = onResize;
}

async function showMdsCertificatesDialog() {
    const dlg = els.certsDialog;
    const body = els.certsDialogBody;
    if (!dlg || !body) return;

    // Re-derive certs at open time so the dialog reflects what's currently loaded.
    // If for some reason currentMetadata isn't populated, fall back to parsing what we rendered.
    let meta = currentMetadata;
    if (!meta && els.entryDetails && !els.entryDetails.hidden) {
        try {
            const txt = String(els.entryDetails.textContent || '').trim();
            if (txt && txt.startsWith('{')) meta = JSON.parse(txt);
        } catch { /* ignore */ }
    }

    currentAttestationRootCerts = getAttestationRootCertificates(meta);
    const certs = Array.isArray(currentAttestationRootCerts) ? currentAttestationRootCerts : [];
    if (certs.length === 0) {
        body.innerHTML = '<p>No certificates found.</p>';
        try { dlg.showModal(); } catch { dlg.setAttribute('open', ''); }
        return;
    }

    body.innerHTML = '<div class="loading-indicator"><progress class="progress progress-primary w-full"></progress></div>';
    try { dlg.showModal(); } catch { dlg.setAttribute('open', ''); }

    const parsed = [];
    for (let i = 0; i < certs.length; i++) {
        try {
            parsed.push({ ok: true, cert: await parseCertificateString(certs[i]) });
        } catch (e) {
            parsed.push({ ok: false, error: (e && e.message) ? e.message : String(e), raw: String(certs[i] || '') });
        }
    }

    let html = '';
    parsed.forEach((p, idx) => {
        function formatNameLikeIndex(arr) {
            try {
                const a = Array.isArray(arr) ? arr : [];
                const cn = a.find(tv => tv.type && String(tv.type).toLowerCase().endsWith('2.5.4.3'));
                if (cn && cn.value) {
                    const tail = a.map(tv => (tv.type || '') + ':' + (tv.value || '')).join(', ');
                    return String(cn.value) + ' (' + tail + ')';
                }
                return a.map(tv => (tv.type || '') + ': ' + (tv.value || '')).join(', ');
            } catch {
                try { return JSON.stringify(arr); } catch { return String(arr); }
            }
        }

        html += '<div class="card bg-base-100 border border-base-300 shadow-sm cert-card" style="margin-bottom:12px;">';
        html += '<div class="card-body p-4" style="display:flex; flex-direction:column; gap:8px;">';
        html += '<div class="font-semibold">Certificate ' + (idx + 1) + '</div>';

        if (p.ok) {
            const c = p.cert;
            html += '<div class="text-sm"><span class="cert-label">Subject:</span> <span class="cert-value">' + escapeHtml(formatNameLikeIndex(c.subject || [])) + '</span></div>';
            html += '<div class="text-sm"><span class="cert-label">Issuer:</span> <span class="cert-value">' + escapeHtml(formatNameLikeIndex(c.issuer || [])) + '</span></div>';
            html += '<div class="text-sm"><span class="cert-label">Serial:</span> <span class="cert-value">' + escapeHtml(c.serialNumber || '') + '</span> <button class="btn btn-ghost btn-xs btn-square cert-copy-serial" data-idx="' + idx + '" title="Copy serial"><span class="material-symbols-outlined" aria-hidden="true">content_copy</span></button></div>';
            html += '<div class="text-sm"><span class="cert-label">Validity:</span> <span class="cert-value">' + escapeHtml(c.notBefore || '') + ' → ' + escapeHtml(c.notAfter || '') + '</span></div>';

            if (c.fingerprintSHA256) {
                html += '<div class="text-sm"><span class="cert-label">Fingerprint (SHA-256):</span> <span class="cert-value">' + escapeHtml((c.fingerprintSHA256Colon || c.fingerprintSHA256)) + '</span> <button class="btn btn-ghost btn-xs btn-square cert-copy-fingerprint" data-idx="' + idx + '" title="Copy fingerprint"><span class="material-symbols-outlined" aria-hidden="true">content_copy</span></button></div>';
            }

            if (c.publicKey && (c.publicKey.algorithm || c.publicKey.size)) {
                const algName = c.publicKey.algorithm ? oidToName(c.publicKey.algorithm) : '';
                const copyBtn = c.publicKeyHex ? '<button class="btn btn-ghost btn-xs btn-square cert-copy-publickey" data-idx="' + idx + '" title="Copy public key (hex)"><span class="material-symbols-outlined" aria-hidden="true">content_copy</span></button>' : '';
                const toggleBtn = c.publicKeyHex ? '<button class="btn btn-link btn-sm public-key-toggle" aria-expanded="false" title="Show public key"><span class="material-symbols-outlined" aria-hidden="true">expand_more</span>&nbsp;Show</button>' : '';
                html += '<div class="text-sm"><span class="cert-label">Public Key:</span> <span class="cert-value">' + escapeHtml((algName || c.publicKey.algorithm || '') + (c.publicKey.size ? ' (' + c.publicKey.size + ' bits)' : '')) + '</span> ' + copyBtn + ' ' + toggleBtn + '</div>';
                if (c.publicKeyHex) {
                    html += '<div class="public-key-block collapsed"><code class="public-key-hex" data-public-key-raw="' + escapeHtml(c.publicKeyHex) + '"></code></div>';
                }
            }

            if (c.extensions) {
                if (c.extensions.basicConstraints) {
                    html += '<div class="cert-ext"><small><span class="cert-label">Basic Constraints:</span> <span class="cert-value">CA=' + (c.extensions.basicConstraints.cA ? 'true' : 'false') + (c.extensions.basicConstraints.pathLenConstraint ? ', pathLen=' + c.extensions.basicConstraints.pathLenConstraint : '') + '</span></small></div>';
                }
                if (c.extensions.keyUsage) {
                    html += '<div class="cert-ext"><small><span class="cert-label">Key Usage:</span> <span class="cert-value">' + escapeHtml(String(c.extensions.keyUsage)) + '</span></small></div>';
                }
                if (c.extensions.extKeyUsage) {
                    const ekus = c.extensions.extKeyUsage.map(o => (oidToName(o) + ' (' + o + ')'));
                    html += '<div class="cert-ext"><small><span class="cert-label">Extended Key Usage:</span> <span class="cert-value">' + escapeHtml(ekus.join(', ')) + '</span></small></div>';
                }
                if (c.extensions.subjectAltName) {
                    function decodeIdHex(val) {
                        try {
                            return String(val).replace(/id:([0-9A-Fa-f]{2,})/g, (m, hex) => {
                                try {
                                    const bytes = pvtsutils.Convert.FromHex(hex);
                                    const str = pvtsutils.BufferSourceConverter.toString(bytes);
                                    return `id:${hex} (${str})`;
                                } catch {
                                    return m;
                                }
                            });
                        } catch { return String(val); }
                    }

                    const san = c.extensions.subjectAltName.map(n => {
                        const t = n.type || '';
                        const rawVal = (typeof n.value === 'object') ? JSON.stringify(n.value) : String(n.value);
                        const val = decodeIdHex(rawVal);
                        return t + ':' + val;
                    }).join(', ');
                    html += '<div class="cert-ext"><small><span class="cert-label">Subject Alt Names:</span> <span class="cert-value">' + escapeHtml(san) + '</span></small></div>';
                }
            }

            html += '<div class="cert-actions">';
            html += '<button class="btn btn-outline btn-sm cert-download-pem" data-idx="' + idx + '"><span class="material-symbols-outlined" aria-hidden="true">file_download</span>&nbsp;Download PEM</button>';
            html += '<button class="btn btn-outline btn-sm cert-download-der" data-idx="' + idx + '"><span class="material-symbols-outlined" aria-hidden="true">cloud_download</span>&nbsp;Download DER</button>';
            html += '<button class="btn btn-ghost btn-sm cert-copy-pem" data-idx="' + idx + '"><span class="material-symbols-outlined" aria-hidden="true">content_copy</span>&nbsp;Copy PEM</button>';
            html += '</div>';
        } else {
            html += '<div class="text-sm text-error">Failed to parse: ' + escapeHtml(p.error) + '</div>';
            html += '<details><summary class="btn btn-link btn-sm" style="padding-left:0;">Show raw</summary>';
            html += '<pre class="mono" style="white-space:pre-wrap; word-break:break-word; overflow-wrap:anywhere;">' + escapeHtml(p.raw || '') + '</pre>';
            html += '</details>';
        }

        html += '</div></div>';
    });

    body.innerHTML = html;

    function downloadBlob(filename, blob) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        setTimeout(() => {
            URL.revokeObjectURL(url);
            a.remove();
        }, 1000);
    }

    async function copyTextWithFallback(text) {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch {
            try {
                const ta = document.createElement('textarea');
                ta.value = text;
                ta.style.position = 'fixed';
                ta.style.left = '-9999px';
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                ta.remove();
                return true;
            } catch {
                return false;
            }
        }
    }

    // Per-cert actions
    body.querySelectorAll('.cert-download-pem').forEach(btn => {
        btn.addEventListener('click', () => {
            const idx = parseInt(btn.getAttribute('data-idx') || '0', 10);
            const p = parsed[idx];
            if (!p || !p.ok) return;
            const pem = p.cert.pem || '';
            const blob = new Blob([pem], { type: 'application/x-pem-file' });
            downloadBlob('certificate-' + (idx + 1) + '.pem', blob);
        });
    });

    body.querySelectorAll('.cert-download-der').forEach(btn => {
        btn.addEventListener('click', () => {
            const idx = parseInt(btn.getAttribute('data-idx') || '0', 10);
            const p = parsed[idx];
            if (!p || !p.ok) return;
            const ab = p.cert.raw;
            if (!ab) return;
            const blob = new Blob([ab], { type: 'application/octet-stream' });
            downloadBlob('certificate-' + (idx + 1) + '.der', blob);
        });
    });

    body.querySelectorAll('.cert-copy-pem').forEach(btn => {
        btn.addEventListener('click', async () => {
            const idx = parseInt(btn.getAttribute('data-idx') || '0', 10);
            const p = parsed[idx];
            if (!p || !p.ok) return;
            const ok = await copyTextWithFallback(p.cert.pem || '');
            showToast(ok ? 'info' : 'warning', ok ? 'PEM copied to clipboard' : 'Copy failed; use Download PEM');
        });
    });

    body.querySelectorAll('.cert-copy-fingerprint').forEach(btn => {
        btn.addEventListener('click', async () => {
            const idx = parseInt(btn.getAttribute('data-idx') || '0', 10);
            const p = parsed[idx];
            if (!p || !p.ok) return;
            const toCopy = p.cert.fingerprintSHA256 || p.cert.fingerprintSHA256Colon || '';
            if (!toCopy) return;
            const ok = await copyTextWithFallback(toCopy);
            showToast(ok ? 'info' : 'warning', ok ? 'Fingerprint copied' : 'Copy failed');
        });
    });

    body.querySelectorAll('.cert-copy-serial').forEach(btn => {
        btn.addEventListener('click', async () => {
            const idx = parseInt(btn.getAttribute('data-idx') || '0', 10);
            const p = parsed[idx];
            if (!p || !p.ok) return;
            const toCopy = p.cert.serialNumber || '';
            if (!toCopy) return;
            const ok = await copyTextWithFallback(toCopy);
            showToast(ok ? 'info' : 'warning', ok ? 'Serial copied' : 'Copy failed');
        });
    });

    body.querySelectorAll('.cert-copy-publickey').forEach(btn => {
        btn.addEventListener('click', async () => {
            const idx = parseInt(btn.getAttribute('data-idx') || '0', 10);
            const p = parsed[idx];
            if (!p || !p.ok) return;
            const toCopy = p.cert.publicKeyHex || '';
            if (!toCopy) return;
            const ok = await copyTextWithFallback(toCopy);
            showToast(ok ? 'info' : 'warning', ok ? 'Public key copied' : 'Copy failed');
        });
    });

    // Public key toggles
    body.querySelectorAll('.public-key-toggle').forEach(btn => {
        btn.addEventListener('click', () => {
            const parentDiv = btn.closest('div');
            let block = parentDiv ? parentDiv.nextElementSibling : null;
            if (!block || !block.classList || !block.classList.contains('public-key-block')) {
                const card = btn.closest('.cert-card');
                if (card) block = card.querySelector('.public-key-block');
            }
            if (!block) return;
            const expanded = btn.getAttribute('aria-expanded') === 'true';
            if (expanded) {
                block.classList.add('collapsed');
                btn.setAttribute('aria-expanded', 'false');
                btn.innerHTML = '<span class="material-symbols-outlined" aria-hidden="true">expand_more</span>&nbsp;Show';
            } else {
                block.classList.remove('collapsed');
                btn.setAttribute('aria-expanded', 'true');
                btn.innerHTML = '<span class="material-symbols-outlined" aria-hidden="true">expand_less</span>&nbsp;Hide';
                // Fill and format the code element lazily (responsive hex rows)
                const codeEl = block.querySelector('.public-key-hex');
                if (codeEl) {
                    const rawHex = codeEl.getAttribute('data-public-key-raw') || '';
                    attachResponsiveHexForElement(codeEl, rawHex);
                }
            }
        });
    });
}

function setDetailsCardVisible(visible) {
    if (!els.detailsCard) return;
    const v = Boolean(visible);
    // Use both to avoid any CSS/utility overrides.
    els.detailsCard.hidden = !v;
    els.detailsCard.style.display = v ? '' : 'none';
}

function setSelectedLabelCardVisible(visible) {
    if (!els.selectedLabelCard) return;
    const v = Boolean(visible);
    // Use both to avoid any CSS/utility overrides.
    els.selectedLabelCard.hidden = !v;
    els.selectedLabelCard.style.display = v ? '' : 'none';
}

function updateDetailsCardVisibility() {
    const labelVisible = els.selectedLabel ? !els.selectedLabel.hidden : false;
    const detailsVisible = els.entryDetails ? !els.entryDetails.hidden : false;
    setSelectedLabelCardVisible(labelVisible);
    setDetailsCardVisible(detailsVisible);
}

function getToastContainer() {
    let el = document.getElementById('toastContainer');
    if (el) return el;
    el = document.createElement('div');
    el.id = 'toastContainer';
    el.className = 'toast toast-top toast-end z-50';
    document.body.appendChild(el);
    return el;
}

function showToast(kind, message, timeoutMs = 6000) {
    const container = getToastContainer();

    const alert = document.createElement('div');
    const typeClass = kind === 'error'
        ? 'alert-error'
        : kind === 'warning'
            ? 'alert-warning'
            : 'alert-info';

    alert.className = `alert ${typeClass} shadow-lg max-w-md`;
    alert.setAttribute('role', 'alert');
    alert.textContent = String(message || '');

    container.appendChild(alert);
    window.setTimeout(() => {
        try { alert.remove(); } catch { /* ignore */ }
    }, timeoutMs);
}

function normalizeAaguid(input) {
    const raw = String(input || '').trim().toLowerCase();
    if (!raw) return '';
    const hex = raw.replace(/[^0-9a-f]/g, '');
    if (hex.length !== 32) return raw;
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function aaguidToHex32(aaguid) {
    return String(aaguid || '').toLowerCase().replace(/[^0-9a-f]/g, '');
}

async function fetchJson(url) {
    const resp = await fetch(url, { method: 'GET', cache: 'no-store' });
    if (!resp.ok) throw new Error(`Fetch failed (${resp.status})`);
    return resp.json();
}

async function fetchText(url) {
    const resp = await fetch(url, { method: 'GET', cache: 'no-store' });
    if (!resp.ok) throw new Error(`Fetch failed (${resp.status})`);
    return resp.text();
}

function looksLikeBase64(s) {
    const t = String(s || '').trim();
    if (!t || t.length < 16) return false;
    return /^[A-Za-z0-9+/\s]+=*$/.test(t);
}

function toDataUrlFromText(text) {
    const t = String(text || '').trim();
    if (!t) return '';

    if (/^data:/i.test(t)) return t;
    if (/^https?:\/\//i.test(t)) return t;

    // Inline SVG
    if (/^<svg[\s>]/i.test(t)) {
        return `data:image/svg+xml;utf8,${encodeURIComponent(t)}`;
    }

    // base64 (likely PNG/WebP/SVG)
    if (looksLikeBase64(t)) {
        const compact = t.replace(/\s+/g, '');
        let mime = 'image/png';
        if (compact.startsWith('iVBOR')) mime = 'image/png';
        else if (compact.startsWith('/9j/')) mime = 'image/jpeg';
        else if (compact.startsWith('R0lGOD')) mime = 'image/gif';
        else if (compact.startsWith('UklGR')) mime = 'image/webp';
        else if (compact.startsWith('PHN2Zy') || compact.startsWith('PD94bWw')) mime = 'image/svg+xml';

        return `data:${mime};base64,${compact}`;
    }

    // Fallback: treat as a url-ish string
    return t;
}

function clearSelectedIcons() {
    const imgs = [els.selectedIconLight, els.selectedIconDark];
    for (const img of imgs) {
        if (!img) continue;
        try { img.removeAttribute('src'); } catch { /* ignore */ }
        try { img.hidden = true; } catch { /* ignore */ }
    }
}

async function loadAndRenderSelectedIcons(aaguid) {
    clearSelectedIcons();
    const key = String(aaguid || '').toLowerCase();
    if (!key) return;

    // Per repo convention (as requested):
    // - light icon is stored in icon_dark.txt
    // - dark icon is stored in icon_light.txt
    const lightUrl = `${RAW_BASE}/${encodeURIComponent(key)}/icon_dark.txt`;
    const darkUrl = `${RAW_BASE}/${encodeURIComponent(key)}/icon_light.txt`;

    async function tryLoad(url) {
        try {
            const txt = await fetchText(url);
            return toDataUrlFromText(txt);
        } catch {
            return '';
        }
    }

    const [lightSrc, darkSrc] = await Promise.all([tryLoad(lightUrl), tryLoad(darkUrl)]);

    if (els.selectedIconLight && lightSrc) {
        els.selectedIconLight.src = lightSrc;
        els.selectedIconLight.hidden = false;
    }
    if (els.selectedIconDark && darkSrc) {
        els.selectedIconDark.src = darkSrc;
        els.selectedIconDark.hidden = false;
    }
}

async function fetchMetadataJson(aaguid) {
    const key = String(aaguid || '').toLowerCase();
    if (!key) throw new Error('Missing AAGUID');
    if (metadataCache.has(key)) return metadataCache.get(key);
    const url = `${RAW_BASE}/${encodeURIComponent(key)}/metadata.json`;
    const data = await fetchJson(url);
    metadataCache.set(key, data);
    return data;
}

function renderSelectedLabel(entry) {
    if (!els.selectedLabel) return;
    if (!entry) {
        els.selectedLabel.textContent = '';
        els.selectedLabel.hidden = true;
        updateDetailsCardVisibility();
        return;
    }
    const name = entry && entry.name ? String(entry.name) : '(unknown)';
    els.selectedLabel.textContent = name;
    els.selectedLabel.hidden = false;
    updateDetailsCardVisibility();
}

function renderEntry(entry) {
    if (!els.entryDetails) return;
    if (!entry) {
        els.entryDetails.textContent = '';
        els.entryDetails.hidden = true;
        updateDetailsCardVisibility();
        return;
    }
    try {
        els.entryDetails.textContent = JSON.stringify(entry, null, 2);
    } catch {
        els.entryDetails.textContent = String(entry);
    }

    els.entryDetails.hidden = false;
    updateDetailsCardVisibility();
}

function hideSuggestions() {
    if (!els.suggestions) return;
    els.suggestions.hidden = true;
    els.suggestions.innerHTML = '';
    activeSuggestionIndex = -1;
}

function getSuggestionButtons() {
    if (!els.suggestions || els.suggestions.hidden) return [];
    return Array.from(els.suggestions.querySelectorAll('li > button'));
}

function setActiveSuggestionIndex(nextIndex, { focus = true } = {}) {
    const btns = getSuggestionButtons();
    if (btns.length === 0) {
        activeSuggestionIndex = -1;
        return;
    }

    let idx = Number(nextIndex);
    if (!Number.isFinite(idx)) idx = 0;
    if (idx < 0) idx = btns.length - 1;
    if (idx >= btns.length) idx = 0;

    // Clear previous active
    for (let i = 0; i < btns.length; i++) {
        try { btns[i].classList.remove('active'); } catch { /* ignore */ }
    }

    const btn = btns[idx];
    try { btn.classList.add('active'); } catch { /* ignore */ }
    activeSuggestionIndex = idx;

    try { btn.scrollIntoView({ block: 'nearest' }); } catch { /* ignore */ }
    if (focus) {
        try { btn.focus(); } catch { /* ignore */ }
    }
}

function showSuggestions(items) {
    if (!els.suggestions) return;
    els.suggestions.innerHTML = '';
    if (!items || items.length === 0) {
        els.suggestions.hidden = true;
        activeSuggestionIndex = -1;
        return;
    }

    const maxItems = Math.min(items.length, 25);
    for (let i = 0; i < maxItems; i++) {
        const item = items[i];
        const li = document.createElement('li');
        li.style.width = '100%';
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'text-left whitespace-normal';
        btn.style.width = '100%';
        btn.style.display = 'block';
        const name = item && item.name ? String(item.name) : '(unknown)';
        const aaguid = item && item.aaguid ? String(item.aaguid) : '';
        btn.textContent = `${name}${aaguid ? ` (${aaguid})` : ''}`;
        btn.addEventListener('click', () => selectEntry(item));
        btn.addEventListener('mousemove', () => {
            // Keep active highlight in sync with hover.
            const btns = getSuggestionButtons();
            const idx = btns.indexOf(btn);
            if (idx >= 0) setActiveSuggestionIndex(idx, { focus: false });
        });
        btn.addEventListener('keydown', (e) => {
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                setActiveSuggestionIndex(activeSuggestionIndex + 1);
                return;
            }
            if (e.key === 'ArrowUp') {
                e.preventDefault();
                setActiveSuggestionIndex(activeSuggestionIndex - 1);
                return;
            }
            if (e.key === 'Escape') {
                e.preventDefault();
                hideSuggestions();
                try { els.aaguidInput && els.aaguidInput.focus(); } catch { /* ignore */ }
                return;
            }
            if (e.key === 'Enter') {
                e.preventDefault();
                selectEntry(item);
            }
        });
        li.appendChild(btn);
        els.suggestions.appendChild(li);
    }
    els.suggestions.hidden = false;
    activeSuggestionIndex = -1;
}

function scoreEntry(entry, q) {
    const qLower = String(q || '').trim().toLowerCase();
    if (!qLower) return -1;

    const name = entry && entry.nameNorm ? entry.nameNorm : '';
    const aaguid = entry && entry.aaguidNorm ? entry.aaguidNorm : '';
    const aaguidHex = entry && entry.aaguidHex ? entry.aaguidHex : '';

    // Prefer exact AAGUID match.
    const qAsAaguid = normalizeAaguid(qLower);
    if (qAsAaguid && qAsAaguid.length === 36 && qAsAaguid === aaguid) return 1000;

    // AAGUID hex substring match (supports partial typing without hyphens).
    const qHex = aaguidToHex32(qLower);
    if (qHex.length >= 4) {
        if (aaguidHex.startsWith(qHex)) return 900 - (aaguidHex.length - qHex.length);
        if (aaguidHex.includes(qHex)) return 700;
    }

    // Name match.
    if (name === qLower) return 650;
    if (name.startsWith(qLower)) return 600;
    if (name.includes(qLower)) return 450;

    // AAGUID string match as a fallback.
    if (aaguid.startsWith(qLower)) return 400;
    if (aaguid.includes(qLower)) return 250;

    return -1;
}

function findMatches(query) {
    const q = String(query || '').trim();
    if (!q) return [];
    if (!Array.isArray(indexed) || indexed.length === 0) return [];

    const scored = [];
    for (const e of indexed) {
        const s = scoreEntry(e, q);
        if (s >= 0) scored.push({ e, s });
    }
    scored.sort((a, b) => b.s - a.s);
    return scored.slice(0, 25).map(x => x.e);
}

async function selectEntry(entry) {
    if (!entry || !entry.aaguid) {
        showToast('warning', 'Invalid selection.');
        return;
    }
    hideSuggestions();

    const aaguid = String(entry.aaguid).toLowerCase();
    if (els.aaguidInput) els.aaguidInput.value = aaguid;
    selectedAaguid = aaguid;
    updateClearButtonVisibility();

    renderSelectedLabel(entry);
    loadAndRenderSelectedIcons(aaguid);
    renderEntry(null);

    try {
        const metadata = await fetchMetadataJson(aaguid);
        updateViewCertsButtonFromMetadata(metadata);
        renderEntry(metadata);
    } catch (e) {
        updateViewCertsButtonFromMetadata(null);
        renderEntry(null);
        showToast('error', `Metadata load failed: ${e && e.message ? e.message : e}`);
    }
}

function updateClearButtonVisibility() {
    if (!els.clearBtn) return;
    const hasText = Boolean(String(els.aaguidInput ? els.aaguidInput.value : '').trim());
    els.clearBtn.hidden = !hasText;
}

function clearSearchAndResults() {
    if (els.aaguidInput) els.aaguidInput.value = '';
    selectedAaguid = '';
    hideSuggestions();
    renderSelectedLabel(null);
    clearSelectedIcons();
    updateViewCertsButtonFromMetadata(null);
    renderEntry(null);
    updateClearButtonVisibility();
    try { els.aaguidInput && els.aaguidInput.focus(); } catch { /* ignore */ }
}

function clearSelectionDisplayOnly() {
    selectedAaguid = '';
    renderSelectedLabel(null);
    clearSelectedIcons();
    updateViewCertsButtonFromMetadata(null);
    renderEntry(null);
}

async function loadDataset() {
    try {
        const list = await fetchJson(AAGUIDS_URL);

        if (!Array.isArray(list)) throw new Error('Dataset is not an array');
        aaguids = list;

        indexed = aaguids
            .filter(e => e && e.aaguid)
            .map(e => {
                const aaguid = String(e.aaguid).toLowerCase();
                const name = e && e.name ? String(e.name) : '';
                return {
                    ...e,
                    aaguid,
                    name,
                    aaguidNorm: aaguid,
                    aaguidHex: aaguidToHex32(aaguid),
                    nameNorm: String(name).toLowerCase()
                };
            });
    } catch (e) {
        showToast('error', `Load failed: ${e && e.message ? e.message : e}`);
    }
}

function getInitialAaguidFromUrl() {
    try {
        const params = new URLSearchParams(window.location.search || '');
        const v = params.get('aaguid') || params.get('q') || '';
        return String(v || '').trim();
    } catch {
        return '';
    }
}

function wireUi() {
    let debounceTimer = null;

    function isEditableTarget(target) {
        const el = target;
        if (!el) return false;
        if (el.isContentEditable) return true;
        const tag = String(el.tagName || '').toUpperCase();
        return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT';
    }

    function onQueryChange() {
        const q = els.aaguidInput ? els.aaguidInput.value : '';

        // If the user starts a new search, hide the old selection/details so it
        // doesn't look clipped behind the dropdown.
        if (selectedAaguid) {
            const qNorm = normalizeAaguid(q);
            const qLower = String(qNorm || q || '').trim().toLowerCase();
            if (qLower && qLower !== selectedAaguid) clearSelectionDisplayOnly();
        }

        const matches = findMatches(q);
        showSuggestions(matches);
        updateClearButtonVisibility();
    }

    async function doSearch(commit = false) {
        const q = String(els.aaguidInput ? els.aaguidInput.value : '').trim();
        if (!q) {
            hideSuggestions();
            renderSelectedLabel(null);
            clearSelectedIcons();
            updateViewCertsButtonFromMetadata(null);
            renderEntry(null);
            return;
        }
        if (!Array.isArray(indexed) || indexed.length === 0) {
            showToast('warning', 'Dataset not loaded yet. Refresh the page.');
            return;
        }

        const matches = findMatches(q);
        if (!commit) {
            showSuggestions(matches);
            return;
        }

        if (!matches || matches.length === 0) {
            hideSuggestions();
            showToast('warning', 'No matches.');
            return;
        }

        await selectEntry(matches[0]);
    }

    if (els.aaguidInput) {
        els.aaguidInput.addEventListener('input', () => {
            if (debounceTimer) window.clearTimeout(debounceTimer);
            debounceTimer = window.setTimeout(() => onQueryChange(), 120);
        });

        els.aaguidInput.addEventListener('focus', () => {
            onQueryChange();
        });

        els.aaguidInput.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                hideSuggestions();
                return;
            }
            if (e.key === 'Enter') {
                e.preventDefault();
                doSearch(true);
            }
            if (e.key === 'ArrowDown') {
                if (els.suggestions && !els.suggestions.hidden) {
                    e.preventDefault();
                    setActiveSuggestionIndex(activeSuggestionIndex < 0 ? 0 : activeSuggestionIndex + 1);
                    return;
                }
                // If list isn't open yet, open it and focus first item.
                onQueryChange();
                if (els.suggestions && !els.suggestions.hidden) {
                    e.preventDefault();
                    setActiveSuggestionIndex(0);
                }
            }
            if (e.key === 'ArrowUp' && els.suggestions && !els.suggestions.hidden) {
                e.preventDefault();
                setActiveSuggestionIndex(activeSuggestionIndex < 0 ? getSuggestionButtons().length - 1 : activeSuggestionIndex - 1);
            }
        });
    }

    if (els.clearBtn) {
        els.clearBtn.addEventListener('click', (e) => {
            try { e.preventDefault(); } catch { /* ignore */ }
            try { e.stopPropagation(); } catch { /* ignore */ }
            clearSearchAndResults();
        });
    }

    document.addEventListener('click', (e) => {
        const t = e.target;
        const clickedInside = (els.suggestions && els.suggestions.contains(t)) || (els.aaguidInput && els.aaguidInput.contains(t)) || (els.clearBtn && els.clearBtn.contains(t));
        if (!clickedInside) hideSuggestions();
    });

    // Keyboard shortcut: press '/' anywhere to clear current selection/details
    // and focus the search box (similar to common "focus search" UX).
    document.addEventListener('keydown', (e) => {
        if (e.defaultPrevented) return;
        if (e.key !== '/') return;
        if (e.ctrlKey || e.metaKey || e.altKey) return;
        if (isEditableTarget(e.target)) return;

        try { e.preventDefault(); } catch { /* ignore */ }

        // Same behavior as clicking the X: clear query + selection/details + refocus.
        clearSearchAndResults();
    });
}

(async function init() {
    // Wire certificate dialog actions
    try {
        if (els.viewCertsButton) {
            els.viewCertsButton.addEventListener('click', (e) => {
                try { e.preventDefault(); } catch { /* ignore */ }
                showMdsCertificatesDialog();
            });
        }
        if (els.certsDialogCloseButton && els.certsDialog) {
            els.certsDialogCloseButton.addEventListener('click', () => closeDialog(els.certsDialog));
        }
        if (els.certsDialogXButton && els.certsDialog) {
            els.certsDialogXButton.addEventListener('click', () => closeDialog(els.certsDialog));
        }
        if (els.certsDialog) {
            els.certsDialog.addEventListener('close', () => {
                try {
                    const nodes = els.certsDialog.querySelectorAll('.public-key-hex');
                    nodes.forEach(n => {
                        try { if (n._hexObserver) { n._hexObserver.disconnect(); delete n._hexObserver; } } catch { /* ignore */ }
                        try { if (n._hexResizeListener) { window.removeEventListener('resize', n._hexResizeListener); delete n._hexResizeListener; } } catch { /* ignore */ }
                    });
                } catch { /* ignore */ }
            });
        }
        // Start hidden until metadata is loaded
        updateViewCertsButtonFromMetadata(null);
    } catch { /* ignore */ }

    wireUi();
    // Put cursor in the search box on load.
    try {
        if (els.aaguidInput) {
            els.aaguidInput.focus();
            els.aaguidInput.select?.();
        }
    } catch { /* ignore */ }

    // Ensure details are hidden on initial load.
    try {
        if (els.selectedLabel) els.selectedLabel.hidden = true;
        if (els.entryDetails) els.entryDetails.hidden = true;
    } catch { /* ignore */ }
    updateDetailsCardVisibility();

    updateClearButtonVisibility();
    await loadDataset();

    // If launched from a credential card, preselect the provided AAGUID.
    const initial = getInitialAaguidFromUrl();
    if (initial) {
        const q = normalizeAaguid(initial);
        try {
            if (els.aaguidInput) {
                els.aaguidInput.value = q;
            }
        } catch { /* ignore */ }

        updateClearButtonVisibility();

        const matches = findMatches(q);
        if (matches && matches.length) {
            await selectEntry(matches[0]);
        } else {
            // Fallback: try to load metadata directly (may still succeed even if not in dataset).
            try {
                const aaguid = String(q || initial).toLowerCase();
                renderSelectedLabel({ aaguid, name: '' });
                loadAndRenderSelectedIcons(aaguid);
                renderEntry(null);
                const metadata = await fetchMetadataJson(aaguid);
                updateViewCertsButtonFromMetadata(metadata);
                renderEntry(metadata);
            } catch (e) {
                updateViewCertsButtonFromMetadata(null);
                showToast('warning', 'No matching authenticator found for the provided AAGUID.');
            }
        }
    }
})();
