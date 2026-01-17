// Client-side AAGUID lookup: fetches the public dataset from GitHub and
// provides an interactive Name/AAGUID search. No local caching.

const AAGUIDS_URL = 'https://raw.githubusercontent.com/akshayku/passkey-aaguids/main/aaguids.json';
const RAW_BASE = 'https://raw.githubusercontent.com/akshayku/passkey-aaguids/main';

const els = {
    aaguidInput: document.getElementById('aaguidInput'),
    clearBtn: document.getElementById('clearBtn'),
    suggestions: document.getElementById('suggestions'),
    detailsCard: document.getElementById('detailsCard'),
    selectedLabel: document.getElementById('selectedLabel'),
    entryDetails: document.getElementById('entryDetails')
};

let aaguids = [];
let indexed = [];
const metadataCache = new Map();
let activeSuggestionIndex = -1;
let selectedAaguid = '';

function updateDetailsCardVisibility() {
    if (!els.detailsCard) return;
    const labelVisible = els.selectedLabel ? !els.selectedLabel.hidden : false;
    const detailsVisible = els.entryDetails ? !els.entryDetails.hidden : false;
    els.detailsCard.hidden = !(labelVisible || detailsVisible);
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
    const aaguid = entry && entry.aaguid ? String(entry.aaguid) : '';
    els.selectedLabel.textContent = `${name}${aaguid ? ` (${aaguid})` : ''}`;
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
    renderEntry(null);

    try {
        const metadata = await fetchMetadataJson(aaguid);
        renderEntry(metadata);
    } catch (e) {
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
    renderEntry(null);
    updateClearButtonVisibility();
    try { els.aaguidInput && els.aaguidInput.focus(); } catch { /* ignore */ }
}

function clearSelectionDisplayOnly() {
    selectedAaguid = '';
    renderSelectedLabel(null);
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

function wireUi() {
    let debounceTimer = null;

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
}

(async function init() {
    wireUi();
    // Put cursor in the search box on load.
    try {
        if (els.aaguidInput) {
            els.aaguidInput.focus();
            els.aaguidInput.select?.();
        }
    } catch { /* ignore */ }
    updateClearButtonVisibility();
    await loadDataset();
})();
