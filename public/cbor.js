// Lightweight CBOR decoder for playground purposes.
// Supports RFC 8949 major types: unsigned, negative, byte/text strings, arrays, maps, tags, simple + floats.
// Indefinite-length items are partially supported (arrays/maps/strings) until break (0xFF).
// NOT for production security-critical parsing.

(function(global){
    function readUint(data, offset, length){
        if(offset + length > data.length) throw new Error('Truncated integer');
        let val = 0n;
        for(let i=0;i<length;i++) val = (val << 8n) | BigInt(data[offset+i]);
        const num = Number(val);
        return {value: (val <= BigInt(Number.MAX_SAFE_INTEGER)) ? num : val, offset: offset + length};
    }

    function readLength(addl, data, offset){
        if(addl < 24) return {len: addl, offset};
        if(addl === 24){
            if(offset >= data.length) throw new Error('Truncated length (8)');
            return {len: data[offset], offset: offset+1};
        }
        if(addl === 25){
            const r = readUint(data, offset, 2); return {len: r.value, offset: r.offset};
        }
        if(addl === 26){
            const r = readUint(data, offset, 4); return {len: r.value, offset: r.offset};
        }
        if(addl === 27){
            const r = readUint(data, offset, 8); return {len: r.value, offset: r.offset};
        }
        if(addl === 31){ // indefinite
            return {len: -1, offset};
        }
        throw new Error('Invalid additional info for length: ' + addl);
    }

    function readHalfFloat(bytes){
        const b0 = bytes[0], b1 = bytes[1];
        const sign = (b0 & 0x80) ? -1 : 1;
        const exp = (b0 & 0x7C) >> 2;
        const frac = ((b0 & 0x03) << 8) | b1;
        if(exp === 0){
            if(frac === 0) return sign * 0;
            return sign * Math.pow(2,-14) * (frac / 1024);
        }
        if(exp === 31){
            if(frac === 0) return sign * Infinity;
            return NaN;
        }
        return sign * Math.pow(2, exp - 15) * (1 + frac/1024);
    }

    function toUtf8(bytes){
        if(typeof TextDecoder !== 'undefined') return new TextDecoder('utf-8',{fatal:false}).decode(bytes);
        // Fallback minimal decoder
        let str = ''; for(let i=0;i<bytes.length;i++) str += String.fromCharCode(bytes[i]);
        return decodeURIComponent(escape(str));
    }

    function decodeItem(data, offset){
        if(offset >= data.length) throw new Error('Unexpected end of data');
        const ib = data[offset++];
        const major = ib >> 5;
        const addl = ib & 0x1f;
        if(addl >= 28 && addl <= 30){
            throw new Error('Reserved additional info ' + addl + ' (byte 0x' + ib.toString(16).padStart(2,'0') + ') at offset ' + (offset-1) + ' – possible malformed CBOR or truncated prior item.');
        }

        switch(major){
            case 0: { // unsigned int
                const {len, offset: o2} = readLength(addl, data, offset);
                offset = o2; return {value: len, offset};
            }
            case 1: { // negative int
                const {len, offset: o2} = readLength(addl, data, offset);
                offset = o2; return {value: -1 - len, offset};
            }
            case 2: { // byte string
                const {len, offset: o2} = readLength(addl, data, offset); offset = o2;
                if(len === -1){ // indefinite
                    let parts = [];
                    while(true){
                        if(offset >= data.length) throw new Error('Unterminated indefinite byte string');
                        if(data[offset] === 0xFF){ offset++; break; }
                        const r = decodeItem(data, offset);
                        if(!(r.value instanceof Uint8Array)) throw new Error('Indefinite bytes expect definite byte chunks');
                        parts.push(r.value); offset = r.offset;
                    }
                    let total = parts.reduce((a,p)=>a+p.length,0); const out = new Uint8Array(total);
                    let pos=0; parts.forEach(p=>{out.set(p,pos); pos+=p.length;});
                    return {value: out, offset};
                }
                if(offset + len > data.length) throw new Error('Truncated byte string');
                const val = data.slice(offset, offset+len); offset += len; return {value: val, offset};
            }
            case 3: { // text string
                const {len, offset: o2} = readLength(addl, data, offset); offset = o2;
                if(len === -1){ // indefinite
                    let chunks = [];
                    while(true){
                        if(offset >= data.length) throw new Error('Unterminated indefinite text string');
                        if(data[offset] === 0xFF){ offset++; break; }
                        const r = decodeItem(data, offset);
                        if(typeof r.value !== 'string') throw new Error('Indefinite text expects definite text chunks');
                        chunks.push(r.value); offset = r.offset;
                    }
                    return {value: chunks.join(''), offset};
                }
                if(offset + len > data.length) throw new Error('Truncated text string');
                const str = toUtf8(data.slice(offset, offset+len)); offset += len; return {value: str, offset};
            }
            case 4: { // array
                const {len, offset: o2} = readLength(addl, data, offset); offset = o2;
                let arr = [];
                if(len === -1){ // indefinite
                    while(true){
                        if(offset >= data.length) throw new Error('Unterminated indefinite array');
                        if(data[offset] === 0xFF){ offset++; break; }
                        const r = decodeItem(data, offset); arr.push(r.value); offset = r.offset;
                    }
                } else {
                    for(let i=0;i<len;i++){ const r = decodeItem(data, offset); arr.push(r.value); offset = r.offset; }
                }
                return {value: arr, offset};
            }
            case 5: { // map
                const {len, offset: o2} = readLength(addl, data, offset); offset = o2;
                let obj = {};
                const readPairs = (count)=>{ for(let i=0;i<count;i++){ const k = decodeItem(data, offset); offset = k.offset; const v = decodeItem(data, offset); offset = v.offset; const key = (typeof k.value === 'string')? k.value : JSON.stringify(k.value); obj[key]=v.value; } };
                if(len === -1){
                    while(true){
                        if(offset >= data.length) throw new Error('Unterminated indefinite map');
                        if(data[offset] === 0xFF){ offset++; break; }
                        const k = decodeItem(data, offset); offset = k.offset; const v = decodeItem(data, offset); offset = v.offset; const key = (typeof k.value === 'string')? k.value : JSON.stringify(k.value); obj[key]=v.value;
                    }
                } else { readPairs(len); }
                return {value: obj, offset};
            }
            case 6: { // tag
                const {len: tagNum, offset: o2} = readLength(addl, data, offset); offset = o2;
                const tagged = decodeItem(data, offset); offset = tagged.offset;
                // Interpret selected semantic tags (RFC 8949) to remove previous limitations:
                // 2 = positive bignum, 3 = negative bignum.
                if((tagNum === 2 || tagNum === 3) && tagged.value instanceof Uint8Array){
                    // Big-endian unsigned magnitude in the byte string.
                    let bn = 0n;
                    for(const b of tagged.value){ bn = (bn << 8n) | BigInt(b); }
                    if(tagNum === 3){ // negative: value = -1 - n
                        bn = -1n - bn;
                    }
                    return { value: bn, offset };
                }
                // 0 = date/time string in RFC 3339 format
                if(tagNum === 0 && typeof tagged.value === 'string'){
                    return { value: { '@datetime': tagged.value }, offset };
                }
                // 1 = epoch-based date/time (seconds since 1970-01-01T00:00Z) int/float
                if(tagNum === 1 && (typeof tagged.value === 'number' || typeof tagged.value === 'bigint')){
                    // Convert to ISO 8601 string; BigInt may exceed safe range, so limit conversion if large.
                    let secs = tagged.value;
                    let iso;
                    try {
                        if(typeof secs === 'bigint'){
                            // Only convert if within safe millisecond range.
                            const msBig = secs * 1000n;
                            if(msBig <= BigInt(Number.MAX_SAFE_INTEGER) && msBig >= BigInt(Number.MIN_SAFE_INTEGER)){
                                iso = new Date(Number(msBig)).toISOString();
                            } else {
                                iso = secs.toString() + 's';
                            }
                        } else {
                            iso = new Date(secs * 1000).toISOString();
                        }
                    } catch{ iso = String(secs); }
                    return { value: { '@epoch': secs, '@iso': iso }, offset };
                }
                // 24 = encoded CBOR data item in a byte string
                if(tagNum === 24 && tagged.value instanceof Uint8Array){
                    let embedded;
                    try {
                        embedded = decodeCbor(tagged.value);
                    } catch(e){
                        embedded = { '@error': 'Embedded decode failed: ' + e.message, '@bytes': bytesToHex(tagged.value) };
                    }
                    return { value: { '@embedded': embedded }, offset };
                }
                // 32 = URI, 33 = base64url, 34 = base64, 35 = regexp, 36 = MIME message
                if(tagNum === 32 && typeof tagged.value === 'string') return { value: { '@uri': tagged.value }, offset };
                if(tagNum === 33 && typeof tagged.value === 'string') return { value: { '@base64url': tagged.value }, offset };
                if(tagNum === 34 && typeof tagged.value === 'string') return { value: { '@base64': tagged.value }, offset };
                if(tagNum === 35 && typeof tagged.value === 'string') return { value: { '@regex': tagged.value }, offset };
                if(tagNum === 36 && typeof tagged.value === 'string') return { value: { '@mime': tagged.value }, offset };
                return {value: {"@tag": tagNum, value: tagged.value}, offset};
            }
            case 7: { // simple / floats
                if(addl < 20) return {value: {"@simple": addl}, offset};
                switch(addl){
                    case 20: return {value: false, offset};
                    case 21: return {value: true, offset};
                    case 22: return {value: null, offset};
                    case 23: return {value: undefined, offset};
                    case 24: { if(offset>=data.length) throw new Error('Truncated simple value'); return {value: {"@simple": data[offset++]}, offset}; }
                    case 25: { if(offset+2>data.length) throw new Error('Truncated half float'); const f = readHalfFloat(data.slice(offset, offset+2)); offset+=2; return {value: f, offset}; }
                    case 26: { if(offset+4>data.length) throw new Error('Truncated float32'); const view=new DataView(data.buffer, data.byteOffset+offset,4); const f = view.getFloat32(0,false); offset+=4; return {value:f, offset}; }
                    case 27: { if(offset+8>data.length) throw new Error('Truncated float64'); const view=new DataView(data.buffer, data.byteOffset+offset,8); const f = view.getFloat64(0,false); offset+=8; return {value:f, offset}; }
                    case 31: throw new Error('Unexpected BREAK');
                }
                throw new Error('Unknown simple/fp additional info: '+addl);
            }
        }
        throw new Error('Unknown major type: ' + major);
    }

    function decodeCbor(bytes){
        if(!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
        const out = decodeItem(bytes, 0);
        if(out.offset !== bytes.length){
            // Allow trailing whitespace? Not defined; treat as error.
            throw new Error('Extra data after top-level item at byte '+out.offset+' of '+bytes.length);
        }
        return out.value;
    }

    function decodeCborStream(bytes){
        if(!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
        let offset = 0; const values = [];
        while(offset < bytes.length){
            const r = decodeItem(bytes, offset);
            values.push(r.value);
            offset = r.offset;
        }
        return values;
    }


    function bytesToHex(u8){ return Array.from(u8).map(b=>b.toString(16).padStart(2,'0')).join(''); }
    function hexToBytes(hex){
        // Support optional leading 0x / 0X
        if(/^0x/i.test(hex.trim())) hex = hex.trim().slice(2);
    hex = Array.from(hex).filter(c => '0123456789abcdefABCDEF'.includes(c)).join('');
        if(hex.length % 2) throw new Error('Hex length must be even');
        const out = new Uint8Array(hex.length/2);
        for(let i=0;i<out.length;i++) out[i] = parseInt(hex.substr(i*2,2),16);
        return out;
    }
    function base64ToBytes(b64){
        if(typeof atob === 'undefined') throw new Error('Base64 decode not supported in this environment');
    b64 = b64.split(/\s+/).join('').split('-').join('+').split('_').join('/');
        const pad = b64.length % 4; if(pad) b64 += '='.repeat(4-pad);
        const bin = atob(b64); const out = new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i); return out;
    }

    function formatDiagnostic(value, indent=0){
        const pad = n => ' '.repeat(n);
        // Byte string -> h'HEX'
        if(value instanceof Uint8Array){
            return "h'" + bytesToHex(value).toUpperCase() + "'";
        }
        // Arrays
        if(Array.isArray(value)){
            if(value.length === 0) return '[]';
            const parts = value.map(v=> pad(indent+2) + formatDiagnostic(v, indent+2));
            return '[\n' + parts.join(',\n') + '\n' + pad(indent) + ']';
        }
        // Objects / maps / special wrappers
        if(value && typeof value === 'object'){
            if(Object.prototype.hasOwnProperty.call(value,'@tag')){
                return 'tag(' + value['@tag'] + ', ' + formatDiagnostic(value.value, indent) + ')';
            }
            if(Object.prototype.hasOwnProperty.call(value,'@simple')){
                return 'simple(' + value['@simple'] + ')';
            }
            const entries = Object.entries(value);
            if(entries.length === 0) return '{}';
            const formatted = entries.map(([k,v])=>{
                let keyOut;
                if(/^[0-9]+$/.test(k)) keyOut = k; // numeric key
                else if(/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(k)) keyOut = k; // identifier-like
                else keyOut = JSON.stringify(k);
                return pad(indent+2) + keyOut + ': ' + formatDiagnostic(v, indent+2);
            });
            return '{\n' + formatted.join(',\n') + '\n' + pad(indent) + '}';
        }
        // Primitives
        if(typeof value === 'string') return JSON.stringify(value);
        if(typeof value === 'bigint') return value.toString() + 'n';
        if(value === undefined) return 'undefined';
        return String(value);
    }

    // --- Meta decoding for nested offsets (optional UI toggle) ---
    function decodeItemMeta(data, offset){
        const start = offset;
        if(offset >= data.length) throw new Error('Unexpected end of data');
        const ib = data[offset++];
        const major = ib >> 5; const addl = ib & 0x1f;
        if(addl >= 28 && addl <= 30){
            throw new Error('Reserved additional info ' + addl + ' (byte 0x' + ib.toString(16).padStart(2,'0') + ') at offset ' + (offset-1) + ' – possible malformed CBOR or truncated prior item.');
        }
        const meta = { offset: start, major, size: 0, value: undefined };
        function finish(endOffset){ meta.size = endOffset - start; return { meta, offset: endOffset }; }
        switch(major){
            case 0: { const {len, offset:o2} = readLength(addl,data,offset); meta.value = len; return finish(o2); }
            case 1: { const {len, offset:o2} = readLength(addl,data,offset); meta.value = -1 - len; return finish(o2); }
            case 2: { const {len, offset:o2} = readLength(addl,data,offset); offset = o2; if(len === -1){ let parts=[]; while(true){ if(offset>=data.length) throw new Error('Unterminated indefinite byte string'); if(data[offset]===0xFF){ offset++; break; } const chunk = decodeItemMeta(data, offset); if(!(chunk.meta.value instanceof Uint8Array)) throw new Error('Indef bytes expect definite byte strings'); parts.push(chunk.meta.value); offset = chunk.offset; } let total=parts.reduce((a,p)=>a+p.length,0); const out=new Uint8Array(total); let pos=0; parts.forEach(p=>{out.set(p,pos); pos+=p.length;}); meta.value=out; return finish(offset);} if(offset+len>data.length) throw new Error('Truncated byte string'); meta.value = data.slice(offset, offset+len); offset += len; return finish(offset); }
            case 3: { const {len, offset:o2} = readLength(addl,data,offset); offset = o2; if(len === -1){ let chunks=[]; while(true){ if(offset>=data.length) throw new Error('Unterminated indefinite text string'); if(data[offset]===0xFF){ offset++; break; } const chunk = decodeItemMeta(data, offset); if(typeof chunk.meta.value !== 'string') throw new Error('Indef text expects definite text'); chunks.push(chunk.meta.value); offset = chunk.offset; } meta.value = chunks.join(''); return finish(offset);} if(offset+len>data.length) throw new Error('Truncated text string'); meta.value = toUtf8(data.slice(offset, offset+len)); offset += len; return finish(offset); }
            case 4: { const {len, offset:o2} = readLength(addl,data,offset); offset = o2; meta.elements=[]; if(len === -1){ while(true){ if(offset>=data.length) throw new Error('Unterminated indefinite array'); if(data[offset]===0xFF){ offset++; break; } const child = decodeItemMeta(data, offset); meta.elements.push(child.meta); offset = child.offset; } } else { for(let i=0;i<len;i++){ const child = decodeItemMeta(data, offset); meta.elements.push(child.meta); offset = child.offset; } } meta.value = meta.elements.map(c=>c.value); return finish(offset); }
            case 5: { const {len, offset:o2} = readLength(addl,data,offset); offset = o2; meta.entries=[]; let obj={}; function addPair(km, vm){ const key = (typeof km.value === 'string')? km.value : JSON.stringify(km.value); obj[key]=vm.value; meta.entries.push({ key: km, value: vm }); }
                if(len === -1){ while(true){ if(offset>=data.length) throw new Error('Unterminated indefinite map'); if(data[offset]===0xFF){ offset++; break; } const k = decodeItemMeta(data, offset); offset = k.offset; const v = decodeItemMeta(data, offset); offset = v.offset; addPair(k.meta, v.meta); } } else { for(let i=0;i<len;i++){ const k = decodeItemMeta(data, offset); offset = k.offset; const v = decodeItemMeta(data, offset); offset = v.offset; addPair(k.meta, v.meta); } }
                meta.value = obj; return finish(offset); }
            case 6: { const {len: tagNum, offset:o2} = readLength(addl,data,offset); offset = o2; const inner = decodeItemMeta(data, offset); offset = inner.offset; meta.tag = tagNum; meta.child = inner.meta; 
                // Mirror main-path semantic interpretations for common tags while preserving meta child info.
                const rawVal = inner.meta.value;
                if((tagNum === 2 || tagNum === 3) && rawVal instanceof Uint8Array){
                    let bn=0n; for(const b of rawVal){ bn = (bn<<8n) | BigInt(b); } if(tagNum===3) bn = -1n - bn; meta.value = bn; return finish(offset);
                }
                if(tagNum === 0 && typeof rawVal === 'string'){ meta.value = { '@datetime': rawVal }; return finish(offset); }
                if(tagNum === 1 && (typeof rawVal === 'number' || typeof rawVal === 'bigint')){
                    let secs = rawVal; let iso; try { if(typeof secs === 'bigint'){ const msBig = secs*1000n; if(msBig <= BigInt(Number.MAX_SAFE_INTEGER) && msBig >= BigInt(Number.MIN_SAFE_INTEGER)) iso = new Date(Number(msBig)).toISOString(); else iso = secs.toString() + 's'; } else { iso = new Date(secs*1000).toISOString(); } } catch{ iso = String(secs);} meta.value = { '@epoch': secs, '@iso': iso }; return finish(offset);
                }
                if(tagNum === 24 && rawVal instanceof Uint8Array){ let embedded; try { embedded = decodeCbor(rawVal); } catch(e){ embedded = { '@error': 'Embedded decode failed: ' + e.message, '@bytes': bytesToHex(rawVal) }; } meta.value = { '@embedded': embedded }; return finish(offset); }
                if(tagNum === 32 && typeof rawVal === 'string'){ meta.value = { '@uri': rawVal }; return finish(offset); }
                if(tagNum === 33 && typeof rawVal === 'string'){ meta.value = { '@base64url': rawVal }; return finish(offset); }
                if(tagNum === 34 && typeof rawVal === 'string'){ meta.value = { '@base64': rawVal }; return finish(offset); }
                if(tagNum === 35 && typeof rawVal === 'string'){ meta.value = { '@regex': rawVal }; return finish(offset); }
                if(tagNum === 36 && typeof rawVal === 'string'){ meta.value = { '@mime': rawVal }; return finish(offset); }
                meta.value = { '@tag': tagNum, value: rawVal }; return finish(offset); }
            // Meta decoding now interprets bignum/date/embedded/URI/base64/regex/mime tags similar to primary decode.
            case 7: { if(addl < 20){ meta.value = {'@simple': addl}; return finish(offset);} switch(addl){ case 20: meta.value=false; return finish(offset); case 21: meta.value=true; return finish(offset); case 22: meta.value=null; return finish(offset); case 23: meta.value=undefined; return finish(offset); case 24: { if(offset>=data.length) throw new Error('Truncated simple'); meta.value={'@simple': data[offset++]}; return finish(offset);} case 25: { if(offset+2>data.length) throw new Error('Truncated half float'); meta.value=readHalfFloat(data.slice(offset, offset+2)); offset+=2; return finish(offset);} case 26: { if(offset+4>data.length) throw new Error('Truncated float32'); meta.value=new DataView(data.buffer,data.byteOffset+offset,4).getFloat32(0,false); offset+=4; return finish(offset);} case 27: { if(offset+8>data.length) throw new Error('Truncated float64'); meta.value=new DataView(data.buffer,data.byteOffset+offset,8).getFloat64(0,false); offset+=8; return finish(offset);} case 31: throw new Error('Unexpected BREAK'); }
                throw new Error('Unknown simple/fp additional info: '+addl); }
        }
        throw new Error('Unknown major '+major);
    }

    function decodeCborStreamTreeMeta(bytes){
        if(!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
        let offset=0; const roots=[]; while(offset < bytes.length){ const r = decodeItemMeta(bytes, offset); roots.push(r.meta); offset = r.offset; } return roots;
    }

    function formatMeta(meta, options, indent=0){
        const { nestedOffsets } = options; // only nestedOffsets now used
        const pad = n => ' '.repeat(n);
        const prefix = (nestedOffsets ? `@${meta.offset}+${meta.size} ` : '');
        // Byte string
        if(meta.value instanceof Uint8Array){ return prefix + "h'" + bytesToHex(meta.value).toUpperCase() + "'"; }
        if(meta.tag !== undefined){
            const inner = formatMeta(meta.child, options, indent + (mode==='pretty'?2:0));
            return prefix + 'tag(' + meta.tag + ', ' + inner + ')';
        }
        if(Array.isArray(meta.elements)){
            if(meta.elements.length === 0) return prefix + '[]';
            const lines = meta.elements.map(m=> pad(indent+2) + formatMeta(m, options, indent+2));
            return prefix + '[\n' + lines.join(',\n') + '\n' + pad(indent) + ']';
        }
        if(Array.isArray(meta.entries)){
            if(meta.entries.length === 0) return prefix + '{}';
            const lines = meta.entries.map(e=>{
                const k = formatMapKey(e.key.value);
                return pad(indent+2) + k + ': ' + formatMeta(e.value, options, indent+2);
            });
            return prefix + '{\n' + lines.join(',\n') + '\n' + pad(indent) + '}';
        }
        if(typeof meta.value === 'string') return prefix + JSON.stringify(meta.value);
        if(typeof meta.value === 'bigint') return prefix + meta.value.toString() + 'n';
        if(meta.value && typeof meta.value === 'object' && meta.value['@simple'] !== undefined) return prefix + 'simple(' + meta.value['@simple'] + ')';
        return prefix + String(meta.value);
    }

    function formatMapKey(k){
        if(typeof k === 'string'){
            if(/^[0-9]+$/.test(k)) return k; // numeric string
            if(/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(k)) return k;
            return JSON.stringify(k);
        }
        return JSON.stringify(k);
    }

    function formatMetaRoots(roots, options){
        if(roots.length === 1) return formatMeta(roots[0], options, 0);
        const lines = roots.map(r=> '  ' + formatMeta(r, options,2));
        return '[\n' + lines.join(',\n') + '\n]';
    }

    global.CBORPlayground = { decodeCbor, decodeCborStream, hexToBytes, base64ToBytes, bytesToHex, formatDiagnostic, decodeCborStreamTreeMeta: decodeCborStreamTreeMeta, formatMetaRoots };
    // ---------------- Encoding Support ----------------
    function encodeUnsigned(num){
        if(num < 24) return Uint8Array.of(num);
        if(num < 0x100) return Uint8Array.of(0x18, num);
        if(num < 0x10000) return concat(Uint8Array.of(0x19), u16(num));
        if(num < 0x100000000) return concat(Uint8Array.of(0x1a), u32(num));
        const bn = BigInt(num);
        return concat(Uint8Array.of(0x1b), u64(bn));
    }
    function encodeNegative(num){
        // CBOR negative: -1 - n encoded as unsigned n
        const n = -1 - num;
        const head = encodeUnsigned(n);
        head[0] |= 0x20; // set major type 1
        return head;
    }
    function u16(v){ return Uint8Array.of((v>>8)&0xff, v&0xff); }
    function u32(v){ return Uint8Array.of((v>>>24)&0xff,(v>>>16)&0xff,(v>>>8)&0xff,v&0xff); }
    function u64(v){ let bn=BigInt(v); const out=new Uint8Array(8); for(let i=7;i>=0;i--){ out[i]=Number(bn & 0xffn); bn >>= 8n;} return out; }
    function concat(){
        let total = 0; for(const a of arguments) total += a.length; const out = new Uint8Array(total); let o=0; for(const a of arguments){ out.set(a,o); o+=a.length;} return out;
    }
    function encodeBytes(u8){
        const len = encodeLength(2, u8.length); return concat(len, u8);
    }
    function encodeText(str){
        const enc = typeof TextEncoder !== 'undefined' ? new TextEncoder() : { encode: s => { const arr = new Uint8Array(s.length); for(let i=0;i<s.length;i++) arr[i]=s.charCodeAt(i); return arr; } };
        const bytes = enc.encode(str);
        const len = encodeLength(3, bytes.length); return concat(len, bytes);
    }
    function encodeArray(arr){
        const head = encodeLength(4, arr.length); const parts = [head];
        for(const v of arr) parts.push(encodeAny(v));
        return concat.apply(null, parts);
    }
    function encodeMap(obj){
        let entries = Object.entries(obj);
        // Optional canonical ordering per RFC 8949 Section 4.2: sort by length of encoded key, then lexicographically.
        // We approximate by encoding the map key and comparing the resulting byte arrays.
        if(global.CBORPlayground && global.CBORPlayground.canonicalSortMapKeys){
            entries = entries.slice().sort((a,b)=>{
                const ka = encodeAny(mapKeyToCborKey(a[0]));
                const kb = encodeAny(mapKeyToCborKey(b[0]));
                if(ka.length !== kb.length) return ka.length - kb.length;
                for(let i=0;i<ka.length && i<kb.length;i++){
                    if(ka[i] !== kb[i]) return ka[i] - kb[i];
                }
                return 0;
            });
        }
        const head = encodeLength(5, entries.length); const parts=[head];
        for(const [k,v] of entries){ parts.push(encodeAny(mapKeyToCborKey(k)), encodeAny(v)); }
        return concat.apply(null, parts);
    }
    function mapKeyToCborKey(k){
        // Attempt numeric if optional leading minus sign and decimal digits only (supports negative integer map keys)
        if(/^-?[0-9]+$/.test(k)){
            const n = Number(k); if(Number.isSafeInteger(n)) return n;
        }
        return k; // fallback to string
    }
    function encodeTag(tagNum, value){
        const tagHead = encodeLength(6, tagNum);
        return concat(tagHead, encodeAny(value));
    }
    function encodeSimple(n){
        if(n < 24) return Uint8Array.of(0xe0 | n);
        return Uint8Array.of(0xf8, n & 0xff);
    }
    function encodeFloat64(num){
        const buf = new ArrayBuffer(8); const view = new DataView(buf); view.setFloat64(0, num, false); const arr = new Uint8Array(buf); return concat(Uint8Array.of(0xfb), arr);
    }
    function encodeLength(major, len){
        if(len < 24) return Uint8Array.of((major<<5) | len);
        if(len < 0x100) return Uint8Array.of((major<<5)|24, len);
        if(len < 0x10000) return concat(Uint8Array.of((major<<5)|25), u16(len));
        if(len < 0x100000000) return concat(Uint8Array.of((major<<5)|26), u32(len));
        return concat(Uint8Array.of((major<<5)|27), u64(len));
    }
    function encodeBigInt(bn){
        if(bn >= 0n){
            if(bn <= BigInt(Number.MAX_SAFE_INTEGER)) return encodeUnsigned(Number(bn));
            // Tag 2 (positive bignum) with byte string big-endian
            let tmp = bn; const bytes=[]; while(tmp > 0){ bytes.push(Number(tmp & 0xffn)); tmp >>= 8n; } bytes.reverse();
            const bstr = Uint8Array.from(bytes);
            return encodeTag(2, bstr);
        } else {
            const pos = -1n - bn; // convert to n for negative representation
            if(pos <= BigInt(Number.MAX_SAFE_INTEGER)) return encodeNegative(Number(-1n - pos));
            let tmp = pos; const bytes=[]; while(tmp > 0){ bytes.push(Number(tmp & 0xffn)); tmp >>= 8n; } bytes.reverse();
            const bstr = Uint8Array.from(bytes);
            return encodeTag(3, bstr); // Negative bignum tag 3
        }
    }
    function encodeAny(value){
        if(value === null) return Uint8Array.of(0xf6);
        if(value === undefined) return Uint8Array.of(0xf7);
        if(typeof value === 'boolean') return Uint8Array.of(value ? 0xf5 : 0xf4);
        if(typeof value === 'number'){
            if(Number.isInteger(value)){
                if(value >= 0) return encodeUnsigned(value);
                return encodeNegative(value);
            }
            return encodeFloat64(value);
        }
        if(typeof value === 'bigint') return encodeBigInt(value);
        if(value instanceof Uint8Array) return encodeBytes(value);
        if(typeof value === 'string') return encodeText(value);
        if(Array.isArray(value)) return encodeArray(value);
        if(value && typeof value === 'object'){
            // Tag object form {"@tag":N, value: X}
            if(Object.prototype.hasOwnProperty.call(value, '@tag') && Object.prototype.hasOwnProperty.call(value, 'value')){
                return encodeTag(value['@tag'], value['value']);
            }
            // Simple value {"@simple":n}
            if(Object.prototype.hasOwnProperty.call(value,'@simple')) return encodeSimple(value['@simple']);
            // Bigint encoded object {"@bigint":"..."}
            if(Object.prototype.hasOwnProperty.call(value,'@bigint')) return encodeBigInt(BigInt(value['@bigint']));
            // Byte string encoded object {"@bytes":"HEX"}
            if(Object.prototype.hasOwnProperty.call(value,'@bytes')) return encodeBytes(hexToBytes(value['@bytes']));
            return encodeMap(value);
        }
        throw new Error('Unsupported type for encoding');
    }

    function exportValue(value){
        // Convert runtime structure into export-friendly JSON with markers
        if(value instanceof Uint8Array) return { '@bytes': bytesToHex(value) };
        if(typeof value === 'bigint') return { '@bigint': value.toString() };
        if(value && typeof value === 'object'){
            if(Object.prototype.hasOwnProperty.call(value,'@tag')) return { '@tag': value['@tag'], value: exportValue(value.value) };
            if(Object.prototype.hasOwnProperty.call(value,'@simple')) return { '@simple': value['@simple'] };
            if(Array.isArray(value)) return value.map(exportValue);
            const obj={}; for(const [k,v] of Object.entries(value)) obj[k]=exportValue(v); return obj;
        }
        return value; // number, boolean, null, undefined (undefined preserved as null?)
    }
    function importValue(exp){
        if(exp && typeof exp === 'object'){
            if(exp['@bytes']) return hexToBytes(exp['@bytes']);
            if(exp['@bigint']) return BigInt(exp['@bigint']);
            if(exp['@tag'] !== undefined) return { '@tag': exp['@tag'], value: importValue(exp.value) };
            if(exp['@simple'] !== undefined) return { '@simple': exp['@simple'] };
            if(Array.isArray(exp)) return exp.map(importValue);
            const obj={}; for(const [k,v] of Object.entries(exp)) obj[k]=importValue(v); return obj;
        }
        return exp;
    }

    function encodeValues(values){
        const parts = values.map(encodeAny); return concat.apply(null, parts);
    }

    // Augment export
    global.CBORPlayground.encodeAny = encodeAny;
    global.CBORPlayground.exportValue = exportValue;
    global.CBORPlayground.importValue = importValue;
    global.CBORPlayground.encodeValues = encodeValues;
    global.CBORPlayground.canonicalSortMapKeys = false; // default disabled; UI can toggle
})(typeof window !== 'undefined' ? window : globalThis);
