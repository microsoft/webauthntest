// Lightweight CBOR decoder for playground purposes.
// Supports RFC 8949 major types: unsigned, negative, byte/text strings, arrays, maps, tags, simple + floats.
// Indefinite-length items are partially supported (arrays/maps/strings) until break (0xFF).
// NOT for production security-critical parsing.

(function(global){
    class CborMap {
        constructor(entries){
            this.entries = entries.map(([k, v]) => [k, v]);
        }
    }

    function isCborMap(value){
        return value instanceof CborMap;
    }

    function indentBlock(text, indent){
        const padding = ' '.repeat(indent);
        return text.split('\n').map(line => padding + line).join('\n');
    }

    function inlineSummary(text){
        return text.replace(/\s+/g, ' ').trim();
    }

    function formatIntegerHex(num){
        if(Object.is(num, -0)) return '-0x0';
        if(num === 0) return '0x0';
        const sign = num < 0 ? '-' : '';
        const absHex = Math.abs(num).toString(16).toUpperCase();
        return sign + '0x' + absHex;
    }

    function formatBigIntHex(bn){
        if(bn === 0n) return '0x0n';
        const sign = bn < 0n ? '-' : '';
        const absHex = (bn < 0n ? -bn : bn).toString(16).toUpperCase();
        return sign + '0x' + absHex + 'n';
    }
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
                const entries = [];
                function readPair(){
                    const k = decodeItem(data, offset); offset = k.offset;
                    const v = decodeItem(data, offset); offset = v.offset;
                    entries.push([k.value, v.value]);
                }
                if(len === -1){
                    while(true){
                        if(offset >= data.length) throw new Error('Unterminated indefinite map');
                        if(data[offset] === 0xFF){ offset++; break; }
                        readPair();
                    }
                } else {
                    for(let i=0;i<len;i++) readPair();
                }
                return {value: new CborMap(entries), offset};
            }
            case 6: { // tag
                const {len: tagNum, offset: o2} = readLength(addl, data, offset); offset = o2;
                const tagged = decodeItem(data, offset); offset = tagged.offset;
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
        hex = hex.replace(/[^0-9a-fA-F]/g,'');
        if(hex.length % 2) throw new Error('Hex length must be even');
        const out = new Uint8Array(hex.length/2);
        for(let i=0;i<out.length;i++) out[i] = parseInt(hex.substr(i*2,2),16);
        return out;
    }
    function base64ToBytes(b64){
        if(typeof atob === 'undefined') throw new Error('Base64 decode not supported in this environment');
        b64 = b64.replace(/\s+/g,'').replace(/-/g,'+').replace(/_/g,'/');
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
        if(isCborMap(value)){
            if(value.entries.length === 0) return '{}';
            const formatted = value.entries.map(([k, v]) => {
                const keyInline = inlineSummary(formatDiagnostic(k, indent+2));
                const valStr = formatDiagnostic(v, indent+2);
                if(valStr.indexOf('\n') !== -1){
                    const indentedVal = indentBlock(valStr, indent+4);
                    return pad(indent+2) + keyInline + ' =>\n' + indentedVal;
                }
                return pad(indent+2) + keyInline + ' => ' + valStr;
            });
            return '{\n' + formatted.join(',\n') + '\n' + pad(indent) + '}';
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
        if(typeof value === 'number'){
            if(Number.isInteger(value)) return formatIntegerHex(value);
            return String(value);
        }
        if(typeof value === 'bigint') return formatBigIntHex(value);
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
            case 5: { const {len, offset:o2} = readLength(addl,data,offset); offset = o2; meta.entries=[];
                function addPair(km, vm){ meta.entries.push({ key: km, value: vm }); }
                if(len === -1){ while(true){ if(offset>=data.length) throw new Error('Unterminated indefinite map'); if(data[offset]===0xFF){ offset++; break; } const k = decodeItemMeta(data, offset); offset = k.offset; const v = decodeItemMeta(data, offset); offset = v.offset; addPair(k.meta, v.meta); } }
                else { for(let i=0;i<len;i++){ const k = decodeItemMeta(data, offset); offset = k.offset; const v = decodeItemMeta(data, offset); offset = v.offset; addPair(k.meta, v.meta); } }
                meta.value = new CborMap(meta.entries.map(e => [e.key.value, e.value.value]));
                return finish(offset); }
            case 6: { const {len: tagNum, offset:o2} = readLength(addl,data,offset); offset = o2; const inner = decodeItemMeta(data, offset); offset = inner.offset; meta.tag = tagNum; meta.child = inner.meta; meta.value = { '@tag': tagNum, value: inner.meta.value }; return finish(offset); }
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
            const inner = formatMeta(meta.child, options, indent + 2);
            return prefix + 'tag(' + meta.tag + ', ' + inner + ')';
        }
        if(Array.isArray(meta.elements)){
            if(meta.elements.length === 0) return prefix + '[]';
            const lines = meta.elements.map(m=> pad(indent+2) + formatMeta(m, options, indent+2));
            return prefix + '[\n' + lines.join(',\n') + '\n' + pad(indent) + ']';
        }
        if(isCborMap(meta.value)){
            const entries = meta.entries || [];
            if(entries.length === 0) return prefix + '{}';
            const lines = entries.map(e=>{
                const keyInline = inlineSummary(formatMeta(e.key, options, indent+2));
                const valueStr = formatMeta(e.value, options, indent+2);
                if(valueStr.indexOf('\n') !== -1){
                    const indented = indentBlock(valueStr, indent+4);
                    return pad(indent+2) + keyInline + ' =>\n' + indented;
                }
                return pad(indent+2) + keyInline + ' => ' + valueStr;
            });
            return prefix + '{\n' + lines.join(',\n') + '\n' + pad(indent) + '}';
        }
        if(typeof meta.value === 'string') return prefix + JSON.stringify(meta.value);
        if(typeof meta.value === 'number'){
            if(Number.isInteger(meta.value)) return prefix + formatIntegerHex(meta.value);
        }
        if(typeof meta.value === 'bigint') return prefix + formatBigIntHex(meta.value);
        if(meta.value && typeof meta.value === 'object' && meta.value['@simple'] !== undefined) return prefix + 'simple(' + meta.value['@simple'] + ')';
        return prefix + String(meta.value);
    }

    function formatMetaRoots(roots, options){
        if(roots.length === 1) return formatMeta(roots[0], options, 0);
        const lines = roots.map(r=> '  ' + formatMeta(r, options,2));
        return '[\n' + lines.join(',\n') + '\n]';
    }

    global.CBORPlayground = { decodeCbor, decodeCborStream, hexToBytes, base64ToBytes, bytesToHex, formatDiagnostic, decodeCborStreamTreeMeta: decodeCborStreamTreeMeta, formatMetaRoots, CborMap };
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
    function encodeMap(mapLike){
        let entries;
        if(isCborMap(mapLike)){
            entries = mapLike.entries.map(([k, v]) => [k, v]);
        } else if(Array.isArray(mapLike)){
            entries = mapLike.map(([k, v]) => [k, v]);
        } else {
            entries = Object.entries(mapLike).map(([k, v]) => [mapKeyToCborKey(k), v]);
        }
        const head = encodeLength(5, entries.length); const parts=[head];
        for(const [k,v] of entries){ parts.push(encodeAny(k), encodeAny(v)); }
        return concat.apply(null, parts);
    }
    function mapKeyToCborKey(k){
        // Attempt numeric if decimal digits only
        if(/^[0-9]+$/.test(k)){
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
        if(isCborMap(value)) return encodeMap(value);
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
        if(isCborMap(value)) return { '@map': value.entries.map(([k, v]) => [exportValue(k), exportValue(v)]) };
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
            if(exp['@map']) return new CborMap(exp['@map'].map(([k, v]) => [importValue(k), importValue(v)]));
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
})(typeof window !== 'undefined' ? window : globalThis);
