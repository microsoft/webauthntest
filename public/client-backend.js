// src/lib/base64.js
var textEncoder = new TextEncoder();
function utf8ToBytes(str) {
  return textEncoder.encode(String(str));
}
function bytesToHex(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let out = "";
  for (let i = 0; i < u8.length; i++) out += u8[i].toString(16).padStart(2, "0");
  return out.toUpperCase();
}
function bytesToBase64Url(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = "";
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  const b64 = btoa(bin);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function bytesToBase64(bytes) {
  let b64 = bytesToBase64Url(bytes).replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  return b64;
}
function base64UrlToBytes(b64u) {
  const s = String(b64u || "").replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4 ? "=".repeat(4 - s.length % 4) : "";
  const b64 = s + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function base64ToBytes(b64) {
  return base64UrlToBytes(normalizeBase64Url(b64));
}
function normalizeBase64Url(b64u) {
  let s = String(b64u || "").trim();
  s = s.replace(/\+/g, "-").replace(/\//g, "_");
  s = s.replace(/=+$/g, "");
  return s;
}

// src/lib/crypto.js
async function sha256Bytes(dataBytes) {
  const digest = await crypto.subtle.digest("SHA-256", dataBytes);
  return new Uint8Array(digest);
}
async function sha256Utf8(str) {
  return sha256Bytes(utf8ToBytes(str));
}
async function hmacSha256Base64Url(secret, dataBytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    utf8ToBytes(String(secret)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, dataBytes);
  return bytesToBase64Url(new Uint8Array(sig));
}

// src/lib/uid.js
function normalizeUsername(username) {
  return String(username || "").trim().toLowerCase();
}
async function hashUsername(username, uidHashSecret) {
  const normalized = normalizeUsername(username);
  if (uidHashSecret && String(uidHashSecret).length > 0) {
    const sigB64u = await hmacSha256Base64Url(String(uidHashSecret), utf8ToBytes(normalized));
    const bytes = base64UrlToBytes(sigB64u);
    return bytesToHex(bytes);
  }
  const digest = await sha256Utf8(normalized);
  return bytesToHex(digest);
}

// node_modules/cbor-x/decode.js
var decoder;
try {
  decoder = new TextDecoder();
} catch (error) {
}
var src;
var srcEnd;
var position = 0;
var EMPTY_ARRAY = [];
var LEGACY_RECORD_INLINE_ID = 105;
var RECORD_DEFINITIONS_ID = 57342;
var RECORD_INLINE_ID = 57343;
var BUNDLED_STRINGS_ID = 57337;
var PACKED_REFERENCE_TAG_ID = 6;
var STOP_CODE = {};
var maxArraySize = 11281e4;
var maxMapSize = 1681e4;
var strings = EMPTY_ARRAY;
var stringPosition = 0;
var currentDecoder = {};
var currentStructures;
var srcString;
var srcStringStart = 0;
var srcStringEnd = 0;
var bundledStrings;
var referenceMap;
var currentExtensions = [];
var currentExtensionRanges = [];
var packedValues;
var dataView;
var restoreMapsAsObject;
var defaultOptions = {
  useRecords: false,
  mapsAsObjects: true
};
var sequentialMode = false;
var inlineObjectReadThreshold = 2;
try {
  new Function("");
} catch (error) {
  inlineObjectReadThreshold = Infinity;
}
var Decoder = class _Decoder {
  constructor(options) {
    if (options) {
      if ((options.keyMap || options._keyMap) && !options.useRecords) {
        options.useRecords = false;
        options.mapsAsObjects = true;
      }
      if (options.useRecords === false && options.mapsAsObjects === void 0)
        options.mapsAsObjects = true;
      if (options.getStructures)
        options.getShared = options.getStructures;
      if (options.getShared && !options.structures)
        (options.structures = []).uninitialized = true;
      if (options.keyMap) {
        this.mapKey = /* @__PURE__ */ new Map();
        for (let [k, v] of Object.entries(options.keyMap)) this.mapKey.set(v, k);
      }
    }
    Object.assign(this, options);
  }
  /*
  decodeKey(key) {
  	return this.keyMap
  		? Object.keys(this.keyMap)[Object.values(this.keyMap).indexOf(key)] || key
  		: key
  }
  */
  decodeKey(key) {
    return this.keyMap ? this.mapKey.get(key) || key : key;
  }
  encodeKey(key) {
    return this.keyMap && this.keyMap.hasOwnProperty(key) ? this.keyMap[key] : key;
  }
  encodeKeys(rec) {
    if (!this._keyMap) return rec;
    let map = /* @__PURE__ */ new Map();
    for (let [k, v] of Object.entries(rec)) map.set(this._keyMap.hasOwnProperty(k) ? this._keyMap[k] : k, v);
    return map;
  }
  decodeKeys(map) {
    if (!this._keyMap || map.constructor.name != "Map") return map;
    if (!this._mapKey) {
      this._mapKey = /* @__PURE__ */ new Map();
      for (let [k, v] of Object.entries(this._keyMap)) this._mapKey.set(v, k);
    }
    let res = {};
    map.forEach((v, k) => res[safeKey(this._mapKey.has(k) ? this._mapKey.get(k) : k)] = v);
    return res;
  }
  mapDecode(source, end) {
    let res = this.decode(source);
    if (this._keyMap) {
      switch (res.constructor.name) {
        case "Array":
          return res.map((r) => this.decodeKeys(r));
      }
    }
    return res;
  }
  decode(source, end) {
    if (src) {
      return saveState(() => {
        clearSource();
        return this ? this.decode(source, end) : _Decoder.prototype.decode.call(defaultOptions, source, end);
      });
    }
    srcEnd = end > -1 ? end : source.length;
    position = 0;
    stringPosition = 0;
    srcStringEnd = 0;
    srcString = null;
    strings = EMPTY_ARRAY;
    bundledStrings = null;
    src = source;
    try {
      dataView = source.dataView || (source.dataView = new DataView(source.buffer, source.byteOffset, source.byteLength));
    } catch (error) {
      src = null;
      if (source instanceof Uint8Array)
        throw error;
      throw new Error("Source must be a Uint8Array or Buffer but was a " + (source && typeof source == "object" ? source.constructor.name : typeof source));
    }
    if (this instanceof _Decoder) {
      currentDecoder = this;
      packedValues = this.sharedValues && (this.pack ? new Array(this.maxPrivatePackedValues || 16).concat(this.sharedValues) : this.sharedValues);
      if (this.structures) {
        currentStructures = this.structures;
        return checkedRead();
      } else if (!currentStructures || currentStructures.length > 0) {
        currentStructures = [];
      }
    } else {
      currentDecoder = defaultOptions;
      if (!currentStructures || currentStructures.length > 0)
        currentStructures = [];
      packedValues = null;
    }
    return checkedRead();
  }
  decodeMultiple(source, forEach) {
    let values, lastPosition = 0;
    try {
      let size = source.length;
      sequentialMode = true;
      let value = this ? this.decode(source, size) : defaultDecoder.decode(source, size);
      if (forEach) {
        if (forEach(value) === false) {
          return;
        }
        while (position < size) {
          lastPosition = position;
          if (forEach(checkedRead()) === false) {
            return;
          }
        }
      } else {
        values = [value];
        while (position < size) {
          lastPosition = position;
          values.push(checkedRead());
        }
        return values;
      }
    } catch (error) {
      error.lastPosition = lastPosition;
      error.values = values;
      throw error;
    } finally {
      sequentialMode = false;
      clearSource();
    }
  }
};
function checkedRead() {
  try {
    let result = read();
    if (bundledStrings) {
      if (position >= bundledStrings.postBundlePosition) {
        let error = new Error("Unexpected bundle position");
        error.incomplete = true;
        throw error;
      }
      position = bundledStrings.postBundlePosition;
      bundledStrings = null;
    }
    if (position == srcEnd) {
      currentStructures = null;
      src = null;
      if (referenceMap)
        referenceMap = null;
    } else if (position > srcEnd) {
      let error = new Error("Unexpected end of CBOR data");
      error.incomplete = true;
      throw error;
    } else if (!sequentialMode) {
      throw new Error("Data read, but end of buffer not reached");
    }
    return result;
  } catch (error) {
    clearSource();
    if (error instanceof RangeError || error.message.startsWith("Unexpected end of buffer")) {
      error.incomplete = true;
    }
    throw error;
  }
}
function read() {
  let token = src[position++];
  let majorType = token >> 5;
  token = token & 31;
  if (token > 23) {
    switch (token) {
      case 24:
        token = src[position++];
        break;
      case 25:
        if (majorType == 7) {
          return getFloat16();
        }
        token = dataView.getUint16(position);
        position += 2;
        break;
      case 26:
        if (majorType == 7) {
          let value = dataView.getFloat32(position);
          if (currentDecoder.useFloat32 > 2) {
            let multiplier = mult10[(src[position] & 127) << 1 | src[position + 1] >> 7];
            position += 4;
            return (multiplier * value + (value > 0 ? 0.5 : -0.5) >> 0) / multiplier;
          }
          position += 4;
          return value;
        }
        token = dataView.getUint32(position);
        position += 4;
        break;
      case 27:
        if (majorType == 7) {
          let value = dataView.getFloat64(position);
          position += 8;
          return value;
        }
        if (majorType > 1) {
          if (dataView.getUint32(position) > 0)
            throw new Error("JavaScript does not support arrays, maps, or strings with length over 4294967295");
          token = dataView.getUint32(position + 4);
        } else if (currentDecoder.int64AsNumber) {
          token = dataView.getUint32(position) * 4294967296;
          token += dataView.getUint32(position + 4);
        } else
          token = dataView.getBigUint64(position);
        position += 8;
        break;
      case 31:
        switch (majorType) {
          case 2:
          // byte string
          case 3:
            throw new Error("Indefinite length not supported for byte or text strings");
          case 4:
            let array = [];
            let value, i = 0;
            while ((value = read()) != STOP_CODE) {
              if (i >= maxArraySize) throw new Error(`Array length exceeds ${maxArraySize}`);
              array[i++] = value;
            }
            return majorType == 4 ? array : majorType == 3 ? array.join("") : Buffer.concat(array);
          case 5:
            let key;
            if (currentDecoder.mapsAsObjects) {
              let object = {};
              let i2 = 0;
              if (currentDecoder.keyMap) {
                while ((key = read()) != STOP_CODE) {
                  if (i2++ >= maxMapSize) throw new Error(`Property count exceeds ${maxMapSize}`);
                  object[safeKey(currentDecoder.decodeKey(key))] = read();
                }
              } else {
                while ((key = read()) != STOP_CODE) {
                  if (i2++ >= maxMapSize) throw new Error(`Property count exceeds ${maxMapSize}`);
                  object[safeKey(key)] = read();
                }
              }
              return object;
            } else {
              if (restoreMapsAsObject) {
                currentDecoder.mapsAsObjects = true;
                restoreMapsAsObject = false;
              }
              let map = /* @__PURE__ */ new Map();
              if (currentDecoder.keyMap) {
                let i2 = 0;
                while ((key = read()) != STOP_CODE) {
                  if (i2++ >= maxMapSize) {
                    throw new Error(`Map size exceeds ${maxMapSize}`);
                  }
                  map.set(currentDecoder.decodeKey(key), read());
                }
              } else {
                let i2 = 0;
                while ((key = read()) != STOP_CODE) {
                  if (i2++ >= maxMapSize) {
                    throw new Error(`Map size exceeds ${maxMapSize}`);
                  }
                  map.set(key, read());
                }
              }
              return map;
            }
          case 7:
            return STOP_CODE;
          default:
            throw new Error("Invalid major type for indefinite length " + majorType);
        }
      default:
        throw new Error("Unknown token " + token);
    }
  }
  switch (majorType) {
    case 0:
      return token;
    case 1:
      return ~token;
    case 2:
      return readBin(token);
    case 3:
      if (srcStringEnd >= position) {
        return srcString.slice(position - srcStringStart, (position += token) - srcStringStart);
      }
      if (srcStringEnd == 0 && srcEnd < 140 && token < 32) {
        let string = token < 16 ? shortStringInJS(token) : longStringInJS(token);
        if (string != null)
          return string;
      }
      return readFixedString(token);
    case 4:
      if (token >= maxArraySize) throw new Error(`Array length exceeds ${maxArraySize}`);
      let array = new Array(token);
      for (let i = 0; i < token; i++) array[i] = read();
      return array;
    case 5:
      if (token >= maxMapSize) throw new Error(`Map size exceeds ${maxArraySize}`);
      if (currentDecoder.mapsAsObjects) {
        let object = {};
        if (currentDecoder.keyMap) for (let i = 0; i < token; i++) object[safeKey(currentDecoder.decodeKey(read()))] = read();
        else for (let i = 0; i < token; i++) object[safeKey(read())] = read();
        return object;
      } else {
        if (restoreMapsAsObject) {
          currentDecoder.mapsAsObjects = true;
          restoreMapsAsObject = false;
        }
        let map = /* @__PURE__ */ new Map();
        if (currentDecoder.keyMap) for (let i = 0; i < token; i++) map.set(currentDecoder.decodeKey(read()), read());
        else for (let i = 0; i < token; i++) map.set(read(), read());
        return map;
      }
    case 6:
      if (token >= BUNDLED_STRINGS_ID) {
        let structure = currentStructures[token & 8191];
        if (structure) {
          if (!structure.read) structure.read = createStructureReader(structure);
          return structure.read();
        }
        if (token < 65536) {
          if (token == RECORD_INLINE_ID) {
            let length = readJustLength();
            let id2 = read();
            let structure2 = read();
            recordDefinition(id2, structure2);
            let object = {};
            if (currentDecoder.keyMap) for (let i = 2; i < length; i++) {
              let key = currentDecoder.decodeKey(structure2[i - 2]);
              object[safeKey(key)] = read();
            }
            else for (let i = 2; i < length; i++) {
              let key = structure2[i - 2];
              object[safeKey(key)] = read();
            }
            return object;
          } else if (token == RECORD_DEFINITIONS_ID) {
            let length = readJustLength();
            let id2 = read();
            for (let i = 2; i < length; i++) {
              recordDefinition(id2++, read());
            }
            return read();
          } else if (token == BUNDLED_STRINGS_ID) {
            return readBundleExt();
          }
          if (currentDecoder.getShared) {
            loadShared();
            structure = currentStructures[token & 8191];
            if (structure) {
              if (!structure.read)
                structure.read = createStructureReader(structure);
              return structure.read();
            }
          }
        }
      }
      let extension = currentExtensions[token];
      if (extension) {
        if (extension.handlesRead)
          return extension(read);
        else
          return extension(read());
      } else {
        let input = read();
        for (let i = 0; i < currentExtensionRanges.length; i++) {
          let value = currentExtensionRanges[i](token, input);
          if (value !== void 0)
            return value;
        }
        return new Tag(input, token);
      }
    case 7:
      switch (token) {
        case 20:
          return false;
        case 21:
          return true;
        case 22:
          return null;
        case 23:
          return;
        // undefined
        case 31:
        default:
          let packedValue = (packedValues || getPackedValues())[token];
          if (packedValue !== void 0)
            return packedValue;
          throw new Error("Unknown token " + token);
      }
    default:
      if (isNaN(token)) {
        let error = new Error("Unexpected end of CBOR data");
        error.incomplete = true;
        throw error;
      }
      throw new Error("Unknown CBOR token " + token);
  }
}
var validName = /^[a-zA-Z_$][a-zA-Z\d_$]*$/;
function createStructureReader(structure) {
  if (!structure) throw new Error("Structure is required in record definition");
  function readObject() {
    let length = src[position++];
    length = length & 31;
    if (length > 23) {
      switch (length) {
        case 24:
          length = src[position++];
          break;
        case 25:
          length = dataView.getUint16(position);
          position += 2;
          break;
        case 26:
          length = dataView.getUint32(position);
          position += 4;
          break;
        default:
          throw new Error("Expected array header, but got " + src[position - 1]);
      }
    }
    let compiledReader = this.compiledReader;
    while (compiledReader) {
      if (compiledReader.propertyCount === length)
        return compiledReader(read);
      compiledReader = compiledReader.next;
    }
    if (this.slowReads++ >= inlineObjectReadThreshold) {
      let array = this.length == length ? this : this.slice(0, length);
      compiledReader = currentDecoder.keyMap ? new Function("r", "return {" + array.map((k) => currentDecoder.decodeKey(k)).map((k) => validName.test(k) ? safeKey(k) + ":r()" : "[" + JSON.stringify(k) + "]:r()").join(",") + "}") : new Function("r", "return {" + array.map((key) => validName.test(key) ? safeKey(key) + ":r()" : "[" + JSON.stringify(key) + "]:r()").join(",") + "}");
      if (this.compiledReader)
        compiledReader.next = this.compiledReader;
      compiledReader.propertyCount = length;
      this.compiledReader = compiledReader;
      return compiledReader(read);
    }
    let object = {};
    if (currentDecoder.keyMap) for (let i = 0; i < length; i++) object[safeKey(currentDecoder.decodeKey(this[i]))] = read();
    else for (let i = 0; i < length; i++) {
      object[safeKey(this[i])] = read();
    }
    return object;
  }
  structure.slowReads = 0;
  return readObject;
}
function safeKey(key) {
  if (typeof key === "string") return key === "__proto__" ? "__proto_" : key;
  if (typeof key === "number" || typeof key === "boolean" || typeof key === "bigint") return key.toString();
  if (key == null) return key + "";
  throw new Error("Invalid property name type " + typeof key);
}
var readFixedString = readStringJS;
function readStringJS(length) {
  let result;
  if (length < 16) {
    if (result = shortStringInJS(length))
      return result;
  }
  if (length > 64 && decoder)
    return decoder.decode(src.subarray(position, position += length));
  const end = position + length;
  const units = [];
  result = "";
  while (position < end) {
    const byte1 = src[position++];
    if ((byte1 & 128) === 0) {
      units.push(byte1);
    } else if ((byte1 & 224) === 192) {
      const byte2 = src[position++] & 63;
      units.push((byte1 & 31) << 6 | byte2);
    } else if ((byte1 & 240) === 224) {
      const byte2 = src[position++] & 63;
      const byte3 = src[position++] & 63;
      units.push((byte1 & 31) << 12 | byte2 << 6 | byte3);
    } else if ((byte1 & 248) === 240) {
      const byte2 = src[position++] & 63;
      const byte3 = src[position++] & 63;
      const byte4 = src[position++] & 63;
      let unit = (byte1 & 7) << 18 | byte2 << 12 | byte3 << 6 | byte4;
      if (unit > 65535) {
        unit -= 65536;
        units.push(unit >>> 10 & 1023 | 55296);
        unit = 56320 | unit & 1023;
      }
      units.push(unit);
    } else {
      units.push(byte1);
    }
    if (units.length >= 4096) {
      result += fromCharCode.apply(String, units);
      units.length = 0;
    }
  }
  if (units.length > 0) {
    result += fromCharCode.apply(String, units);
  }
  return result;
}
var fromCharCode = String.fromCharCode;
function longStringInJS(length) {
  let start = position;
  let bytes = new Array(length);
  for (let i = 0; i < length; i++) {
    const byte = src[position++];
    if ((byte & 128) > 0) {
      position = start;
      return;
    }
    bytes[i] = byte;
  }
  return fromCharCode.apply(String, bytes);
}
function shortStringInJS(length) {
  if (length < 4) {
    if (length < 2) {
      if (length === 0)
        return "";
      else {
        let a = src[position++];
        if ((a & 128) > 1) {
          position -= 1;
          return;
        }
        return fromCharCode(a);
      }
    } else {
      let a = src[position++];
      let b = src[position++];
      if ((a & 128) > 0 || (b & 128) > 0) {
        position -= 2;
        return;
      }
      if (length < 3)
        return fromCharCode(a, b);
      let c = src[position++];
      if ((c & 128) > 0) {
        position -= 3;
        return;
      }
      return fromCharCode(a, b, c);
    }
  } else {
    let a = src[position++];
    let b = src[position++];
    let c = src[position++];
    let d = src[position++];
    if ((a & 128) > 0 || (b & 128) > 0 || (c & 128) > 0 || (d & 128) > 0) {
      position -= 4;
      return;
    }
    if (length < 6) {
      if (length === 4)
        return fromCharCode(a, b, c, d);
      else {
        let e = src[position++];
        if ((e & 128) > 0) {
          position -= 5;
          return;
        }
        return fromCharCode(a, b, c, d, e);
      }
    } else if (length < 8) {
      let e = src[position++];
      let f = src[position++];
      if ((e & 128) > 0 || (f & 128) > 0) {
        position -= 6;
        return;
      }
      if (length < 7)
        return fromCharCode(a, b, c, d, e, f);
      let g = src[position++];
      if ((g & 128) > 0) {
        position -= 7;
        return;
      }
      return fromCharCode(a, b, c, d, e, f, g);
    } else {
      let e = src[position++];
      let f = src[position++];
      let g = src[position++];
      let h = src[position++];
      if ((e & 128) > 0 || (f & 128) > 0 || (g & 128) > 0 || (h & 128) > 0) {
        position -= 8;
        return;
      }
      if (length < 10) {
        if (length === 8)
          return fromCharCode(a, b, c, d, e, f, g, h);
        else {
          let i = src[position++];
          if ((i & 128) > 0) {
            position -= 9;
            return;
          }
          return fromCharCode(a, b, c, d, e, f, g, h, i);
        }
      } else if (length < 12) {
        let i = src[position++];
        let j = src[position++];
        if ((i & 128) > 0 || (j & 128) > 0) {
          position -= 10;
          return;
        }
        if (length < 11)
          return fromCharCode(a, b, c, d, e, f, g, h, i, j);
        let k = src[position++];
        if ((k & 128) > 0) {
          position -= 11;
          return;
        }
        return fromCharCode(a, b, c, d, e, f, g, h, i, j, k);
      } else {
        let i = src[position++];
        let j = src[position++];
        let k = src[position++];
        let l = src[position++];
        if ((i & 128) > 0 || (j & 128) > 0 || (k & 128) > 0 || (l & 128) > 0) {
          position -= 12;
          return;
        }
        if (length < 14) {
          if (length === 12)
            return fromCharCode(a, b, c, d, e, f, g, h, i, j, k, l);
          else {
            let m = src[position++];
            if ((m & 128) > 0) {
              position -= 13;
              return;
            }
            return fromCharCode(a, b, c, d, e, f, g, h, i, j, k, l, m);
          }
        } else {
          let m = src[position++];
          let n = src[position++];
          if ((m & 128) > 0 || (n & 128) > 0) {
            position -= 14;
            return;
          }
          if (length < 15)
            return fromCharCode(a, b, c, d, e, f, g, h, i, j, k, l, m, n);
          let o = src[position++];
          if ((o & 128) > 0) {
            position -= 15;
            return;
          }
          return fromCharCode(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o);
        }
      }
    }
  }
}
function readBin(length) {
  return currentDecoder.copyBuffers ? (
    // specifically use the copying slice (not the node one)
    Uint8Array.prototype.slice.call(src, position, position += length)
  ) : src.subarray(position, position += length);
}
var f32Array = new Float32Array(1);
var u8Array = new Uint8Array(f32Array.buffer, 0, 4);
function getFloat16() {
  let byte0 = src[position++];
  let byte1 = src[position++];
  let exponent = (byte0 & 127) >> 2;
  if (exponent === 31) {
    if (byte1 || byte0 & 3)
      return NaN;
    return byte0 & 128 ? -Infinity : Infinity;
  }
  if (exponent === 0) {
    let abs = ((byte0 & 3) << 8 | byte1) / (1 << 24);
    return byte0 & 128 ? -abs : abs;
  }
  u8Array[3] = byte0 & 128 | // sign bit
  (exponent >> 1) + 56;
  u8Array[2] = (byte0 & 7) << 5 | // last exponent bit and first two mantissa bits
  byte1 >> 3;
  u8Array[1] = byte1 << 5;
  u8Array[0] = 0;
  return f32Array[0];
}
var keyCache = new Array(4096);
var Tag = class {
  constructor(value, tag) {
    this.value = value;
    this.tag = tag;
  }
};
currentExtensions[0] = (dateString) => {
  return new Date(dateString);
};
currentExtensions[1] = (epochSec) => {
  return new Date(Math.round(epochSec * 1e3));
};
currentExtensions[2] = (buffer) => {
  let value = BigInt(0);
  for (let i = 0, l = buffer.byteLength; i < l; i++) {
    value = BigInt(buffer[i]) + (value << BigInt(8));
  }
  return value;
};
currentExtensions[3] = (buffer) => {
  return BigInt(-1) - currentExtensions[2](buffer);
};
currentExtensions[4] = (fraction) => {
  return +(fraction[1] + "e" + fraction[0]);
};
currentExtensions[5] = (fraction) => {
  return fraction[1] * Math.exp(fraction[0] * Math.log(2));
};
var recordDefinition = (id2, structure) => {
  id2 = id2 - 57344;
  let existingStructure = currentStructures[id2];
  if (existingStructure && existingStructure.isShared) {
    (currentStructures.restoreStructures || (currentStructures.restoreStructures = []))[id2] = existingStructure;
  }
  currentStructures[id2] = structure;
  structure.read = createStructureReader(structure);
};
currentExtensions[LEGACY_RECORD_INLINE_ID] = (data) => {
  let length = data.length;
  let structure = data[1];
  recordDefinition(data[0], structure);
  let object = {};
  for (let i = 2; i < length; i++) {
    let key = structure[i - 2];
    object[safeKey(key)] = data[i];
  }
  return object;
};
currentExtensions[14] = (value) => {
  if (bundledStrings)
    return bundledStrings[0].slice(bundledStrings.position0, bundledStrings.position0 += value);
  return new Tag(value, 14);
};
currentExtensions[15] = (value) => {
  if (bundledStrings)
    return bundledStrings[1].slice(bundledStrings.position1, bundledStrings.position1 += value);
  return new Tag(value, 15);
};
var glbl = { Error, RegExp };
currentExtensions[27] = (data) => {
  return (glbl[data[0]] || Error)(data[1], data[2]);
};
var packedTable = (read2) => {
  if (src[position++] != 132) {
    let error = new Error("Packed values structure must be followed by a 4 element array");
    if (src.length < position)
      error.incomplete = true;
    throw error;
  }
  let newPackedValues = read2();
  if (!newPackedValues || !newPackedValues.length) {
    let error = new Error("Packed values structure must be followed by a 4 element array");
    error.incomplete = true;
    throw error;
  }
  packedValues = packedValues ? newPackedValues.concat(packedValues.slice(newPackedValues.length)) : newPackedValues;
  packedValues.prefixes = read2();
  packedValues.suffixes = read2();
  return read2();
};
packedTable.handlesRead = true;
currentExtensions[51] = packedTable;
currentExtensions[PACKED_REFERENCE_TAG_ID] = (data) => {
  if (!packedValues) {
    if (currentDecoder.getShared)
      loadShared();
    else
      return new Tag(data, PACKED_REFERENCE_TAG_ID);
  }
  if (typeof data == "number")
    return packedValues[16 + (data >= 0 ? 2 * data : -2 * data - 1)];
  let error = new Error("No support for non-integer packed references yet");
  if (data === void 0)
    error.incomplete = true;
  throw error;
};
currentExtensions[28] = (read2) => {
  if (!referenceMap) {
    referenceMap = /* @__PURE__ */ new Map();
    referenceMap.id = 0;
  }
  let id2 = referenceMap.id++;
  let startingPosition = position;
  let token = src[position];
  let target2;
  if (token >> 5 == 4)
    target2 = [];
  else
    target2 = {};
  let refEntry = { target: target2 };
  referenceMap.set(id2, refEntry);
  let targetProperties = read2();
  if (refEntry.used) {
    if (Object.getPrototypeOf(target2) !== Object.getPrototypeOf(targetProperties)) {
      position = startingPosition;
      target2 = targetProperties;
      referenceMap.set(id2, { target: target2 });
      targetProperties = read2();
    }
    return Object.assign(target2, targetProperties);
  }
  refEntry.target = targetProperties;
  return targetProperties;
};
currentExtensions[28].handlesRead = true;
currentExtensions[29] = (id2) => {
  let refEntry = referenceMap.get(id2);
  refEntry.used = true;
  return refEntry.target;
};
currentExtensions[258] = (array) => new Set(array);
(currentExtensions[259] = (read2) => {
  if (currentDecoder.mapsAsObjects) {
    currentDecoder.mapsAsObjects = false;
    restoreMapsAsObject = true;
  }
  return read2();
}).handlesRead = true;
function combine(a, b) {
  if (typeof a === "string")
    return a + b;
  if (a instanceof Array)
    return a.concat(b);
  return Object.assign({}, a, b);
}
function getPackedValues() {
  if (!packedValues) {
    if (currentDecoder.getShared)
      loadShared();
    else
      throw new Error("No packed values available");
  }
  return packedValues;
}
var SHARED_DATA_TAG_ID = 1399353956;
currentExtensionRanges.push((tag, input) => {
  if (tag >= 225 && tag <= 255)
    return combine(getPackedValues().prefixes[tag - 224], input);
  if (tag >= 28704 && tag <= 32767)
    return combine(getPackedValues().prefixes[tag - 28672], input);
  if (tag >= 1879052288 && tag <= 2147483647)
    return combine(getPackedValues().prefixes[tag - 1879048192], input);
  if (tag >= 216 && tag <= 223)
    return combine(input, getPackedValues().suffixes[tag - 216]);
  if (tag >= 27647 && tag <= 28671)
    return combine(input, getPackedValues().suffixes[tag - 27639]);
  if (tag >= 1811940352 && tag <= 1879048191)
    return combine(input, getPackedValues().suffixes[tag - 1811939328]);
  if (tag == SHARED_DATA_TAG_ID) {
    return {
      packedValues,
      structures: currentStructures.slice(0),
      version: input
    };
  }
  if (tag == 55799)
    return input;
});
var isLittleEndianMachine = new Uint8Array(new Uint16Array([1]).buffer)[0] == 1;
var typedArrays = [
  Uint8Array,
  Uint8ClampedArray,
  Uint16Array,
  Uint32Array,
  typeof BigUint64Array == "undefined" ? { name: "BigUint64Array" } : BigUint64Array,
  Int8Array,
  Int16Array,
  Int32Array,
  typeof BigInt64Array == "undefined" ? { name: "BigInt64Array" } : BigInt64Array,
  Float32Array,
  Float64Array
];
var typedArrayTags = [64, 68, 69, 70, 71, 72, 77, 78, 79, 85, 86];
for (let i = 0; i < typedArrays.length; i++) {
  registerTypedArray(typedArrays[i], typedArrayTags[i]);
}
function registerTypedArray(TypedArray, tag) {
  let dvMethod = "get" + TypedArray.name.slice(0, -5);
  let bytesPerElement;
  if (typeof TypedArray === "function")
    bytesPerElement = TypedArray.BYTES_PER_ELEMENT;
  else
    TypedArray = null;
  for (let littleEndian = 0; littleEndian < 2; littleEndian++) {
    if (!littleEndian && bytesPerElement == 1)
      continue;
    let sizeShift = bytesPerElement == 2 ? 1 : bytesPerElement == 4 ? 2 : bytesPerElement == 8 ? 3 : 0;
    currentExtensions[littleEndian ? tag : tag - 4] = bytesPerElement == 1 || littleEndian == isLittleEndianMachine ? (buffer) => {
      if (!TypedArray)
        throw new Error("Could not find typed array for code " + tag);
      if (!currentDecoder.copyBuffers) {
        if (bytesPerElement === 1 || bytesPerElement === 2 && !(buffer.byteOffset & 1) || bytesPerElement === 4 && !(buffer.byteOffset & 3) || bytesPerElement === 8 && !(buffer.byteOffset & 7))
          return new TypedArray(buffer.buffer, buffer.byteOffset, buffer.byteLength >> sizeShift);
      }
      return new TypedArray(Uint8Array.prototype.slice.call(buffer, 0).buffer);
    } : (buffer) => {
      if (!TypedArray)
        throw new Error("Could not find typed array for code " + tag);
      let dv = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
      let elements = buffer.length >> sizeShift;
      let ta = new TypedArray(elements);
      let method = dv[dvMethod];
      for (let i = 0; i < elements; i++) {
        ta[i] = method.call(dv, i << sizeShift, littleEndian);
      }
      return ta;
    };
  }
}
function readBundleExt() {
  let length = readJustLength();
  let bundlePosition = position + read();
  for (let i = 2; i < length; i++) {
    let bundleLength = readJustLength();
    position += bundleLength;
  }
  let dataPosition = position;
  position = bundlePosition;
  bundledStrings = [readStringJS(readJustLength()), readStringJS(readJustLength())];
  bundledStrings.position0 = 0;
  bundledStrings.position1 = 0;
  bundledStrings.postBundlePosition = position;
  position = dataPosition;
  return read();
}
function readJustLength() {
  let token = src[position++] & 31;
  if (token > 23) {
    switch (token) {
      case 24:
        token = src[position++];
        break;
      case 25:
        token = dataView.getUint16(position);
        position += 2;
        break;
      case 26:
        token = dataView.getUint32(position);
        position += 4;
        break;
    }
  }
  return token;
}
function loadShared() {
  if (currentDecoder.getShared) {
    let sharedData = saveState(() => {
      src = null;
      return currentDecoder.getShared();
    }) || {};
    let updatedStructures = sharedData.structures || [];
    currentDecoder.sharedVersion = sharedData.version;
    packedValues = currentDecoder.sharedValues = sharedData.packedValues;
    if (currentStructures === true)
      currentDecoder.structures = currentStructures = updatedStructures;
    else
      currentStructures.splice.apply(currentStructures, [0, updatedStructures.length].concat(updatedStructures));
  }
}
function saveState(callback) {
  let savedSrcEnd = srcEnd;
  let savedPosition = position;
  let savedStringPosition = stringPosition;
  let savedSrcStringStart = srcStringStart;
  let savedSrcStringEnd = srcStringEnd;
  let savedSrcString = srcString;
  let savedStrings = strings;
  let savedReferenceMap = referenceMap;
  let savedBundledStrings = bundledStrings;
  let savedSrc = new Uint8Array(src.slice(0, srcEnd));
  let savedStructures = currentStructures;
  let savedDecoder = currentDecoder;
  let savedSequentialMode = sequentialMode;
  let value = callback();
  srcEnd = savedSrcEnd;
  position = savedPosition;
  stringPosition = savedStringPosition;
  srcStringStart = savedSrcStringStart;
  srcStringEnd = savedSrcStringEnd;
  srcString = savedSrcString;
  strings = savedStrings;
  referenceMap = savedReferenceMap;
  bundledStrings = savedBundledStrings;
  src = savedSrc;
  sequentialMode = savedSequentialMode;
  currentStructures = savedStructures;
  currentDecoder = savedDecoder;
  dataView = new DataView(src.buffer, src.byteOffset, src.byteLength);
  return value;
}
function clearSource() {
  src = null;
  referenceMap = null;
  currentStructures = null;
}
var mult10 = new Array(147);
for (let i = 0; i < 256; i++) {
  mult10[i] = +("1e" + Math.floor(45.15 - i * 0.30103));
}
var defaultDecoder = new Decoder({ useRecords: false });
var decode = defaultDecoder.decode;
var decodeMultiple = defaultDecoder.decodeMultiple;
var FLOAT32_OPTIONS = {
  NEVER: 0,
  ALWAYS: 1,
  DECIMAL_ROUND: 3,
  DECIMAL_FIT: 4
};

// node_modules/cbor-x/encode.js
var textEncoder2;
try {
  textEncoder2 = new TextEncoder();
} catch (error) {
}
var extensions;
var extensionClasses;
var Buffer2 = typeof globalThis === "object" && globalThis.Buffer;
var hasNodeBuffer = typeof Buffer2 !== "undefined";
var ByteArrayAllocate = hasNodeBuffer ? Buffer2.allocUnsafeSlow : Uint8Array;
var ByteArray = hasNodeBuffer ? Buffer2 : Uint8Array;
var MAX_STRUCTURES = 256;
var MAX_BUFFER_SIZE = hasNodeBuffer ? 4294967296 : 2144337920;
var throwOnIterable;
var target;
var targetView;
var position2 = 0;
var safeEnd;
var bundledStrings2 = null;
var MAX_BUNDLE_SIZE = 61440;
var hasNonLatin = /[\u0080-\uFFFF]/;
var RECORD_SYMBOL = /* @__PURE__ */ Symbol("record-id");
var Encoder = class extends Decoder {
  constructor(options) {
    super(options);
    this.offset = 0;
    let typeBuffer;
    let start;
    let sharedStructures;
    let hasSharedUpdate;
    let structures;
    let referenceMap2;
    options = options || {};
    let encodeUtf8 = ByteArray.prototype.utf8Write ? function(string, position3, maxBytes) {
      return target.utf8Write(string, position3, maxBytes);
    } : textEncoder2 && textEncoder2.encodeInto ? function(string, position3) {
      return textEncoder2.encodeInto(string, target.subarray(position3)).written;
    } : false;
    let encoder = this;
    let hasSharedStructures = options.structures || options.saveStructures;
    let maxSharedStructures = options.maxSharedStructures;
    if (maxSharedStructures == null)
      maxSharedStructures = hasSharedStructures ? 128 : 0;
    if (maxSharedStructures > 8190)
      throw new Error("Maximum maxSharedStructure is 8190");
    let isSequential = options.sequential;
    if (isSequential) {
      maxSharedStructures = 0;
    }
    if (!this.structures)
      this.structures = [];
    if (this.saveStructures)
      this.saveShared = this.saveStructures;
    let samplingPackedValues, packedObjectMap2, sharedValues = options.sharedValues;
    let sharedPackedObjectMap2;
    if (sharedValues) {
      sharedPackedObjectMap2 = /* @__PURE__ */ Object.create(null);
      for (let i = 0, l = sharedValues.length; i < l; i++) {
        sharedPackedObjectMap2[sharedValues[i]] = i;
      }
    }
    let recordIdsToRemove = [];
    let transitionsCount = 0;
    let serializationsSinceTransitionRebuild = 0;
    this.mapEncode = function(value, encodeOptions) {
      if (this._keyMap && !this._mapped) {
        switch (value.constructor.name) {
          case "Array":
            value = value.map((r) => this.encodeKeys(r));
            break;
        }
      }
      return this.encode(value, encodeOptions);
    };
    this.encode = function(value, encodeOptions) {
      if (!target) {
        target = new ByteArrayAllocate(8192);
        targetView = new DataView(target.buffer, 0, 8192);
        position2 = 0;
      }
      safeEnd = target.length - 10;
      if (safeEnd - position2 < 2048) {
        target = new ByteArrayAllocate(target.length);
        targetView = new DataView(target.buffer, 0, target.length);
        safeEnd = target.length - 10;
        position2 = 0;
      } else if (encodeOptions === REUSE_BUFFER_MODE)
        position2 = position2 + 7 & 2147483640;
      start = position2;
      if (encoder.useSelfDescribedHeader) {
        targetView.setUint32(position2, 3654940416);
        position2 += 3;
      }
      referenceMap2 = encoder.structuredClone ? /* @__PURE__ */ new Map() : null;
      if (encoder.bundleStrings && typeof value !== "string") {
        bundledStrings2 = [];
        bundledStrings2.size = Infinity;
      } else
        bundledStrings2 = null;
      sharedStructures = encoder.structures;
      if (sharedStructures) {
        if (sharedStructures.uninitialized) {
          let sharedData = encoder.getShared() || {};
          encoder.structures = sharedStructures = sharedData.structures || [];
          encoder.sharedVersion = sharedData.version;
          let sharedValues2 = encoder.sharedValues = sharedData.packedValues;
          if (sharedValues2) {
            sharedPackedObjectMap2 = {};
            for (let i = 0, l = sharedValues2.length; i < l; i++)
              sharedPackedObjectMap2[sharedValues2[i]] = i;
          }
        }
        let sharedStructuresLength = sharedStructures.length;
        if (sharedStructuresLength > maxSharedStructures && !isSequential)
          sharedStructuresLength = maxSharedStructures;
        if (!sharedStructures.transitions) {
          sharedStructures.transitions = /* @__PURE__ */ Object.create(null);
          for (let i = 0; i < sharedStructuresLength; i++) {
            let keys = sharedStructures[i];
            if (!keys)
              continue;
            let nextTransition, transition = sharedStructures.transitions;
            for (let j = 0, l = keys.length; j < l; j++) {
              if (transition[RECORD_SYMBOL] === void 0)
                transition[RECORD_SYMBOL] = i;
              let key = keys[j];
              nextTransition = transition[key];
              if (!nextTransition) {
                nextTransition = transition[key] = /* @__PURE__ */ Object.create(null);
              }
              transition = nextTransition;
            }
            transition[RECORD_SYMBOL] = i | 1048576;
          }
        }
        if (!isSequential)
          sharedStructures.nextId = sharedStructuresLength;
      }
      if (hasSharedUpdate)
        hasSharedUpdate = false;
      structures = sharedStructures || [];
      packedObjectMap2 = sharedPackedObjectMap2;
      if (options.pack) {
        let packedValues2 = /* @__PURE__ */ new Map();
        packedValues2.values = [];
        packedValues2.encoder = encoder;
        packedValues2.maxValues = options.maxPrivatePackedValues || (sharedPackedObjectMap2 ? 16 : Infinity);
        packedValues2.objectMap = sharedPackedObjectMap2 || false;
        packedValues2.samplingPackedValues = samplingPackedValues;
        findRepetitiveStrings(value, packedValues2);
        if (packedValues2.values.length > 0) {
          target[position2++] = 216;
          target[position2++] = 51;
          writeArrayHeader(4);
          let valuesArray = packedValues2.values;
          encode2(valuesArray);
          writeArrayHeader(0);
          writeArrayHeader(0);
          packedObjectMap2 = Object.create(sharedPackedObjectMap2 || null);
          for (let i = 0, l = valuesArray.length; i < l; i++) {
            packedObjectMap2[valuesArray[i]] = i;
          }
        }
      }
      throwOnIterable = encodeOptions & THROW_ON_ITERABLE;
      try {
        if (throwOnIterable)
          return;
        encode2(value);
        if (bundledStrings2) {
          writeBundles(start, encode2);
        }
        encoder.offset = position2;
        if (referenceMap2 && referenceMap2.idsToInsert) {
          position2 += referenceMap2.idsToInsert.length * 2;
          if (position2 > safeEnd)
            makeRoom(position2);
          encoder.offset = position2;
          let serialized = insertIds(target.subarray(start, position2), referenceMap2.idsToInsert);
          referenceMap2 = null;
          return serialized;
        }
        if (encodeOptions & REUSE_BUFFER_MODE) {
          target.start = start;
          target.end = position2;
          return target;
        }
        return target.subarray(start, position2);
      } finally {
        if (sharedStructures) {
          if (serializationsSinceTransitionRebuild < 10)
            serializationsSinceTransitionRebuild++;
          if (sharedStructures.length > maxSharedStructures)
            sharedStructures.length = maxSharedStructures;
          if (transitionsCount > 1e4) {
            sharedStructures.transitions = null;
            serializationsSinceTransitionRebuild = 0;
            transitionsCount = 0;
            if (recordIdsToRemove.length > 0)
              recordIdsToRemove = [];
          } else if (recordIdsToRemove.length > 0 && !isSequential) {
            for (let i = 0, l = recordIdsToRemove.length; i < l; i++) {
              recordIdsToRemove[i][RECORD_SYMBOL] = void 0;
            }
            recordIdsToRemove = [];
          }
        }
        if (hasSharedUpdate && encoder.saveShared) {
          if (encoder.structures.length > maxSharedStructures) {
            encoder.structures = encoder.structures.slice(0, maxSharedStructures);
          }
          let returnBuffer = target.subarray(start, position2);
          if (encoder.updateSharedData() === false)
            return encoder.encode(value);
          return returnBuffer;
        }
        if (encodeOptions & RESET_BUFFER_MODE)
          position2 = start;
      }
    };
    this.findCommonStringsToPack = () => {
      samplingPackedValues = /* @__PURE__ */ new Map();
      if (!sharedPackedObjectMap2)
        sharedPackedObjectMap2 = /* @__PURE__ */ Object.create(null);
      return (options2) => {
        let threshold = options2 && options2.threshold || 4;
        let position3 = this.pack ? options2.maxPrivatePackedValues || 16 : 0;
        if (!sharedValues)
          sharedValues = this.sharedValues = [];
        for (let [key, status] of samplingPackedValues) {
          if (status.count > threshold) {
            sharedPackedObjectMap2[key] = position3++;
            sharedValues.push(key);
            hasSharedUpdate = true;
          }
        }
        while (this.saveShared && this.updateSharedData() === false) {
        }
        samplingPackedValues = null;
      };
    };
    const encode2 = (value) => {
      if (position2 > safeEnd)
        target = makeRoom(position2);
      var type = typeof value;
      var length;
      if (type === "string") {
        if (packedObjectMap2) {
          let packedPosition = packedObjectMap2[value];
          if (packedPosition >= 0) {
            if (packedPosition < 16)
              target[position2++] = packedPosition + 224;
            else {
              target[position2++] = 198;
              if (packedPosition & 1)
                encode2(15 - packedPosition >> 1);
              else
                encode2(packedPosition - 16 >> 1);
            }
            return;
          } else if (samplingPackedValues && !options.pack) {
            let status = samplingPackedValues.get(value);
            if (status)
              status.count++;
            else
              samplingPackedValues.set(value, {
                count: 1
              });
          }
        }
        let strLength = value.length;
        if (bundledStrings2 && strLength >= 4 && strLength < 1024) {
          if ((bundledStrings2.size += strLength) > MAX_BUNDLE_SIZE) {
            let extStart;
            let maxBytes2 = (bundledStrings2[0] ? bundledStrings2[0].length * 3 + bundledStrings2[1].length : 0) + 10;
            if (position2 + maxBytes2 > safeEnd)
              target = makeRoom(position2 + maxBytes2);
            target[position2++] = 217;
            target[position2++] = 223;
            target[position2++] = 249;
            target[position2++] = bundledStrings2.position ? 132 : 130;
            target[position2++] = 26;
            extStart = position2 - start;
            position2 += 4;
            if (bundledStrings2.position) {
              writeBundles(start, encode2);
            }
            bundledStrings2 = ["", ""];
            bundledStrings2.size = 0;
            bundledStrings2.position = extStart;
          }
          let twoByte = hasNonLatin.test(value);
          bundledStrings2[twoByte ? 0 : 1] += value;
          target[position2++] = twoByte ? 206 : 207;
          encode2(strLength);
          return;
        }
        let headerSize;
        if (strLength < 32) {
          headerSize = 1;
        } else if (strLength < 256) {
          headerSize = 2;
        } else if (strLength < 65536) {
          headerSize = 3;
        } else {
          headerSize = 5;
        }
        let maxBytes = strLength * 3;
        if (position2 + maxBytes > safeEnd)
          target = makeRoom(position2 + maxBytes);
        if (strLength < 64 || !encodeUtf8) {
          let i, c1, c2, strPosition = position2 + headerSize;
          for (i = 0; i < strLength; i++) {
            c1 = value.charCodeAt(i);
            if (c1 < 128) {
              target[strPosition++] = c1;
            } else if (c1 < 2048) {
              target[strPosition++] = c1 >> 6 | 192;
              target[strPosition++] = c1 & 63 | 128;
            } else if ((c1 & 64512) === 55296 && ((c2 = value.charCodeAt(i + 1)) & 64512) === 56320) {
              c1 = 65536 + ((c1 & 1023) << 10) + (c2 & 1023);
              i++;
              target[strPosition++] = c1 >> 18 | 240;
              target[strPosition++] = c1 >> 12 & 63 | 128;
              target[strPosition++] = c1 >> 6 & 63 | 128;
              target[strPosition++] = c1 & 63 | 128;
            } else {
              target[strPosition++] = c1 >> 12 | 224;
              target[strPosition++] = c1 >> 6 & 63 | 128;
              target[strPosition++] = c1 & 63 | 128;
            }
          }
          length = strPosition - position2 - headerSize;
        } else {
          length = encodeUtf8(value, position2 + headerSize, maxBytes);
        }
        if (length < 24) {
          target[position2++] = 96 | length;
        } else if (length < 256) {
          if (headerSize < 2) {
            target.copyWithin(position2 + 2, position2 + 1, position2 + 1 + length);
          }
          target[position2++] = 120;
          target[position2++] = length;
        } else if (length < 65536) {
          if (headerSize < 3) {
            target.copyWithin(position2 + 3, position2 + 2, position2 + 2 + length);
          }
          target[position2++] = 121;
          target[position2++] = length >> 8;
          target[position2++] = length & 255;
        } else {
          if (headerSize < 5) {
            target.copyWithin(position2 + 5, position2 + 3, position2 + 3 + length);
          }
          target[position2++] = 122;
          targetView.setUint32(position2, length);
          position2 += 4;
        }
        position2 += length;
      } else if (type === "number") {
        if (!this.alwaysUseFloat && value >>> 0 === value) {
          if (value < 24) {
            target[position2++] = value;
          } else if (value < 256) {
            target[position2++] = 24;
            target[position2++] = value;
          } else if (value < 65536) {
            target[position2++] = 25;
            target[position2++] = value >> 8;
            target[position2++] = value & 255;
          } else {
            target[position2++] = 26;
            targetView.setUint32(position2, value);
            position2 += 4;
          }
        } else if (!this.alwaysUseFloat && value >> 0 === value) {
          if (value >= -24) {
            target[position2++] = 31 - value;
          } else if (value >= -256) {
            target[position2++] = 56;
            target[position2++] = ~value;
          } else if (value >= -65536) {
            target[position2++] = 57;
            targetView.setUint16(position2, ~value);
            position2 += 2;
          } else {
            target[position2++] = 58;
            targetView.setUint32(position2, ~value);
            position2 += 4;
          }
        } else {
          let useFloat32;
          if ((useFloat32 = this.useFloat32) > 0 && value < 4294967296 && value >= -2147483648) {
            target[position2++] = 250;
            targetView.setFloat32(position2, value);
            let xShifted;
            if (useFloat32 < 4 || // this checks for rounding of numbers that were encoded in 32-bit float to nearest significant decimal digit that could be preserved
            (xShifted = value * mult10[(target[position2] & 127) << 1 | target[position2 + 1] >> 7]) >> 0 === xShifted) {
              position2 += 4;
              return;
            } else
              position2--;
          }
          target[position2++] = 251;
          targetView.setFloat64(position2, value);
          position2 += 8;
        }
      } else if (type === "object") {
        if (!value)
          target[position2++] = 246;
        else {
          if (referenceMap2) {
            let referee = referenceMap2.get(value);
            if (referee) {
              target[position2++] = 216;
              target[position2++] = 29;
              target[position2++] = 25;
              if (!referee.references) {
                let idsToInsert = referenceMap2.idsToInsert || (referenceMap2.idsToInsert = []);
                referee.references = [];
                idsToInsert.push(referee);
              }
              referee.references.push(position2 - start);
              position2 += 2;
              return;
            } else
              referenceMap2.set(value, { offset: position2 - start });
          }
          let constructor = value.constructor;
          if (constructor === Object) {
            writeObject(value);
          } else if (constructor === Array) {
            length = value.length;
            if (length < 24) {
              target[position2++] = 128 | length;
            } else {
              writeArrayHeader(length);
            }
            for (let i = 0; i < length; i++) {
              encode2(value[i]);
            }
          } else if (constructor === Map) {
            if (this.mapsAsObjects ? this.useTag259ForMaps !== false : this.useTag259ForMaps) {
              target[position2++] = 217;
              target[position2++] = 1;
              target[position2++] = 3;
            }
            length = value.size;
            if (length < 24) {
              target[position2++] = 160 | length;
            } else if (length < 256) {
              target[position2++] = 184;
              target[position2++] = length;
            } else if (length < 65536) {
              target[position2++] = 185;
              target[position2++] = length >> 8;
              target[position2++] = length & 255;
            } else {
              target[position2++] = 186;
              targetView.setUint32(position2, length);
              position2 += 4;
            }
            if (encoder.keyMap) {
              for (let [key, entryValue] of value) {
                encode2(encoder.encodeKey(key));
                encode2(entryValue);
              }
            } else {
              for (let [key, entryValue] of value) {
                encode2(key);
                encode2(entryValue);
              }
            }
          } else {
            for (let i = 0, l = extensions.length; i < l; i++) {
              let extensionClass = extensionClasses[i];
              if (value instanceof extensionClass) {
                let extension = extensions[i];
                let tag = extension.tag;
                if (tag == void 0)
                  tag = extension.getTag && extension.getTag.call(this, value);
                if (tag < 24) {
                  target[position2++] = 192 | tag;
                } else if (tag < 256) {
                  target[position2++] = 216;
                  target[position2++] = tag;
                } else if (tag < 65536) {
                  target[position2++] = 217;
                  target[position2++] = tag >> 8;
                  target[position2++] = tag & 255;
                } else if (tag > -1) {
                  target[position2++] = 218;
                  targetView.setUint32(position2, tag);
                  position2 += 4;
                }
                extension.encode.call(this, value, encode2, makeRoom);
                return;
              }
            }
            if (value[Symbol.iterator]) {
              if (throwOnIterable) {
                let error = new Error("Iterable should be serialized as iterator");
                error.iteratorNotHandled = true;
                throw error;
              }
              target[position2++] = 159;
              for (let entry of value) {
                encode2(entry);
              }
              target[position2++] = 255;
              return;
            }
            if (value[Symbol.asyncIterator] || isBlob(value)) {
              let error = new Error("Iterable/blob should be serialized as iterator");
              error.iteratorNotHandled = true;
              throw error;
            }
            if (this.useToJSON && value.toJSON) {
              const json = value.toJSON();
              if (json !== value)
                return encode2(json);
            }
            writeObject(value);
          }
        }
      } else if (type === "boolean") {
        target[position2++] = value ? 245 : 244;
      } else if (type === "bigint") {
        if (value < BigInt(1) << BigInt(64) && value >= 0) {
          target[position2++] = 27;
          targetView.setBigUint64(position2, value);
        } else if (value > -(BigInt(1) << BigInt(64)) && value < 0) {
          target[position2++] = 59;
          targetView.setBigUint64(position2, -value - BigInt(1));
        } else {
          if (this.largeBigIntToFloat) {
            target[position2++] = 251;
            targetView.setFloat64(position2, Number(value));
          } else {
            if (value >= BigInt(0))
              target[position2++] = 194;
            else {
              target[position2++] = 195;
              value = BigInt(-1) - value;
            }
            let bytes = [];
            while (value) {
              bytes.push(Number(value & BigInt(255)));
              value >>= BigInt(8);
            }
            writeBuffer(new Uint8Array(bytes.reverse()), makeRoom);
            return;
          }
        }
        position2 += 8;
      } else if (type === "undefined") {
        target[position2++] = 247;
      } else {
        throw new Error("Unknown type: " + type);
      }
    };
    const writeObject = this.useRecords === false ? this.variableMapSize ? (object) => {
      let keys = Object.keys(object);
      let vals = Object.values(object);
      let length = keys.length;
      if (length < 24) {
        target[position2++] = 160 | length;
      } else if (length < 256) {
        target[position2++] = 184;
        target[position2++] = length;
      } else if (length < 65536) {
        target[position2++] = 185;
        target[position2++] = length >> 8;
        target[position2++] = length & 255;
      } else {
        target[position2++] = 186;
        targetView.setUint32(position2, length);
        position2 += 4;
      }
      let key;
      if (encoder.keyMap) {
        for (let i = 0; i < length; i++) {
          encode2(encoder.encodeKey(keys[i]));
          encode2(vals[i]);
        }
      } else {
        for (let i = 0; i < length; i++) {
          encode2(keys[i]);
          encode2(vals[i]);
        }
      }
    } : (object) => {
      target[position2++] = 185;
      let objectOffset = position2 - start;
      position2 += 2;
      let size = 0;
      if (encoder.keyMap) {
        for (let key in object) if (typeof object.hasOwnProperty !== "function" || object.hasOwnProperty(key)) {
          encode2(encoder.encodeKey(key));
          encode2(object[key]);
          size++;
        }
      } else {
        for (let key in object) if (typeof object.hasOwnProperty !== "function" || object.hasOwnProperty(key)) {
          encode2(key);
          encode2(object[key]);
          size++;
        }
      }
      target[objectOffset++ + start] = size >> 8;
      target[objectOffset + start] = size & 255;
    } : (object, skipValues) => {
      let nextTransition, transition = structures.transitions || (structures.transitions = /* @__PURE__ */ Object.create(null));
      let newTransitions = 0;
      let length = 0;
      let parentRecordId;
      let keys;
      if (this.keyMap) {
        keys = Object.keys(object).map((k) => this.encodeKey(k));
        length = keys.length;
        for (let i = 0; i < length; i++) {
          let key = keys[i];
          nextTransition = transition[key];
          if (!nextTransition) {
            nextTransition = transition[key] = /* @__PURE__ */ Object.create(null);
            newTransitions++;
          }
          transition = nextTransition;
        }
      } else {
        for (let key in object) if (typeof object.hasOwnProperty !== "function" || object.hasOwnProperty(key)) {
          nextTransition = transition[key];
          if (!nextTransition) {
            if (transition[RECORD_SYMBOL] & 1048576) {
              parentRecordId = transition[RECORD_SYMBOL] & 65535;
            }
            nextTransition = transition[key] = /* @__PURE__ */ Object.create(null);
            newTransitions++;
          }
          transition = nextTransition;
          length++;
        }
      }
      let recordId = transition[RECORD_SYMBOL];
      if (recordId !== void 0) {
        recordId &= 65535;
        target[position2++] = 217;
        target[position2++] = recordId >> 8 | 224;
        target[position2++] = recordId & 255;
      } else {
        if (!keys)
          keys = transition.__keys__ || (transition.__keys__ = Object.keys(object));
        if (parentRecordId === void 0) {
          recordId = structures.nextId++;
          if (!recordId) {
            recordId = 0;
            structures.nextId = 1;
          }
          if (recordId >= MAX_STRUCTURES) {
            structures.nextId = (recordId = maxSharedStructures) + 1;
          }
        } else {
          recordId = parentRecordId;
        }
        structures[recordId] = keys;
        if (recordId < maxSharedStructures) {
          target[position2++] = 217;
          target[position2++] = recordId >> 8 | 224;
          target[position2++] = recordId & 255;
          transition = structures.transitions;
          for (let i = 0; i < length; i++) {
            if (transition[RECORD_SYMBOL] === void 0 || transition[RECORD_SYMBOL] & 1048576)
              transition[RECORD_SYMBOL] = recordId;
            transition = transition[keys[i]];
          }
          transition[RECORD_SYMBOL] = recordId | 1048576;
          hasSharedUpdate = true;
        } else {
          transition[RECORD_SYMBOL] = recordId;
          targetView.setUint32(position2, 3655335680);
          position2 += 3;
          if (newTransitions)
            transitionsCount += serializationsSinceTransitionRebuild * newTransitions;
          if (recordIdsToRemove.length >= MAX_STRUCTURES - maxSharedStructures)
            recordIdsToRemove.shift()[RECORD_SYMBOL] = void 0;
          recordIdsToRemove.push(transition);
          writeArrayHeader(length + 2);
          encode2(57344 + recordId);
          encode2(keys);
          if (skipValues) return;
          for (let key in object)
            if (typeof object.hasOwnProperty !== "function" || object.hasOwnProperty(key))
              encode2(object[key]);
          return;
        }
      }
      if (length < 24) {
        target[position2++] = 128 | length;
      } else {
        writeArrayHeader(length);
      }
      if (skipValues) return;
      for (let key in object)
        if (typeof object.hasOwnProperty !== "function" || object.hasOwnProperty(key))
          encode2(object[key]);
    };
    const makeRoom = (end) => {
      let newSize;
      if (end > 16777216) {
        if (end - start > MAX_BUFFER_SIZE)
          throw new Error("Encoded buffer would be larger than maximum buffer size");
        newSize = Math.min(
          MAX_BUFFER_SIZE,
          Math.round(Math.max((end - start) * (end > 67108864 ? 1.25 : 2), 4194304) / 4096) * 4096
        );
      } else
        newSize = (Math.max(end - start << 2, target.length - 1) >> 12) + 1 << 12;
      let newBuffer = new ByteArrayAllocate(newSize);
      targetView = new DataView(newBuffer.buffer, 0, newSize);
      if (target.copy)
        target.copy(newBuffer, 0, start, end);
      else
        newBuffer.set(target.slice(start, end));
      position2 -= start;
      start = 0;
      safeEnd = newBuffer.length - 10;
      return target = newBuffer;
    };
    let chunkThreshold = 100;
    let continuedChunkThreshold = 1e3;
    this.encodeAsIterable = function(value, options2) {
      return startEncoding(value, options2, encodeObjectAsIterable);
    };
    this.encodeAsAsyncIterable = function(value, options2) {
      return startEncoding(value, options2, encodeObjectAsAsyncIterable);
    };
    function* encodeObjectAsIterable(object, iterateProperties, finalIterable) {
      let constructor = object.constructor;
      if (constructor === Object) {
        let useRecords = encoder.useRecords !== false;
        if (useRecords)
          writeObject(object, true);
        else
          writeEntityLength(Object.keys(object).length, 160);
        for (let key in object) {
          let value = object[key];
          if (!useRecords) encode2(key);
          if (value && typeof value === "object") {
            if (iterateProperties[key])
              yield* encodeObjectAsIterable(value, iterateProperties[key]);
            else
              yield* tryEncode(value, iterateProperties, key);
          } else encode2(value);
        }
      } else if (constructor === Array) {
        let length = object.length;
        writeArrayHeader(length);
        for (let i = 0; i < length; i++) {
          let value = object[i];
          if (value && (typeof value === "object" || position2 - start > chunkThreshold)) {
            if (iterateProperties.element)
              yield* encodeObjectAsIterable(value, iterateProperties.element);
            else
              yield* tryEncode(value, iterateProperties, "element");
          } else encode2(value);
        }
      } else if (object[Symbol.iterator] && !object.buffer) {
        target[position2++] = 159;
        for (let value of object) {
          if (value && (typeof value === "object" || position2 - start > chunkThreshold)) {
            if (iterateProperties.element)
              yield* encodeObjectAsIterable(value, iterateProperties.element);
            else
              yield* tryEncode(value, iterateProperties, "element");
          } else encode2(value);
        }
        target[position2++] = 255;
      } else if (isBlob(object)) {
        writeEntityLength(object.size, 64);
        yield target.subarray(start, position2);
        yield object;
        restartEncoding();
      } else if (object[Symbol.asyncIterator]) {
        target[position2++] = 159;
        yield target.subarray(start, position2);
        yield object;
        restartEncoding();
        target[position2++] = 255;
      } else {
        encode2(object);
      }
      if (finalIterable && position2 > start) yield target.subarray(start, position2);
      else if (position2 - start > chunkThreshold) {
        yield target.subarray(start, position2);
        restartEncoding();
      }
    }
    function* tryEncode(value, iterateProperties, key) {
      let restart = position2 - start;
      try {
        encode2(value);
        if (position2 - start > chunkThreshold) {
          yield target.subarray(start, position2);
          restartEncoding();
        }
      } catch (error) {
        if (error.iteratorNotHandled) {
          iterateProperties[key] = {};
          position2 = start + restart;
          yield* encodeObjectAsIterable.call(this, value, iterateProperties[key]);
        } else throw error;
      }
    }
    function restartEncoding() {
      chunkThreshold = continuedChunkThreshold;
      encoder.encode(null, THROW_ON_ITERABLE);
    }
    function startEncoding(value, options2, encodeIterable) {
      if (options2 && options2.chunkThreshold)
        chunkThreshold = continuedChunkThreshold = options2.chunkThreshold;
      else
        chunkThreshold = 100;
      if (value && typeof value === "object") {
        encoder.encode(null, THROW_ON_ITERABLE);
        return encodeIterable(value, encoder.iterateProperties || (encoder.iterateProperties = {}), true);
      }
      return [encoder.encode(value)];
    }
    async function* encodeObjectAsAsyncIterable(value, iterateProperties) {
      for (let encodedValue of encodeObjectAsIterable(value, iterateProperties, true)) {
        let constructor = encodedValue.constructor;
        if (constructor === ByteArray || constructor === Uint8Array)
          yield encodedValue;
        else if (isBlob(encodedValue)) {
          let reader = encodedValue.stream().getReader();
          let next;
          while (!(next = await reader.read()).done) {
            yield next.value;
          }
        } else if (encodedValue[Symbol.asyncIterator]) {
          for await (let asyncValue of encodedValue) {
            restartEncoding();
            if (asyncValue)
              yield* encodeObjectAsAsyncIterable(asyncValue, iterateProperties.async || (iterateProperties.async = {}));
            else yield encoder.encode(asyncValue);
          }
        } else {
          yield encodedValue;
        }
      }
    }
  }
  useBuffer(buffer) {
    target = buffer;
    targetView = new DataView(target.buffer, target.byteOffset, target.byteLength);
    position2 = 0;
  }
  clearSharedData() {
    if (this.structures)
      this.structures = [];
    if (this.sharedValues)
      this.sharedValues = void 0;
  }
  updateSharedData() {
    let lastVersion = this.sharedVersion || 0;
    this.sharedVersion = lastVersion + 1;
    let structuresCopy = this.structures.slice(0);
    let sharedData = new SharedData(structuresCopy, this.sharedValues, this.sharedVersion);
    let saveResults = this.saveShared(
      sharedData,
      (existingShared) => (existingShared && existingShared.version || 0) == lastVersion
    );
    if (saveResults === false) {
      sharedData = this.getShared() || {};
      this.structures = sharedData.structures || [];
      this.sharedValues = sharedData.packedValues;
      this.sharedVersion = sharedData.version;
      this.structures.nextId = this.structures.length;
    } else {
      structuresCopy.forEach((structure, i) => this.structures[i] = structure);
    }
    return saveResults;
  }
};
function writeEntityLength(length, majorValue) {
  if (length < 24)
    target[position2++] = majorValue | length;
  else if (length < 256) {
    target[position2++] = majorValue | 24;
    target[position2++] = length;
  } else if (length < 65536) {
    target[position2++] = majorValue | 25;
    target[position2++] = length >> 8;
    target[position2++] = length & 255;
  } else {
    target[position2++] = majorValue | 26;
    targetView.setUint32(position2, length);
    position2 += 4;
  }
}
var SharedData = class {
  constructor(structures, values, version) {
    this.structures = structures;
    this.packedValues = values;
    this.version = version;
  }
};
function writeArrayHeader(length) {
  if (length < 24)
    target[position2++] = 128 | length;
  else if (length < 256) {
    target[position2++] = 152;
    target[position2++] = length;
  } else if (length < 65536) {
    target[position2++] = 153;
    target[position2++] = length >> 8;
    target[position2++] = length & 255;
  } else {
    target[position2++] = 154;
    targetView.setUint32(position2, length);
    position2 += 4;
  }
}
var BlobConstructor = typeof Blob === "undefined" ? function() {
} : Blob;
function isBlob(object) {
  if (object instanceof BlobConstructor)
    return true;
  let tag = object[Symbol.toStringTag];
  return tag === "Blob" || tag === "File";
}
function findRepetitiveStrings(value, packedValues2) {
  switch (typeof value) {
    case "string":
      if (value.length > 3) {
        if (packedValues2.objectMap[value] > -1 || packedValues2.values.length >= packedValues2.maxValues)
          return;
        let packedStatus = packedValues2.get(value);
        if (packedStatus) {
          if (++packedStatus.count == 2) {
            packedValues2.values.push(value);
          }
        } else {
          packedValues2.set(value, {
            count: 1
          });
          if (packedValues2.samplingPackedValues) {
            let status = packedValues2.samplingPackedValues.get(value);
            if (status)
              status.count++;
            else
              packedValues2.samplingPackedValues.set(value, {
                count: 1
              });
          }
        }
      }
      break;
    case "object":
      if (value) {
        if (value instanceof Array) {
          for (let i = 0, l = value.length; i < l; i++) {
            findRepetitiveStrings(value[i], packedValues2);
          }
        } else {
          let includeKeys = !packedValues2.encoder.useRecords;
          for (var key in value) {
            if (value.hasOwnProperty(key)) {
              if (includeKeys)
                findRepetitiveStrings(key, packedValues2);
              findRepetitiveStrings(value[key], packedValues2);
            }
          }
        }
      }
      break;
    case "function":
      console.log(value);
  }
}
var isLittleEndianMachine2 = new Uint8Array(new Uint16Array([1]).buffer)[0] == 1;
extensionClasses = [
  Date,
  Set,
  Error,
  RegExp,
  Tag,
  ArrayBuffer,
  Uint8Array,
  Uint8ClampedArray,
  Uint16Array,
  Uint32Array,
  typeof BigUint64Array == "undefined" ? function() {
  } : BigUint64Array,
  Int8Array,
  Int16Array,
  Int32Array,
  typeof BigInt64Array == "undefined" ? function() {
  } : BigInt64Array,
  Float32Array,
  Float64Array,
  SharedData
];
extensions = [
  {
    // Date
    tag: 1,
    encode(date, encode2) {
      let seconds = date.getTime() / 1e3;
      if ((this.useTimestamp32 || date.getMilliseconds() === 0) && seconds >= 0 && seconds < 4294967296) {
        target[position2++] = 26;
        targetView.setUint32(position2, seconds);
        position2 += 4;
      } else {
        target[position2++] = 251;
        targetView.setFloat64(position2, seconds);
        position2 += 8;
      }
    }
  },
  {
    // Set
    tag: 258,
    // https://github.com/input-output-hk/cbor-sets-spec/blob/master/CBOR_SETS.md
    encode(set, encode2) {
      let array = Array.from(set);
      encode2(array);
    }
  },
  {
    // Error
    tag: 27,
    // http://cbor.schmorp.de/generic-object
    encode(error, encode2) {
      encode2([error.name, error.message]);
    }
  },
  {
    // RegExp
    tag: 27,
    // http://cbor.schmorp.de/generic-object
    encode(regex, encode2) {
      encode2(["RegExp", regex.source, regex.flags]);
    }
  },
  {
    // Tag
    getTag(tag) {
      return tag.tag;
    },
    encode(tag, encode2) {
      encode2(tag.value);
    }
  },
  {
    // ArrayBuffer
    encode(arrayBuffer, encode2, makeRoom) {
      writeBuffer(arrayBuffer, makeRoom);
    }
  },
  {
    // Uint8Array
    getTag(typedArray) {
      if (typedArray.constructor === Uint8Array) {
        if (this.tagUint8Array || hasNodeBuffer && this.tagUint8Array !== false)
          return 64;
      }
    },
    encode(typedArray, encode2, makeRoom) {
      writeBuffer(typedArray, makeRoom);
    }
  },
  typedArrayEncoder(68, 1),
  typedArrayEncoder(69, 2),
  typedArrayEncoder(70, 4),
  typedArrayEncoder(71, 8),
  typedArrayEncoder(72, 1),
  typedArrayEncoder(77, 2),
  typedArrayEncoder(78, 4),
  typedArrayEncoder(79, 8),
  typedArrayEncoder(85, 4),
  typedArrayEncoder(86, 8),
  {
    encode(sharedData, encode2) {
      let packedValues2 = sharedData.packedValues || [];
      let sharedStructures = sharedData.structures || [];
      if (packedValues2.values.length > 0) {
        target[position2++] = 216;
        target[position2++] = 51;
        writeArrayHeader(4);
        let valuesArray = packedValues2.values;
        encode2(valuesArray);
        writeArrayHeader(0);
        writeArrayHeader(0);
        packedObjectMap = Object.create(sharedPackedObjectMap || null);
        for (let i = 0, l = valuesArray.length; i < l; i++) {
          packedObjectMap[valuesArray[i]] = i;
        }
      }
      if (sharedStructures) {
        targetView.setUint32(position2, 3655335424);
        position2 += 3;
        let definitions = sharedStructures.slice(0);
        definitions.unshift(57344);
        definitions.push(new Tag(sharedData.version, 1399353956));
        encode2(definitions);
      } else
        encode2(new Tag(sharedData.version, 1399353956));
    }
  }
];
function typedArrayEncoder(tag, size) {
  if (!isLittleEndianMachine2 && size > 1)
    tag -= 4;
  return {
    tag,
    encode: function writeExtBuffer(typedArray, encode2) {
      let length = typedArray.byteLength;
      let offset = typedArray.byteOffset || 0;
      let buffer = typedArray.buffer || typedArray;
      encode2(hasNodeBuffer ? Buffer2.from(buffer, offset, length) : new Uint8Array(buffer, offset, length));
    }
  };
}
function writeBuffer(buffer, makeRoom) {
  let length = buffer.byteLength;
  if (length < 24) {
    target[position2++] = 64 + length;
  } else if (length < 256) {
    target[position2++] = 88;
    target[position2++] = length;
  } else if (length < 65536) {
    target[position2++] = 89;
    target[position2++] = length >> 8;
    target[position2++] = length & 255;
  } else {
    target[position2++] = 90;
    targetView.setUint32(position2, length);
    position2 += 4;
  }
  if (position2 + length >= target.length) {
    makeRoom(position2 + length);
  }
  target.set(buffer.buffer ? buffer : new Uint8Array(buffer), position2);
  position2 += length;
}
function insertIds(serialized, idsToInsert) {
  let nextId;
  let distanceToMove = idsToInsert.length * 2;
  let lastEnd = serialized.length - distanceToMove;
  idsToInsert.sort((a, b) => a.offset > b.offset ? 1 : -1);
  for (let id2 = 0; id2 < idsToInsert.length; id2++) {
    let referee = idsToInsert[id2];
    referee.id = id2;
    for (let position3 of referee.references) {
      serialized[position3++] = id2 >> 8;
      serialized[position3] = id2 & 255;
    }
  }
  while (nextId = idsToInsert.pop()) {
    let offset = nextId.offset;
    serialized.copyWithin(offset + distanceToMove, offset, lastEnd);
    distanceToMove -= 2;
    let position3 = offset + distanceToMove;
    serialized[position3++] = 216;
    serialized[position3++] = 28;
    lastEnd = offset;
  }
  return serialized;
}
function writeBundles(start, encode2) {
  targetView.setUint32(bundledStrings2.position + start, position2 - bundledStrings2.position - start + 1);
  let writeStrings = bundledStrings2;
  bundledStrings2 = null;
  encode2(writeStrings[0]);
  encode2(writeStrings[1]);
}
var defaultEncoder = new Encoder({ useRecords: false });
var encode = defaultEncoder.encode;
var encodeAsIterable = defaultEncoder.encodeAsIterable;
var encodeAsAsyncIterable = defaultEncoder.encodeAsAsyncIterable;
var { NEVER, ALWAYS, DECIMAL_ROUND, DECIMAL_FIT } = FLOAT32_OPTIONS;
var REUSE_BUFFER_MODE = 512;
var RESET_BUFFER_MODE = 1024;
var THROW_ON_ITERABLE = 2048;

// node_modules/@noble/hashes/utils.js
function isBytes(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
}
function anumber(n, title = "") {
  if (typeof n !== "number") {
    const prefix = title && `"${title}" `;
    throw new TypeError(`${prefix}expected number, got ${typeof n}`);
  }
  if (!Number.isSafeInteger(n) || n < 0) {
    const prefix = title && `"${title}" `;
    throw new RangeError(`${prefix}expected integer >= 0, got ${n}`);
  }
}
function abytes(value, length, title = "") {
  const bytes = isBytes(value);
  const len = value?.length;
  const needsLen = length !== void 0;
  if (!bytes || needsLen && len !== length) {
    const prefix = title && `"${title}" `;
    const ofLen = needsLen ? ` of length ${length}` : "";
    const got = bytes ? `length=${len}` : `type=${typeof value}`;
    const message = prefix + "expected Uint8Array" + ofLen + ", got " + got;
    if (!bytes)
      throw new TypeError(message);
    throw new RangeError(message);
  }
  return value;
}
function aexists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished)
    throw new Error("Hash#digest() has already been called");
}
function aoutput(out, instance) {
  abytes(out, void 0, "digestInto() output");
  const min = instance.outputLen;
  if (out.length < min) {
    throw new RangeError('"digestInto() output" expected to be of length >=' + min);
  }
}
function u32(arr) {
  return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
function clean(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
var isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
function byteSwap(word) {
  return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
}
function byteSwap32(arr) {
  for (let i = 0; i < arr.length; i++) {
    arr[i] = byteSwap(arr[i]);
  }
  return arr;
}
var swap32IfBE = isLE ? (u) => u : byteSwap32;
function concatBytes(...arrays) {
  let sum = 0;
  for (let i = 0; i < arrays.length; i++) {
    const a = arrays[i];
    abytes(a);
    sum += a.length;
  }
  const res = new Uint8Array(sum);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const a = arrays[i];
    res.set(a, pad);
    pad += a.length;
  }
  return res;
}
function createHasher(hashCons, info = {}) {
  const hashC = (msg, opts) => hashCons(opts).update(msg).digest();
  const tmp = hashCons(void 0);
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.canXOF = tmp.canXOF;
  hashC.create = (opts) => hashCons(opts);
  Object.assign(hashC, info);
  return Object.freeze(hashC);
}
function randomBytes(bytesLength = 32) {
  anumber(bytesLength, "bytesLength");
  const cr = typeof globalThis === "object" ? globalThis.crypto : null;
  if (typeof cr?.getRandomValues !== "function")
    throw new Error("crypto.getRandomValues must be defined");
  if (bytesLength > 65536)
    throw new RangeError(`"bytesLength" expected <= 65536, got ${bytesLength}`);
  return cr.getRandomValues(new Uint8Array(bytesLength));
}
var oidNist = (suffix) => ({
  // Current NIST hashAlgs suffixes used here fit in one DER subidentifier octet.
  // Larger suffix values would need base-128 OID encoding and a different length byte.
  oid: Uint8Array.from([6, 9, 96, 134, 72, 1, 101, 3, 4, 2, suffix])
});

// node_modules/@noble/curves/utils.js
function abool(value, title = "") {
  if (typeof value !== "boolean") {
    const prefix = title && `"${title}" `;
    throw new TypeError(prefix + "expected boolean, got type=" + typeof value);
  }
  return value;
}

// node_modules/@noble/hashes/_u64.js
var U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
var _32n = /* @__PURE__ */ BigInt(32);
function fromBig(n, le = false) {
  if (le)
    return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
  return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
function split(lst, le = false) {
  const len = lst.length;
  let Ah = new Uint32Array(len);
  let Al = new Uint32Array(len);
  for (let i = 0; i < len; i++) {
    const { h, l } = fromBig(lst[i], le);
    [Ah[i], Al[i]] = [h, l];
  }
  return [Ah, Al];
}
var rotlSH = (h, l, s) => h << s | l >>> 32 - s;
var rotlSL = (h, l, s) => l << s | h >>> 32 - s;
var rotlBH = (h, l, s) => l << s - 32 | h >>> 64 - s;
var rotlBL = (h, l, s) => h << s - 32 | l >>> 64 - s;

// node_modules/@noble/hashes/sha3.js
var _0n = BigInt(0);
var _1n = BigInt(1);
var _2n = BigInt(2);
var _7n = BigInt(7);
var _256n = BigInt(256);
var _0x71n = BigInt(113);
var SHA3_PI = [];
var SHA3_ROTL = [];
var _SHA3_IOTA = [];
for (let round = 0, R = _1n, x = 1, y = 0; round < 24; round++) {
  [x, y] = [y, (2 * x + 3 * y) % 5];
  SHA3_PI.push(2 * (5 * y + x));
  SHA3_ROTL.push((round + 1) * (round + 2) / 2 % 64);
  let t = _0n;
  for (let j = 0; j < 7; j++) {
    R = (R << _1n ^ (R >> _7n) * _0x71n) % _256n;
    if (R & _2n)
      t ^= _1n << (_1n << BigInt(j)) - _1n;
  }
  _SHA3_IOTA.push(t);
}
var IOTAS = split(_SHA3_IOTA, true);
var SHA3_IOTA_H = IOTAS[0];
var SHA3_IOTA_L = IOTAS[1];
var rotlH = (h, l, s) => s > 32 ? rotlBH(h, l, s) : rotlSH(h, l, s);
var rotlL = (h, l, s) => s > 32 ? rotlBL(h, l, s) : rotlSL(h, l, s);
function keccakP(s, rounds = 24) {
  anumber(rounds, "rounds");
  if (rounds < 1 || rounds > 24)
    throw new Error('"rounds" expected integer 1..24');
  const B = new Uint32Array(5 * 2);
  for (let round = 24 - rounds; round < 24; round++) {
    for (let x = 0; x < 10; x++)
      B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
    for (let x = 0; x < 10; x += 2) {
      const idx1 = (x + 8) % 10;
      const idx0 = (x + 2) % 10;
      const B0 = B[idx0];
      const B1 = B[idx0 + 1];
      const Th = rotlH(B0, B1, 1) ^ B[idx1];
      const Tl = rotlL(B0, B1, 1) ^ B[idx1 + 1];
      for (let y = 0; y < 50; y += 10) {
        s[x + y] ^= Th;
        s[x + y + 1] ^= Tl;
      }
    }
    let curH = s[2];
    let curL = s[3];
    for (let t = 0; t < 24; t++) {
      const shift = SHA3_ROTL[t];
      const Th = rotlH(curH, curL, shift);
      const Tl = rotlL(curH, curL, shift);
      const PI = SHA3_PI[t];
      curH = s[PI];
      curL = s[PI + 1];
      s[PI] = Th;
      s[PI + 1] = Tl;
    }
    for (let y = 0; y < 50; y += 10) {
      const b0 = s[y], b1 = s[y + 1], b2 = s[y + 2], b3 = s[y + 3];
      s[y] ^= ~s[y + 2] & s[y + 4];
      s[y + 1] ^= ~s[y + 3] & s[y + 5];
      s[y + 2] ^= ~s[y + 4] & s[y + 6];
      s[y + 3] ^= ~s[y + 5] & s[y + 7];
      s[y + 4] ^= ~s[y + 6] & s[y + 8];
      s[y + 5] ^= ~s[y + 7] & s[y + 9];
      s[y + 6] ^= ~s[y + 8] & b0;
      s[y + 7] ^= ~s[y + 9] & b1;
      s[y + 8] ^= ~b0 & b2;
      s[y + 9] ^= ~b1 & b3;
    }
    s[0] ^= SHA3_IOTA_H[round];
    s[1] ^= SHA3_IOTA_L[round];
  }
  clean(B);
}
var Keccak = class _Keccak {
  state;
  pos = 0;
  posOut = 0;
  finished = false;
  state32;
  destroyed = false;
  blockLen;
  suffix;
  outputLen;
  canXOF;
  enableXOF = false;
  rounds;
  // NOTE: we accept arguments in bytes instead of bits here.
  constructor(blockLen, suffix, outputLen, enableXOF = false, rounds = 24) {
    this.blockLen = blockLen;
    this.suffix = suffix;
    this.outputLen = outputLen;
    this.enableXOF = enableXOF;
    this.canXOF = enableXOF;
    this.rounds = rounds;
    anumber(outputLen, "outputLen");
    if (!(0 < blockLen && blockLen < 200))
      throw new Error("only keccak-f1600 function is supported");
    this.state = new Uint8Array(200);
    this.state32 = u32(this.state);
  }
  clone() {
    return this._cloneInto();
  }
  keccak() {
    swap32IfBE(this.state32);
    keccakP(this.state32, this.rounds);
    swap32IfBE(this.state32);
    this.posOut = 0;
    this.pos = 0;
  }
  update(data) {
    aexists(this);
    abytes(data);
    const { blockLen, state } = this;
    const len = data.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      for (let i = 0; i < take; i++)
        state[this.pos++] ^= data[pos++];
      if (this.pos === blockLen)
        this.keccak();
    }
    return this;
  }
  finish() {
    if (this.finished)
      return;
    this.finished = true;
    const { state, suffix, pos, blockLen } = this;
    state[pos] ^= suffix;
    if ((suffix & 128) !== 0 && pos === blockLen - 1)
      this.keccak();
    state[blockLen - 1] ^= 128;
    this.keccak();
  }
  writeInto(out) {
    aexists(this, false);
    abytes(out);
    this.finish();
    const bufferOut = this.state;
    const { blockLen } = this;
    for (let pos = 0, len = out.length; pos < len; ) {
      if (this.posOut >= blockLen)
        this.keccak();
      const take = Math.min(blockLen - this.posOut, len - pos);
      out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
      this.posOut += take;
      pos += take;
    }
    return out;
  }
  xofInto(out) {
    if (!this.enableXOF)
      throw new Error("XOF is not possible for this instance");
    return this.writeInto(out);
  }
  xof(bytes) {
    anumber(bytes);
    return this.xofInto(new Uint8Array(bytes));
  }
  digestInto(out) {
    aoutput(out, this);
    if (this.finished)
      throw new Error("digest() was already called");
    this.writeInto(out.subarray(0, this.outputLen));
    this.destroy();
  }
  digest() {
    const out = new Uint8Array(this.outputLen);
    this.digestInto(out);
    return out;
  }
  destroy() {
    this.destroyed = true;
    clean(this.state);
  }
  _cloneInto(to) {
    const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
    to ||= new _Keccak(blockLen, suffix, outputLen, enableXOF, rounds);
    to.blockLen = blockLen;
    to.state32.set(this.state32);
    to.pos = this.pos;
    to.posOut = this.posOut;
    to.finished = this.finished;
    to.rounds = rounds;
    to.suffix = suffix;
    to.outputLen = outputLen;
    to.enableXOF = enableXOF;
    to.canXOF = this.canXOF;
    to.destroyed = this.destroyed;
    return to;
  }
};
var genShake = (suffix, blockLen, outputLen, info = {}) => createHasher((opts = {}) => new Keccak(blockLen, suffix, opts.dkLen === void 0 ? outputLen : opts.dkLen, true), info);
var shake128 = /* @__PURE__ */ genShake(31, 168, 16, /* @__PURE__ */ oidNist(11));
var shake256 = /* @__PURE__ */ genShake(31, 136, 32, /* @__PURE__ */ oidNist(12));

// node_modules/@noble/curves/abstract/fft.js
function checkU32(n) {
  if (!Number.isSafeInteger(n) || n < 0 || n > 4294967295)
    throw new Error("wrong u32 integer:" + n);
  return n;
}
function isPowerOfTwo(x) {
  checkU32(x);
  return (x & x - 1) === 0 && x !== 0;
}
function reverseBits(n, bits) {
  checkU32(n);
  if (!Number.isSafeInteger(bits) || bits < 0 || bits > 32)
    throw new Error(`expected integer 0 <= bits <= 32, got ${bits}`);
  let reversed = 0;
  for (let i = 0; i < bits; i++, n >>>= 1)
    reversed = reversed << 1 | n & 1;
  return reversed >>> 0;
}
function log2(n) {
  checkU32(n);
  return 31 - Math.clz32(n);
}
function bitReversalInplace(values) {
  const n = values.length;
  if (!isPowerOfTwo(n))
    throw new Error("expected positive power-of-two length, got " + n);
  const bits = log2(n);
  for (let i = 0; i < n; i++) {
    const j = reverseBits(i, bits);
    if (i < j) {
      const tmp = values[i];
      values[i] = values[j];
      values[j] = tmp;
    }
  }
  return values;
}
var FFTCore = (F2, coreOpts) => {
  const { N: N2, roots, dit, invertButterflies = false, skipStages = 0, brp = true } = coreOpts;
  const bits = log2(N2);
  if (!isPowerOfTwo(N2))
    throw new Error("FFT: Polynomial size should be power of two");
  if (roots.length !== N2)
    throw new Error(`FFT: wrong roots length: expected ${N2}, got ${roots.length}`);
  const isDit = dit !== invertButterflies;
  isDit;
  return (values) => {
    if (values.length !== N2)
      throw new Error("FFT: wrong Polynomial length");
    if (dit && brp)
      bitReversalInplace(values);
    for (let i = 0, g = 1; i < bits - skipStages; i++) {
      const s = dit ? i + 1 + skipStages : bits - i;
      const m = 1 << s;
      const m2 = m >> 1;
      const stride = N2 >> s;
      for (let k = 0; k < N2; k += m) {
        for (let j = 0, grp = g++; j < m2; j++) {
          const rootPos = invertButterflies ? dit ? N2 - grp : grp : j * stride;
          const i0 = k + j;
          const i1 = k + j + m2;
          const omega = roots[rootPos];
          const b = values[i1];
          const a = values[i0];
          if (isDit) {
            const t = F2.mul(b, omega);
            values[i0] = F2.add(a, t);
            values[i1] = F2.sub(a, t);
          } else if (invertButterflies) {
            values[i0] = F2.add(b, a);
            values[i1] = F2.mul(F2.sub(b, a), omega);
          } else {
            values[i0] = F2.add(a, b);
            values[i1] = F2.mul(F2.sub(a, b), omega);
          }
        }
      }
    }
    if (!dit && brp)
      bitReversalInplace(values);
    return values;
  };
};

// node_modules/@noble/post-quantum/utils.js
var abytesDoc = abytes;
var randomBytes2 = randomBytes;
function equalBytes(a, b) {
  if (a.length !== b.length)
    return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++)
    diff |= a[i] ^ b[i];
  return diff === 0;
}
function validateOpts(opts) {
  if (Object.prototype.toString.call(opts) !== "[object Object]")
    throw new TypeError("expected valid options object");
}
function validateVerOpts(opts) {
  validateOpts(opts);
  if (opts.context !== void 0)
    abytes(opts.context, void 0, "opts.context");
}
function validateSigOpts(opts) {
  validateVerOpts(opts);
  if (opts.extraEntropy !== false && opts.extraEntropy !== void 0)
    abytes(opts.extraEntropy, void 0, "opts.extraEntropy");
}
function splitCoder(label, ...lengths) {
  const getLength = (c) => typeof c === "number" ? c : c.bytesLen;
  const bytesLen = lengths.reduce((sum, a) => sum + getLength(a), 0);
  return {
    bytesLen,
    encode: (bufs) => {
      const res = new Uint8Array(bytesLen);
      for (let i = 0, pos = 0; i < lengths.length; i++) {
        const c = lengths[i];
        const l = getLength(c);
        const b = typeof c === "number" ? bufs[i] : c.encode(bufs[i]);
        abytes(b, l, label);
        res.set(b, pos);
        if (typeof c !== "number")
          b.fill(0);
        pos += l;
      }
      return res;
    },
    decode: (buf) => {
      abytes(buf, bytesLen, label);
      const res = [];
      for (const c of lengths) {
        const l = getLength(c);
        const b = buf.subarray(0, l);
        res.push(typeof c === "number" ? b : c.decode(b));
        buf = buf.subarray(l);
      }
      return res;
    }
  };
}
function vecCoder(c, vecLen) {
  const coder = c;
  const bytesLen = vecLen * coder.bytesLen;
  return {
    bytesLen,
    encode: (u) => {
      if (u.length !== vecLen)
        throw new RangeError(`vecCoder.encode: wrong length=${u.length}. Expected: ${vecLen}`);
      const res = new Uint8Array(bytesLen);
      for (let i = 0, pos = 0; i < u.length; i++) {
        const b = coder.encode(u[i]);
        res.set(b, pos);
        b.fill(0);
        pos += b.length;
      }
      return res;
    },
    decode: (a) => {
      abytes(a, bytesLen);
      const r = [];
      for (let i = 0; i < a.length; i += coder.bytesLen)
        r.push(coder.decode(a.subarray(i, i + coder.bytesLen)));
      return r;
    }
  };
}
function cleanBytes(...list) {
  for (const t of list) {
    if (Array.isArray(t))
      for (const b of t)
        b.fill(0);
    else
      t.fill(0);
  }
}
function getMask(bits) {
  if (!Number.isSafeInteger(bits) || bits < 0 || bits > 32)
    throw new RangeError(`expected bits in [0..32], got ${bits}`);
  return bits === 32 ? 4294967295 : ~(-1 << bits) >>> 0;
}
var EMPTY = /* @__PURE__ */ Uint8Array.of();
function getMessage(msg, ctx = EMPTY) {
  abytes(msg);
  abytes(ctx);
  if (ctx.length > 255)
    throw new RangeError("context should be 255 bytes or less");
  return concatBytes(new Uint8Array([0, ctx.length]), ctx, msg);
}
var oidNistP = /* @__PURE__ */ Uint8Array.from([6, 9, 96, 134, 72, 1, 101, 3, 4, 2]);
function checkHash(hash, requiredStrength = 0) {
  if (!hash.oid || !equalBytes(hash.oid.subarray(0, 10), oidNistP))
    throw new Error("hash.oid is invalid: expected NIST hash");
  const collisionResistance = hash.outputLen * 8 / 2;
  if (requiredStrength > collisionResistance) {
    throw new Error("Pre-hash security strength too low: " + collisionResistance + ", required: " + requiredStrength);
  }
}
function getMessagePrehash(hash, msg, ctx = EMPTY) {
  abytes(msg);
  abytes(ctx);
  if (ctx.length > 255)
    throw new RangeError("context should be 255 bytes or less");
  const hashed = hash(msg);
  return concatBytes(new Uint8Array([1, ctx.length]), ctx, hash.oid, hashed);
}

// node_modules/@noble/post-quantum/_crystals.js
var genCrystals = (opts) => {
  const { newPoly: newPoly2, N: N2, Q: Q2, F: F2, ROOT_OF_UNITY: ROOT_OF_UNITY2, brvBits, isKyber } = opts;
  const mod = (a, modulo = Q2) => {
    const result = a % modulo | 0;
    return (result >= 0 ? result | 0 : modulo + result | 0) | 0;
  };
  const smod = (a, modulo = Q2) => {
    const r = mod(a, modulo) | 0;
    return (r > modulo >> 1 ? r - modulo | 0 : r) | 0;
  };
  function getZettas() {
    const out = newPoly2(N2);
    for (let i = 0; i < N2; i++) {
      const b = reverseBits(i, brvBits);
      const p = BigInt(ROOT_OF_UNITY2) ** BigInt(b) % BigInt(Q2);
      out[i] = Number(p) | 0;
    }
    return out;
  }
  const nttZetas = getZettas();
  const field = {
    add: (a, b) => mod((a | 0) + (b | 0)) | 0,
    sub: (a, b) => mod((a | 0) - (b | 0)) | 0,
    mul: (a, b) => mod((a | 0) * (b | 0)) | 0,
    inv: (_a) => {
      throw new Error("not implemented");
    }
  };
  const nttOpts = {
    N: N2,
    roots: nttZetas,
    invertButterflies: true,
    skipStages: isKyber ? 1 : 0,
    brp: false
  };
  const dif = FFTCore(field, { dit: false, ...nttOpts });
  const dit = FFTCore(field, { dit: true, ...nttOpts });
  const NTT = {
    encode: (r) => {
      return dif(r);
    },
    decode: (r) => {
      dit(r);
      for (let i = 0; i < r.length; i++)
        r[i] = mod(F2 * r[i]);
      return r;
    }
  };
  const bitsCoder = (d, c) => {
    const mask = getMask(d);
    const bytesLen = d * (N2 / 8);
    return {
      bytesLen,
      encode: (poly_) => {
        const poly = poly_;
        const r = new Uint8Array(bytesLen);
        for (let i = 0, buf = 0, bufLen = 0, pos = 0; i < poly.length; i++) {
          buf |= (c.encode(poly[i]) & mask) << bufLen;
          bufLen += d;
          for (; bufLen >= 8; bufLen -= 8, buf >>= 8)
            r[pos++] = buf & getMask(bufLen);
        }
        return r;
      },
      decode: (bytes) => {
        const r = newPoly2(N2);
        for (let i = 0, buf = 0, bufLen = 0, pos = 0; i < bytes.length; i++) {
          buf |= bytes[i] << bufLen;
          bufLen += 8;
          for (; bufLen >= d; bufLen -= d, buf >>= d)
            r[pos++] = c.decode(buf & mask);
        }
        return r;
      }
    };
  };
  return {
    mod,
    smod,
    nttZetas,
    NTT: {
      encode: (r) => NTT.encode(r),
      decode: (r) => NTT.decode(r)
    },
    bitsCoder
  };
};
var createXofShake = (shake) => (seed, blockLen) => {
  if (!blockLen)
    blockLen = shake.blockLen;
  const _seed = new Uint8Array(seed.length + 2);
  _seed.set(seed);
  const seedLen = seed.length;
  const buf = new Uint8Array(blockLen);
  let h = shake.create({});
  let calls = 0;
  let xofs = 0;
  return {
    stats: () => ({ calls, xofs }),
    get: (x, y) => {
      _seed[seedLen + 0] = x;
      _seed[seedLen + 1] = y;
      h.destroy();
      h = shake.create({}).update(_seed);
      calls++;
      return () => {
        xofs++;
        return h.xofInto(buf);
      };
    },
    clean: () => {
      h.destroy();
      cleanBytes(buf, _seed);
    }
  };
};
var XOF128 = /* @__PURE__ */ createXofShake(shake128);
var XOF256 = /* @__PURE__ */ createXofShake(shake256);

// node_modules/@noble/post-quantum/ml-dsa.js
function validateInternalOpts(opts) {
  validateOpts(opts);
  if (opts.externalMu !== void 0)
    abool(opts.externalMu, "opts.externalMu");
}
var N = 256;
var Q = 8380417;
var ROOT_OF_UNITY = 1753;
var F = 8347681;
var D = 13;
var GAMMA2_1 = Math.floor((Q - 1) / 88) | 0;
var GAMMA2_2 = Math.floor((Q - 1) / 32) | 0;
var PARAMS = /* @__PURE__ */ (() => Object.freeze({
  2: Object.freeze({
    K: 4,
    L: 4,
    D,
    GAMMA1: 2 ** 17,
    GAMMA2: GAMMA2_1,
    TAU: 39,
    ETA: 2,
    OMEGA: 80
  }),
  3: Object.freeze({
    K: 6,
    L: 5,
    D,
    GAMMA1: 2 ** 19,
    GAMMA2: GAMMA2_2,
    TAU: 49,
    ETA: 4,
    OMEGA: 55
  }),
  5: Object.freeze({
    K: 8,
    L: 7,
    D,
    GAMMA1: 2 ** 19,
    GAMMA2: GAMMA2_2,
    TAU: 60,
    ETA: 2,
    OMEGA: 75
  })
}))();
var newPoly = (n) => new Int32Array(n);
var crystals = /* @__PURE__ */ genCrystals({
  N,
  Q,
  F,
  ROOT_OF_UNITY,
  newPoly,
  isKyber: false,
  brvBits: 8
});
var id = (n) => n;
var polyCoder = (d, compress = id, verify = id) => crystals.bitsCoder(d, {
  encode: (i) => compress(verify(i)),
  decode: (i) => verify(compress(i))
});
var polyAdd = (a_, b_) => {
  const a = a_;
  const b = b_;
  for (let i = 0; i < a.length; i++)
    a[i] = crystals.mod(a[i] + b[i]);
  return a;
};
var polySub = (a_, b_) => {
  const a = a_;
  const b = b_;
  for (let i = 0; i < a.length; i++)
    a[i] = crystals.mod(a[i] - b[i]);
  return a;
};
var polyShiftl = (p_) => {
  const p = p_;
  for (let i = 0; i < N; i++)
    p[i] <<= D;
  return p;
};
var polyChknorm = (p_, B) => {
  const p = p_;
  for (let i = 0; i < N; i++)
    if (Math.abs(crystals.smod(p[i])) >= B)
      return true;
  return false;
};
var MultiplyNTTs = (a_, b_) => {
  const a = a_;
  const b = b_;
  const c = newPoly(N);
  for (let i = 0; i < a.length; i++)
    c[i] = crystals.mod(a[i] * b[i]);
  return c;
};
function RejNTTPoly(xof_) {
  const xof = xof_;
  const r = newPoly(N);
  for (let j = 0; j < N; ) {
    const b = xof();
    if (b.length % 3)
      throw new Error("RejNTTPoly: unaligned block");
    for (let i = 0; j < N && i <= b.length - 3; i += 3) {
      const t = (b[i + 0] | b[i + 1] << 8 | b[i + 2] << 16) & 8388607;
      if (t < Q)
        r[j++] = t;
    }
  }
  return r;
}
function getDilithium(opts_) {
  const opts = opts_;
  const { K, L, GAMMA1, GAMMA2, TAU, ETA, OMEGA } = opts;
  const { CRH_BYTES, TR_BYTES, C_TILDE_BYTES, XOF128: XOF1282, XOF256: XOF2562, securityLevel } = opts;
  if (![2, 4].includes(ETA))
    throw new Error("Wrong ETA");
  if (![1 << 17, 1 << 19].includes(GAMMA1))
    throw new Error("Wrong GAMMA1");
  if (![GAMMA2_1, GAMMA2_2].includes(GAMMA2))
    throw new Error("Wrong GAMMA2");
  const BETA = TAU * ETA;
  const decompose = (r) => {
    const rPlus = crystals.mod(r);
    const r0 = crystals.smod(rPlus, 2 * GAMMA2) | 0;
    if (rPlus - r0 === Q - 1)
      return { r1: 0 | 0, r0: r0 - 1 | 0 };
    const r1 = Math.floor((rPlus - r0) / (2 * GAMMA2)) | 0;
    return { r1, r0 };
  };
  const HighBits = (r) => decompose(r).r1;
  const LowBits = (r) => decompose(r).r0;
  const MakeHint = (z, r) => {
    const res0 = z <= GAMMA2 || z > Q - GAMMA2 || z === Q - GAMMA2 && r === 0 ? 0 : 1;
    return res0;
  };
  const UseHint = (h, r) => {
    const m = Math.floor((Q - 1) / (2 * GAMMA2));
    const { r1, r0 } = decompose(r);
    if (h === 1)
      return r0 > 0 ? crystals.mod(r1 + 1, m) | 0 : crystals.mod(r1 - 1, m) | 0;
    return r1 | 0;
  };
  const Power2Round = (r) => {
    const rPlus = crystals.mod(r);
    const r0 = crystals.smod(rPlus, 2 ** D) | 0;
    return { r1: Math.floor((rPlus - r0) / 2 ** D) | 0, r0 };
  };
  const hintCoder = {
    bytesLen: OMEGA + K,
    encode: (h_) => {
      const h = h_;
      if (h === false)
        throw new Error("hint.encode: hint is false");
      const res = new Uint8Array(OMEGA + K);
      for (let i = 0, k = 0; i < K; i++) {
        for (let j = 0; j < N; j++)
          if (h[i][j] !== 0)
            res[k++] = j;
        res[OMEGA + i] = k;
      }
      return res;
    },
    decode: (buf) => {
      const h = [];
      let k = 0;
      for (let i = 0; i < K; i++) {
        const hi = newPoly(N);
        if (buf[OMEGA + i] < k || buf[OMEGA + i] > OMEGA)
          return false;
        for (let j = k; j < buf[OMEGA + i]; j++) {
          if (j > k && buf[j] <= buf[j - 1])
            return false;
          hi[buf[j]] = 1;
        }
        k = buf[OMEGA + i];
        h.push(hi);
      }
      for (let j = k; j < OMEGA; j++)
        if (buf[j] !== 0)
          return false;
      return h;
    }
  };
  const ETACoder = polyCoder(ETA === 2 ? 3 : 4, (i) => ETA - i, (i) => {
    if (!(-ETA <= i && i <= ETA))
      throw new Error(`malformed key s1/s3 ${i} outside of ETA range [${-ETA}, ${ETA}]`);
    return i;
  });
  const T0Coder = polyCoder(13, (i) => (1 << D - 1) - i);
  const T1Coder = polyCoder(10);
  const ZCoder = polyCoder(GAMMA1 === 1 << 17 ? 18 : 20, (i) => crystals.smod(GAMMA1 - i));
  const W1Coder = polyCoder(GAMMA2 === GAMMA2_1 ? 6 : 4);
  const W1Vec = vecCoder(W1Coder, K);
  const publicCoder = splitCoder("publicKey", 32, vecCoder(T1Coder, K));
  const secretCoder = splitCoder("secretKey", 32, 32, TR_BYTES, vecCoder(ETACoder, L), vecCoder(ETACoder, K), vecCoder(T0Coder, K));
  const sigCoder = splitCoder("signature", C_TILDE_BYTES, vecCoder(ZCoder, L), hintCoder);
  const CoefFromHalfByte = ETA === 2 ? (n) => n < 15 ? 2 - n % 5 : false : (n) => n < 9 ? 4 - n : false;
  function RejBoundedPoly(xof_) {
    const xof = xof_;
    const r = newPoly(N);
    for (let j = 0; j < N; ) {
      const b = xof();
      for (let i = 0; j < N && i < b.length; i += 1) {
        const d1 = CoefFromHalfByte(b[i] & 15);
        const d2 = CoefFromHalfByte(b[i] >> 4 & 15);
        if (d1 !== false)
          r[j++] = d1;
        if (j < N && d2 !== false)
          r[j++] = d2;
      }
    }
    return r;
  }
  const SampleInBall = (seed) => {
    const pre = newPoly(N);
    const s = shake256.create({}).update(seed);
    const buf = new Uint8Array(shake256.blockLen);
    s.xofInto(buf);
    const masks = buf.slice(0, 8);
    for (let i = N - TAU, pos = 8, maskPos = 0, maskBit = 0; i < N; i++) {
      let b = i + 1;
      for (; b > i; ) {
        b = buf[pos++];
        if (pos < shake256.blockLen)
          continue;
        s.xofInto(buf);
        pos = 0;
      }
      pre[i] = pre[b];
      pre[b] = 1 - ((masks[maskPos] >> maskBit++ & 1) << 1);
      if (maskBit >= 8) {
        maskPos++;
        maskBit = 0;
      }
    }
    return pre;
  };
  const polyPowerRound = (p_) => {
    const p = p_;
    const res0 = newPoly(N);
    const res1 = newPoly(N);
    for (let i = 0; i < p.length; i++) {
      const { r0, r1 } = Power2Round(p[i]);
      res0[i] = r0;
      res1[i] = r1;
    }
    return { r0: res0, r1: res1 };
  };
  const polyUseHint = (u_, h_) => {
    const u = u_;
    const h = h_;
    for (let i = 0; i < N; i++)
      u[i] = UseHint(h[i], u[i]);
    return u;
  };
  const polyMakeHint = (a_, b_) => {
    const a = a_;
    const b = b_;
    const v = newPoly(N);
    let cnt = 0;
    for (let i = 0; i < N; i++) {
      const h = MakeHint(a[i], b[i]);
      v[i] = h;
      cnt += h;
    }
    return { v, cnt };
  };
  const signRandBytes = 32;
  const seedCoder = splitCoder("seed", 32, 64, 32);
  const internal = Object.freeze({
    info: Object.freeze({ type: "internal-ml-dsa" }),
    lengths: Object.freeze({
      secretKey: secretCoder.bytesLen,
      publicKey: publicCoder.bytesLen,
      seed: 32,
      signature: sigCoder.bytesLen,
      signRand: signRandBytes
    }),
    keygen: (seed) => {
      const seedDst = new Uint8Array(32 + 2);
      const randSeed = seed === void 0;
      if (randSeed)
        seed = randomBytes2(32);
      abytesDoc(seed, 32, "seed");
      seedDst.set(seed);
      if (randSeed)
        cleanBytes(seed);
      seedDst[32] = K;
      seedDst[33] = L;
      const [rho, rhoPrime, K_] = seedCoder.decode(shake256(seedDst, { dkLen: seedCoder.bytesLen }));
      const xofPrime = XOF2562(rhoPrime);
      const s1 = [];
      for (let i = 0; i < L; i++)
        s1.push(RejBoundedPoly(xofPrime.get(i & 255, i >> 8 & 255)));
      const s2 = [];
      for (let i = L; i < L + K; i++)
        s2.push(RejBoundedPoly(xofPrime.get(i & 255, i >> 8 & 255)));
      const s1Hat = s1.map((i) => crystals.NTT.encode(i.slice()));
      const t0 = [];
      const t1 = [];
      const xof = XOF1282(rho);
      const t = newPoly(N);
      for (let i = 0; i < K; i++) {
        cleanBytes(t);
        for (let j = 0; j < L; j++) {
          const aij = RejNTTPoly(xof.get(j, i));
          polyAdd(t, MultiplyNTTs(aij, s1Hat[j]));
        }
        crystals.NTT.decode(t);
        const { r0, r1 } = polyPowerRound(polyAdd(t, s2[i]));
        t0.push(r0);
        t1.push(r1);
      }
      const publicKey = publicCoder.encode([rho, t1]);
      const tr = shake256(publicKey, { dkLen: TR_BYTES });
      const secretKey = secretCoder.encode([rho, K_, tr, s1, s2, t0]);
      xof.clean();
      xofPrime.clean();
      cleanBytes(rho, rhoPrime, K_, s1, s2, s1Hat, t, t0, t1, tr, seedDst);
      return {
        publicKey,
        secretKey
      };
    },
    getPublicKey: (secretKey) => {
      const [rho, _K, _tr, s1, s2, _t0] = secretCoder.decode(secretKey);
      const xof = XOF1282(rho);
      const s1Hat = s1.map((p) => crystals.NTT.encode(p.slice()));
      const t1 = [];
      const tmp = newPoly(N);
      for (let i = 0; i < K; i++) {
        tmp.fill(0);
        for (let j = 0; j < L; j++) {
          const aij = RejNTTPoly(xof.get(j, i));
          polyAdd(tmp, MultiplyNTTs(aij, s1Hat[j]));
        }
        crystals.NTT.decode(tmp);
        polyAdd(tmp, s2[i]);
        const { r1 } = polyPowerRound(tmp);
        t1.push(r1);
      }
      xof.clean();
      cleanBytes(tmp, s1Hat, _t0, s1, s2);
      return publicCoder.encode([rho, t1]);
    },
    // NOTE: random is optional.
    sign: (msg, secretKey, opts2 = {}) => {
      validateSigOpts(opts2);
      validateInternalOpts(opts2);
      let { extraEntropy: random, externalMu = false } = opts2;
      const [rho, _K, tr, s1, s2, t0] = secretCoder.decode(secretKey);
      const A = [];
      const xof = XOF1282(rho);
      for (let i = 0; i < K; i++) {
        const pv = [];
        for (let j = 0; j < L; j++)
          pv.push(RejNTTPoly(xof.get(j, i)));
        A.push(pv);
      }
      xof.clean();
      for (let i = 0; i < L; i++)
        crystals.NTT.encode(s1[i]);
      for (let i = 0; i < K; i++) {
        crystals.NTT.encode(s2[i]);
        crystals.NTT.encode(t0[i]);
      }
      const mu = externalMu ? msg : (
        // 6: µ ← H(tr||M, 512)
        //    ▷ Compute message representative µ
        shake256.create({ dkLen: CRH_BYTES }).update(tr).update(msg).digest()
      );
      const rnd = random === false ? new Uint8Array(32) : random === void 0 ? randomBytes2(signRandBytes) : random;
      abytesDoc(rnd, 32, "extraEntropy");
      const rhoprime = shake256.create({ dkLen: CRH_BYTES }).update(_K).update(rnd).update(mu).digest();
      abytesDoc(rhoprime, CRH_BYTES);
      const x256 = XOF2562(rhoprime, ZCoder.bytesLen);
      main_loop: for (let kappa = 0; ; ) {
        const y = [];
        for (let i = 0; i < L; i++, kappa++)
          y.push(ZCoder.decode(x256.get(kappa & 255, kappa >> 8)()));
        const z = y.map((i) => crystals.NTT.encode(i.slice()));
        const w = [];
        for (let i = 0; i < K; i++) {
          const wi = newPoly(N);
          for (let j = 0; j < L; j++)
            polyAdd(wi, MultiplyNTTs(A[i][j], z[j]));
          crystals.NTT.decode(wi);
          w.push(wi);
        }
        const w1 = w.map((j) => j.map(HighBits));
        const cTilde = shake256.create({ dkLen: C_TILDE_BYTES }).update(mu).update(W1Vec.encode(w1)).digest();
        const cHat = crystals.NTT.encode(SampleInBall(cTilde));
        const cs1 = s1.map((i) => MultiplyNTTs(i, cHat));
        for (let i = 0; i < L; i++) {
          polyAdd(crystals.NTT.decode(cs1[i]), y[i]);
          if (polyChknorm(cs1[i], GAMMA1 - BETA))
            continue main_loop;
        }
        let cnt = 0;
        const h = [];
        for (let i = 0; i < K; i++) {
          const cs2 = crystals.NTT.decode(MultiplyNTTs(s2[i], cHat));
          const r0 = polySub(w[i], cs2).map(LowBits);
          if (polyChknorm(r0, GAMMA2 - BETA))
            continue main_loop;
          const ct0 = crystals.NTT.decode(MultiplyNTTs(t0[i], cHat));
          if (polyChknorm(ct0, GAMMA2))
            continue main_loop;
          polyAdd(r0, ct0);
          const hint = polyMakeHint(r0, w1[i]);
          h.push(hint.v);
          cnt += hint.cnt;
        }
        if (cnt > OMEGA)
          continue;
        x256.clean();
        const res = sigCoder.encode([cTilde, cs1, h]);
        cleanBytes(cTilde, cs1, h, cHat, w1, w, z, y, rhoprime, s1, s2, t0, ...A);
        if (!externalMu)
          cleanBytes(mu);
        return res;
      }
      throw new Error("Unreachable code path reached, report this error");
    },
    verify: (sig, msg, publicKey, opts2 = {}) => {
      validateInternalOpts(opts2);
      const { externalMu = false } = opts2;
      const [rho, t1] = publicCoder.decode(publicKey);
      const tr = shake256(publicKey, { dkLen: TR_BYTES });
      if (sig.length !== sigCoder.bytesLen)
        return false;
      const [cTilde, z, h] = sigCoder.decode(sig);
      if (h === false)
        return false;
      for (let i = 0; i < L; i++)
        if (polyChknorm(z[i], GAMMA1 - BETA))
          return false;
      const mu = externalMu ? msg : (
        // 7: µ ← H(tr||M, 512)
        shake256.create({ dkLen: CRH_BYTES }).update(tr).update(msg).digest()
      );
      const c = crystals.NTT.encode(SampleInBall(cTilde));
      const zNtt = z.map((i) => i.slice());
      for (let i = 0; i < L; i++)
        crystals.NTT.encode(zNtt[i]);
      const wTick1 = [];
      const xof = XOF1282(rho);
      for (let i = 0; i < K; i++) {
        const ct12d = MultiplyNTTs(crystals.NTT.encode(polyShiftl(t1[i])), c);
        const Az = newPoly(N);
        for (let j = 0; j < L; j++) {
          const aij = RejNTTPoly(xof.get(j, i));
          polyAdd(Az, MultiplyNTTs(aij, zNtt[j]));
        }
        const wApprox = crystals.NTT.decode(polySub(Az, ct12d));
        wTick1.push(polyUseHint(wApprox, h[i]));
      }
      xof.clean();
      const c2 = shake256.create({ dkLen: C_TILDE_BYTES }).update(mu).update(W1Vec.encode(wTick1)).digest();
      for (const t of h) {
        const sum = t.reduce((acc, i) => acc + i, 0);
        if (!(sum <= OMEGA))
          return false;
      }
      for (const t of z)
        if (polyChknorm(t, GAMMA1 - BETA))
          return false;
      return equalBytes(cTilde, c2);
    }
  });
  return Object.freeze({
    info: Object.freeze({ type: "ml-dsa" }),
    internal,
    securityLevel,
    keygen: internal.keygen,
    lengths: internal.lengths,
    getPublicKey: internal.getPublicKey,
    sign: (msg, secretKey, opts2 = {}) => {
      validateSigOpts(opts2);
      const M = getMessage(msg, opts2.context);
      const res = internal.sign(M, secretKey, opts2);
      cleanBytes(M);
      return res;
    },
    verify: (sig, msg, publicKey, opts2 = {}) => {
      validateVerOpts(opts2);
      return internal.verify(sig, getMessage(msg, opts2.context), publicKey);
    },
    prehash: (hash) => {
      checkHash(hash, securityLevel);
      return Object.freeze({
        info: Object.freeze({ type: "hashml-dsa" }),
        securityLevel,
        lengths: internal.lengths,
        keygen: internal.keygen,
        getPublicKey: internal.getPublicKey,
        sign: (msg, secretKey, opts2 = {}) => {
          validateSigOpts(opts2);
          const M = getMessagePrehash(hash, msg, opts2.context);
          const res = internal.sign(M, secretKey, opts2);
          cleanBytes(M);
          return res;
        },
        verify: (sig, msg, publicKey, opts2 = {}) => {
          validateVerOpts(opts2);
          return internal.verify(sig, getMessagePrehash(hash, msg, opts2.context), publicKey);
        }
      });
    }
  });
}
var ml_dsa44 = /* @__PURE__ */ (() => getDilithium({
  ...PARAMS[2],
  CRH_BYTES: 64,
  TR_BYTES: 64,
  C_TILDE_BYTES: 32,
  XOF128,
  XOF256,
  securityLevel: 128
}))();
var ml_dsa65 = /* @__PURE__ */ (() => getDilithium({
  ...PARAMS[3],
  CRH_BYTES: 64,
  TR_BYTES: 64,
  C_TILDE_BYTES: 48,
  XOF128,
  XOF256,
  securityLevel: 192
}))();
var ml_dsa87 = /* @__PURE__ */ (() => getDilithium({
  ...PARAMS[5],
  CRH_BYTES: 64,
  TR_BYTES: 64,
  C_TILDE_BYTES: 64,
  XOF128,
  XOF256,
  securityLevel: 256
}))();

// src/lib/webauthn.js
function formatUuidFromBytes(u8) {
  const b = u8 instanceof Uint8Array ? u8 : new Uint8Array(u8);
  const hex = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  return (hex.slice(0, 8) + "-" + hex.slice(8, 12) + "-" + hex.slice(12, 16) + "-" + hex.slice(16, 20) + "-" + hex.slice(20)).toUpperCase();
}
function coseToJwk(coseKeyBytes) {
  const decoded = decodeMultiple(coseKeyBytes);
  const key = decoded && decoded.length > 0 ? decoded[0] : decode(coseKeyBytes);
  const get = (label) => {
    if (key && typeof key.get === "function") return key.get(label);
    if (key && typeof key === "object") return key[label] ?? key[String(label)];
    return void 0;
  };
  const kty = get(1);
  const alg = get(3);
  if (alg === -7 || alg === -35 || alg === -36) {
    const crv = get(-1);
    const x = get(-2);
    const y = get(-3);
    const namedCurve = crv === 1 ? "P-256" : crv === 2 ? "P-384" : crv === 3 ? "P-521" : null;
    if (!namedCurve) throw new Error("Unknown EC curve");
    return {
      kty: "EC",
      crv: namedCurve,
      x: bytesToBase64Url(new Uint8Array(x)),
      y: bytesToBase64Url(new Uint8Array(y))
    };
  }
  if (alg === -257) {
    const n = get(-1);
    const e = get(-2);
    return {
      kty: "RSA",
      n: bytesToBase64Url(new Uint8Array(n)),
      e: bytesToBase64Url(new Uint8Array(e))
    };
  }
  if (alg === -8 || kty === 1) {
    const crv = get(-1);
    const x = get(-2);
    const crvName = crv === 6 ? "Ed25519" : null;
    if (!crvName) throw new Error("Unknown OKP curve");
    return {
      key: {
        kty: "OKP",
        crv: crvName,
        x: bytesToBase64Url(new Uint8Array(x)).replace(/-/g, "+").replace(/_/g, "/")
      },
      format: "jwk"
    };
  }
  if (alg === -48 || alg === -49 || alg === -50) {
    const pub = get(-1);
    const algName = alg === -48 ? "ML-DSA-44" : alg === -49 ? "ML-DSA-65" : "ML-DSA-87";
    return {
      kty: "AKP",
      alg: algName,
      pub: bytesToBase64Url(new Uint8Array(pub))
    };
  }
  throw new Error("Unknown public key algorithm");
}
function coseToHex(coseKeyBytes) {
  return bytesToHex(coseKeyBytes);
}
function parseAuthenticatorData(authDataBytes) {
  const authData = authDataBytes instanceof Uint8Array ? authDataBytes : new Uint8Array(authDataBytes);
  if (authData.length < 37) throw new Error("authData too short");
  const rpIdHash = authData.slice(0, 32);
  const flags = authData[32];
  const signCount = authData[33] << 24 | authData[34] << 16 | authData[35] << 8 | authData[36];
  const out = {
    rpIdHash,
    flags,
    signCount,
    attestedCredentialData: void 0,
    extensionDataHex: void 0
  };
  if (flags & 64) {
    const aaguidBytes = authData.slice(37, 53);
    const aaguid = formatUuidFromBytes(aaguidBytes);
    const credentialIdLength = authData[53] << 8 | authData[54];
    const credentialId = authData.slice(55, 55 + credentialIdLength);
    const rest = authData.slice(55 + credentialIdLength);
    let coseLen = rest.length;
    for (let n = 1; n <= rest.length; n++) {
      try {
        decode(rest.slice(0, n));
        coseLen = n;
        break;
      } catch {
      }
    }
    const coseKeyBytes = rest.slice(0, coseLen);
    const publicKeyHex = coseToHex(coseKeyBytes);
    const publicKey = coseToJwk(coseKeyBytes);
    out.attestedCredentialData = {
      aaguid,
      credentialId,
      credentialIdLength,
      publicKeyHex,
      publicKey
    };
    if (flags & 128 && coseLen < rest.length) {
      out.extensionDataHex = bytesToHex(rest.slice(coseLen));
    } else {
      out.extensionDataHex = "No extension data";
    }
  } else if (flags & 128) {
    out.extensionDataHex = bytesToHex(authData.slice(37));
  } else {
    out.extensionDataHex = "No extension data";
  }
  return out;
}
function summarizeAuthenticatorData(authenticatorData) {
  const f = authenticatorData.flags;
  return `UP=${f & 1 ? "1" : "0"}, UV=${f & 4 ? "1" : "0"}, BE=${f & 8 ? "1" : "0"}, BS=${f & 16 ? "1" : "0"}, AT=${f & 64 ? "1" : "0"}, ED=${f & 128 ? "1" : "0"}, SignCount=${authenticatorData.signCount}`;
}
async function importVerifyKey(publicKey) {
  if (publicKey.kty === "RSA") {
    return crypto.subtle.importKey(
      "jwk",
      publicKey,
      { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } },
      false,
      ["verify"]
    );
  }
  if (publicKey.kty === "EC") {
    const namedCurve = publicKey.crv;
    return crypto.subtle.importKey(
      "jwk",
      publicKey,
      { name: "ECDSA", namedCurve },
      false,
      ["verify"]
    );
  }
  if (publicKey.key && publicKey.key.kty === "OKP") {
    return crypto.subtle.importKey(
      "jwk",
      publicKey.key,
      { name: "Ed25519" },
      false,
      ["verify"]
    );
  }
  throw new Error("Unsupported key type");
}
async function verifySignature(publicKey, dataBytes, sigBytes) {
  if (publicKey.kty === "AKP") {
    const mldsa = publicKey.alg === "ML-DSA-44" ? ml_dsa44 : publicKey.alg === "ML-DSA-65" ? ml_dsa65 : publicKey.alg === "ML-DSA-87" ? ml_dsa87 : null;
    if (!mldsa) throw new Error(`Unsupported AKP algorithm ${publicKey.alg}`);
    const pub = base64UrlToBytes(publicKey.pub);
    const msg = dataBytes instanceof Uint8Array ? dataBytes : new Uint8Array(dataBytes);
    const s = sigBytes instanceof Uint8Array ? sigBytes : new Uint8Array(sigBytes);
    return mldsa.verify(s, msg, pub);
  }
  const key = await importVerifyKey(publicKey);
  if (publicKey.kty === "RSA") {
    return crypto.subtle.verify(
      { name: "RSASSA-PKCS1-v1_5" },
      key,
      sigBytes,
      dataBytes
    );
  }
  if (publicKey.kty === "EC") {
    const hashName = publicKey.crv === "P-384" ? "SHA-384" : publicKey.crv === "P-521" ? "SHA-512" : "SHA-256";
    const verify = (signatureBytes) => crypto.subtle.verify(
      { name: "ECDSA", hash: { name: hashName } },
      key,
      signatureBytes,
      dataBytes
    );
    const size = publicKey.crv === "P-384" ? 48 : publicKey.crv === "P-521" ? 66 : 32;
    const u8 = sigBytes instanceof Uint8Array ? sigBytes : new Uint8Array(sigBytes);
    let ok = await verify(u8);
    if (ok) return true;
    const asn1Len = (len) => {
      if (len < 128) return new Uint8Array([len]);
      const bytes = [];
      let n = len;
      while (n > 0) {
        bytes.unshift(n & 255);
        n >>= 8;
      }
      return new Uint8Array([128 | bytes.length, ...bytes]);
    };
    const derToRaw = (der, partLen) => {
      const d = der instanceof Uint8Array ? der : new Uint8Array(der);
      let offset = 0;
      if (d[offset++] !== 48) throw new Error("Not a DER sequence");
      let seqLen = d[offset++];
      if (seqLen & 128) {
        const n = seqLen & 127;
        seqLen = 0;
        for (let i = 0; i < n; i++) seqLen = seqLen << 8 | d[offset++];
      }
      if (d[offset++] !== 2) throw new Error("Expected INTEGER (r)");
      let rLen = d[offset++];
      if (rLen & 128) {
        const n = rLen & 127;
        rLen = 0;
        for (let i = 0; i < n; i++) rLen = rLen << 8 | d[offset++];
      }
      let r = d.slice(offset, offset + rLen);
      offset += rLen;
      if (d[offset++] !== 2) throw new Error("Expected INTEGER (s)");
      let sLen = d[offset++];
      if (sLen & 128) {
        const n = sLen & 127;
        sLen = 0;
        for (let i = 0; i < n; i++) sLen = sLen << 8 | d[offset++];
      }
      let s = d.slice(offset, offset + sLen);
      while (r.length > 1 && r[0] === 0) r = r.slice(1);
      while (s.length > 1 && s[0] === 0) s = s.slice(1);
      if (r.length > partLen || s.length > partLen) throw new Error("Invalid DER integer length");
      const out = new Uint8Array(partLen * 2);
      out.set(r, partLen - r.length);
      out.set(s, partLen * 2 - s.length);
      return out;
    };
    const rawToDer = (raw, partLen) => {
      const r0 = raw.slice(0, partLen);
      const s0 = raw.slice(partLen);
      const trimInt = (bytes) => {
        let b = bytes;
        while (b.length > 1 && b[0] === 0) b = b.slice(1);
        if (b[0] & 128) {
          const prefixed = new Uint8Array(b.length + 1);
          prefixed[0] = 0;
          prefixed.set(b, 1);
          b = prefixed;
        }
        return b;
      };
      const r = trimInt(r0);
      const s = trimInt(s0);
      const rLen = asn1Len(r.length);
      const sLen = asn1Len(s.length);
      const seqBodyLen = 2 + rLen.length + r.length + 2 + sLen.length + s.length;
      const seqLen = asn1Len(seqBodyLen);
      const out = new Uint8Array(1 + seqLen.length + seqBodyLen);
      let o = 0;
      out[o++] = 48;
      out.set(seqLen, o);
      o += seqLen.length;
      out[o++] = 2;
      out.set(rLen, o);
      o += rLen.length;
      out.set(r, o);
      o += r.length;
      out[o++] = 2;
      out.set(sLen, o);
      o += sLen.length;
      out.set(s, o);
      return out;
    };
    try {
      if (u8.length > 8 && u8[0] === 48) {
        ok = await verify(derToRaw(u8, size));
        if (ok) return true;
      }
    } catch {
    }
    try {
      if (u8.length === size * 2) {
        ok = await verify(rawToDer(u8, size));
        if (ok) return true;
      }
    } catch {
    }
    return false;
  }
  if (publicKey.key && publicKey.key.kty === "OKP") {
    return crypto.subtle.verify(
      { name: "Ed25519" },
      key,
      sigBytes,
      dataBytes
    );
  }
  throw new Error("Unsupported key type");
}
function concatBytes2(a, b) {
  const aa = a instanceof Uint8Array ? a : new Uint8Array(a);
  const bb = b instanceof Uint8Array ? b : new Uint8Array(b);
  const out = new Uint8Array(aa.length + bb.length);
  out.set(aa, 0);
  out.set(bb, aa.length);
  return out;
}
function expectedCoseAlgForKey(publicKey) {
  if (!publicKey) return null;
  if (publicKey.kty === "EC") {
    return publicKey.crv === "P-256" ? -7 : publicKey.crv === "P-384" ? -35 : publicKey.crv === "P-521" ? -36 : null;
  }
  if (publicKey.kty === "RSA") return -257;
  if (publicKey.key && publicKey.key.kty === "OKP") {
    return publicKey.key.crv === "Ed25519" ? -8 : null;
  }
  if (publicKey.kty === "AKP") {
    return publicKey.alg === "ML-DSA-44" ? -48 : publicKey.alg === "ML-DSA-65" ? -49 : publicKey.alg === "ML-DSA-87" ? -50 : null;
  }
  return null;
}
function coseAlgName(alg) {
  const names = {
    [-7]: "ES256",
    [-35]: "ES384",
    [-36]: "ES512",
    [-257]: "RS256",
    [-258]: "RS384",
    [-259]: "RS512",
    [-37]: "PS256",
    [-38]: "PS384",
    [-39]: "PS512",
    [-8]: "EdDSA",
    [-65535]: "RS1",
    [-48]: "ML-DSA-44",
    [-49]: "ML-DSA-65",
    [-50]: "ML-DSA-87"
  };
  const name = names[alg];
  return name ? `${name} (${alg})` : `alg ${alg}`;
}
function asn1ReadTlv(bytes, offset) {
  const tag = bytes[offset];
  let p = offset + 1;
  let len = bytes[p++];
  if (len & 128) {
    const n = len & 127;
    len = 0;
    for (let i = 0; i < n; i++) len = len << 8 | bytes[p++];
  }
  return { tag, valueStart: p, length: len, end: p + len };
}
function extractSpkiFromCert(certBytes) {
  const cert = asn1ReadTlv(certBytes, 0);
  const tbs = asn1ReadTlv(certBytes, cert.valueStart);
  let p = tbs.valueStart;
  let seqCount = 0;
  while (p < tbs.end) {
    const child = asn1ReadTlv(certBytes, p);
    if (child.tag === 48) {
      seqCount++;
      if (seqCount === 5) return certBytes.slice(p, child.end);
    }
    p = child.end;
  }
  throw new Error("SubjectPublicKeyInfo not found in certificate");
}
function extractRawPublicKeyFromSpki(spki) {
  const seq = asn1ReadTlv(spki, 0);
  const algId = asn1ReadTlv(spki, seq.valueStart);
  const bitStr = asn1ReadTlv(spki, algId.end);
  if (bitStr.tag !== 3) throw new Error("Expected BIT STRING in SubjectPublicKeyInfo");
  return spki.slice(bitStr.valueStart + 1, bitStr.end);
}
function ecdsaDerToRaw(der, partLen) {
  const d = der instanceof Uint8Array ? der : new Uint8Array(der);
  let offset = 0;
  if (d[offset++] !== 48) throw new Error("Not a DER sequence");
  let seqLen = d[offset++];
  if (seqLen & 128) {
    const n = seqLen & 127;
    seqLen = 0;
    for (let i = 0; i < n; i++) seqLen = seqLen << 8 | d[offset++];
  }
  if (d[offset++] !== 2) throw new Error("Expected INTEGER (r)");
  let rLen = d[offset++];
  let r = d.slice(offset, offset + rLen);
  offset += rLen;
  if (d[offset++] !== 2) throw new Error("Expected INTEGER (s)");
  let sLen = d[offset++];
  let s = d.slice(offset, offset + sLen);
  offset += sLen;
  while (r.length > partLen && r[0] === 0) r = r.slice(1);
  while (s.length > partLen && s[0] === 0) s = s.slice(1);
  const out = new Uint8Array(partLen * 2);
  out.set(r, partLen - r.length);
  out.set(s, partLen * 2 - s.length);
  return out;
}
async function verifyX5cLeafSignature(certBytes, alg, sigBytes, signedData) {
  const spki = extractSpkiFromCert(certBytes);
  const ecParams = {
    [-7]: { curve: "P-256", hash: "SHA-256", size: 32 },
    [-35]: { curve: "P-384", hash: "SHA-384", size: 48 },
    [-36]: { curve: "P-521", hash: "SHA-512", size: 66 }
  };
  const rsaPkcs1 = { [-257]: "SHA-256", [-258]: "SHA-384", [-259]: "SHA-512", [-65535]: "SHA-1" };
  const rsaPss = { [-37]: ["SHA-256", 32], [-38]: ["SHA-384", 48], [-39]: ["SHA-512", 64] };
  const mldsaAlg = { [-48]: ml_dsa44, [-49]: ml_dsa65, [-50]: ml_dsa87 };
  if (mldsaAlg[alg]) {
    const mldsa = mldsaAlg[alg];
    const rawPub = extractRawPublicKeyFromSpki(spki);
    const s = sigBytes instanceof Uint8Array ? sigBytes : new Uint8Array(sigBytes);
    const msg = signedData instanceof Uint8Array ? signedData : new Uint8Array(signedData);
    return mldsa.verify(s, msg, rawPub);
  }
  if (ecParams[alg]) {
    const { curve, hash, size } = ecParams[alg];
    const key = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: curve }, false, ["verify"]);
    const u8 = sigBytes instanceof Uint8Array ? sigBytes : new Uint8Array(sigBytes);
    const doVerify = (s) => crypto.subtle.verify({ name: "ECDSA", hash: { name: hash } }, key, s, signedData);
    if (u8.length > 8 && u8[0] === 48) {
      try {
        if (await doVerify(ecdsaDerToRaw(u8, size))) return true;
      } catch {
      }
    }
    if (u8.length === size * 2) {
      if (await doVerify(u8)) return true;
    }
    return false;
  }
  if (rsaPkcs1[alg]) {
    const hash = rsaPkcs1[alg];
    const key = await crypto.subtle.importKey("spki", spki, { name: "RSASSA-PKCS1-v1_5", hash: { name: hash } }, false, ["verify"]);
    return crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, sigBytes, signedData);
  }
  if (rsaPss[alg]) {
    const [hash, saltLength] = rsaPss[alg];
    const key = await crypto.subtle.importKey("spki", spki, { name: "RSA-PSS", hash: { name: hash } }, false, ["verify"]);
    return crypto.subtle.verify({ name: "RSA-PSS", saltLength }, key, sigBytes, signedData);
  }
  throw new Error(`unsupported x5c alg ${alg}`);
}
var TPM_ALG_RSA = 1;
var TPM_ALG_ECC = 35;
var TPM_GENERATED_VALUE = 4283712327;
var TPM_ST_ATTEST_CERTIFY = 32791;
var TPM_HASH_NAME = { 4: "SHA-1", 11: "SHA-256", 12: "SHA-384", 13: "SHA-512" };
var TPM_ECC_CURVE = { 3: "P-256", 4: "P-384", 5: "P-521" };
function bytesEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
function stripLeadingZeros(bytes) {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i++;
  return bytes.slice(i);
}
function bytesToInt(bytes) {
  let v = 0;
  for (let i = 0; i < bytes.length; i++) v = v * 256 + bytes[i];
  return v;
}
function coseAlgHash(alg) {
  if (alg === -65535) return "SHA-1";
  if (alg === -7 || alg === -257 || alg === -37) return "SHA-256";
  if (alg === -35 || alg === -258 || alg === -38) return "SHA-384";
  if (alg === -36 || alg === -259 || alg === -39) return "SHA-512";
  return "SHA-256";
}
function tpmReader(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let o = 0;
  return {
    u16() {
      const v = b[o] << 8 | b[o + 1];
      o += 2;
      return v;
    },
    u32() {
      const v = (b[o] << 24 | b[o + 1] << 16 | b[o + 2] << 8 | b[o + 3]) >>> 0;
      o += 4;
      return v;
    },
    skip(n) {
      o += n;
    },
    sized16() {
      const n = b[o] << 8 | b[o + 1];
      o += 2;
      const v = b.slice(o, o + n);
      o += n;
      return v;
    }
  };
}
function parseTpmPubArea(pubAreaBytes) {
  const r = tpmReader(pubAreaBytes);
  const type = r.u16();
  const nameAlg = r.u16();
  r.u32();
  r.sized16();
  const out = { type, nameAlg };
  if (type === TPM_ALG_RSA) {
    r.u16();
    r.u16();
    const keyBits = r.u16();
    let exponent = r.u32();
    if (exponent === 0) exponent = 65537;
    const modulus = r.sized16();
    out.rsa = { keyBits, exponent, modulus };
  } else if (type === TPM_ALG_ECC) {
    r.u16();
    r.u16();
    const curveId = r.u16();
    r.u16();
    const x = r.sized16();
    const y = r.sized16();
    out.ecc = { curve: TPM_ECC_CURVE[curveId] || null, x, y };
  } else {
    throw new Error(`unsupported TPM key type 0x${type.toString(16)}`);
  }
  return out;
}
function parseTpmCertInfo(certInfoBytes) {
  const r = tpmReader(certInfoBytes);
  const magic = r.u32();
  const type = r.u16();
  r.sized16();
  const extraData = r.sized16();
  r.skip(17);
  r.skip(8);
  const attestedName = r.sized16();
  return { magic, type, extraData, attestedName };
}
function tpmPubMatchesCredential(pub, credentialPublicKey) {
  if (!credentialPublicKey) return false;
  if (credentialPublicKey.kty === "RSA" && pub.rsa) {
    const n = base64UrlToBytes(credentialPublicKey.n);
    if (!bytesEqual(stripLeadingZeros(pub.rsa.modulus), stripLeadingZeros(n))) return false;
    return pub.rsa.exponent === bytesToInt(base64UrlToBytes(credentialPublicKey.e));
  }
  if (credentialPublicKey.kty === "EC" && pub.ecc) {
    if (pub.ecc.curve !== credentialPublicKey.crv) return false;
    const x = base64UrlToBytes(credentialPublicKey.x);
    const y = base64UrlToBytes(credentialPublicKey.y);
    return bytesEqual(stripLeadingZeros(pub.ecc.x), stripLeadingZeros(x)) && bytesEqual(stripLeadingZeros(pub.ecc.y), stripLeadingZeros(y));
  }
  return false;
}
async function verifyTpmAttestation(attStmt, authDataBytes, clientDataHash, credentialPublicKey) {
  const get = (k) => attStmt && typeof attStmt.get === "function" ? attStmt.get(k) : attStmt ? attStmt[k] : void 0;
  const alg = get("alg");
  const sig = get("sig");
  const x5c = get("x5c");
  const certInfo = get("certInfo");
  const pubArea = get("pubArea");
  const ver = get("ver");
  if (ver && String(ver) !== "2.0") return { verified: false, detail: `TPM: unsupported ver ${ver}` };
  if (!sig || !x5c || !x5c.length || !certInfo || !pubArea) return { verified: false, detail: "TPM: missing attestation fields" };
  const toU8 = (v) => v instanceof Uint8Array ? v : new Uint8Array(v);
  const sigBytes = toU8(sig);
  const certInfoBytes = toU8(certInfo);
  const pubAreaBytes = toU8(pubArea);
  const algName = coseAlgName(alg);
  try {
    const pub = parseTpmPubArea(pubAreaBytes);
    if (!tpmPubMatchesCredential(pub, credentialPublicKey)) {
      return { verified: false, detail: "TPM: pubArea does not match credential public key" };
    }
    const ci = parseTpmCertInfo(certInfoBytes);
    if (ci.magic !== TPM_GENERATED_VALUE) return { verified: false, detail: "TPM: invalid magic in certInfo" };
    if (ci.type !== TPM_ST_ATTEST_CERTIFY) return { verified: false, detail: "TPM: certInfo is not TPM_ST_ATTEST_CERTIFY" };
    const attToBeSigned = concatBytes2(authDataBytes, clientDataHash);
    const extraExpected = new Uint8Array(await crypto.subtle.digest(coseAlgHash(alg), attToBeSigned));
    if (!bytesEqual(ci.extraData, extraExpected)) return { verified: false, detail: "TPM: certInfo extraData mismatch" };
    const nameHash = TPM_HASH_NAME[pub.nameAlg];
    if (!nameHash) return { verified: false, detail: `TPM: unsupported nameAlg 0x${pub.nameAlg.toString(16)}` };
    const pubAreaHash = new Uint8Array(await crypto.subtle.digest(nameHash, pubAreaBytes));
    const expectedName = concatBytes2(new Uint8Array([pub.nameAlg >> 8 & 255, pub.nameAlg & 255]), pubAreaHash);
    if (!bytesEqual(ci.attestedName, expectedName)) return { verified: false, detail: "TPM: attested name mismatch" };
    const leaf = toU8(x5c[0]);
    const ok = await verifyX5cLeafSignature(leaf, alg, sigBytes, certInfoBytes);
    return ok ? { verified: true, detail: `TPM: Attestation verified using ${algName}` } : { verified: false, detail: `TPM: Signature invalid (${algName})` };
  } catch (e) {
    return { verified: false, detail: `TPM: ${e?.message || e}` };
  }
}
async function verifyPackedAttestation(attStmt, authDataBytes, clientDataHash, credentialPublicKey) {
  const get = (k) => attStmt && typeof attStmt.get === "function" ? attStmt.get(k) : attStmt ? attStmt[k] : void 0;
  const alg = get("alg");
  const sig = get("sig");
  const x5c = get("x5c");
  if (typeof sig === "undefined" || sig === null) {
    return { verified: false, detail: "packed: missing signature" };
  }
  const sigBytes = sig instanceof Uint8Array ? sig : new Uint8Array(sig);
  const signedData = concatBytes2(authDataBytes, clientDataHash);
  if (x5c && x5c.length) {
    const leaf = x5c[0];
    const certBytes = leaf instanceof Uint8Array ? leaf : new Uint8Array(leaf);
    const algName = coseAlgName(alg);
    try {
      const ok = await verifyX5cLeafSignature(certBytes, alg, sigBytes, signedData);
      return ok ? { verified: true, detail: `Packed (x5c): Attestation signature verified using ${algName}` } : { verified: false, detail: `Packed (x5c): Attestation signature invalid (${algName})` };
    } catch (e) {
      return { verified: false, detail: `Packed (x5c): ${e?.message || e}` };
    }
  }
  const expectedAlg = expectedCoseAlgForKey(credentialPublicKey);
  if (typeof alg !== "undefined" && expectedAlg !== null && alg !== expectedAlg) {
    return { verified: false, detail: `Packed (self): alg ${alg} does not match credential key alg ${expectedAlg}` };
  }
  try {
    const ok = await verifySignature(credentialPublicKey, signedData, sigBytes);
    const algName = coseAlgName(typeof alg !== "undefined" ? alg : expectedAlg);
    return ok ? { verified: true, detail: `Packed (self) Verified using ${algName}` } : { verified: false, detail: `Packed (self): Signature invalid (${algName})` };
  } catch (e) {
    return { verified: false, detail: `Packed (self): ${e?.message || e}` };
  }
}
async function makeCredential(uid, attestation, hostname) {
  if (!attestation?.id) throw new Error("id is missing");
  if (!attestation?.attestationObject) throw new Error("attestationObject is missing");
  if (!attestation?.clientDataJSON) throw new Error("clientDataJSON is missing");
  let clientData;
  try {
    clientData = JSON.parse(attestation.clientDataJSON);
  } catch {
    throw new Error("clientDataJSON could not be parsed");
  }
  let origin;
  try {
    origin = new URL(clientData.origin);
  } catch {
    throw new Error("Invalid origin in collectedClientData");
  }
  if (origin.hostname !== hostname) throw new Error(`Invalid origin in collectedClientData. Expected hostname ${hostname}`);
  if (hostname !== "localhost" && origin.protocol !== "https:") throw new Error("Invalid origin in collectedClientData. Expected HTTPS protocol.");
  const clientDataHash = await sha256Utf8(attestation.clientDataJSON);
  const attObjBytes = base64ToBytes(attestation.attestationObject);
  const attestationObject = decode(attObjBytes);
  const authDataBytes = new Uint8Array(attestationObject.authData);
  const authenticatorData = parseAuthenticatorData(authDataBytes);
  if (!authenticatorData.attestedCredentialData) throw new Error("Did not see AD flag in authenticatorData");
  const expectedRpId = attestation && attestation.metadata && typeof attestation.metadata.rpId !== "undefined" ? attestation.metadata.rpId : hostname;
  const expectedRpIdHash = await sha256Utf8(expectedRpId);
  if (bytesToHex(authenticatorData.rpIdHash) !== bytesToHex(expectedRpIdHash)) {
    throw new Error(`RPID hash does not match expected value: sha256(${expectedRpId})`);
  }
  if ((authenticatorData.flags & 1) === 0) throw new Error("User Present bit was not set.");
  const fmt = String(attestationObject.fmt || "unknown");
  let attStmtHex = "UNVERIFIED";
  try {
    if (typeof attestationObject.attStmt !== "undefined") {
      attStmtHex = bytesToHex(new Uint8Array(encode(attestationObject.attStmt)));
    }
  } catch {
    attStmtHex = "UNVERIFIED";
  }
  let attestationVerified = false;
  let attestationVerification = `Verification Skipped`;
  if (fmt === "none") {
    attestationVerification = "None (no attestation)";
  } else if (fmt === "packed") {
    const result = await verifyPackedAttestation(
      attestationObject.attStmt,
      authDataBytes,
      clientDataHash,
      authenticatorData.attestedCredentialData.publicKey
    );
    attestationVerified = result.verified;
    attestationVerification = result.detail;
  } else if (fmt === "tpm") {
    const result = await verifyTpmAttestation(
      attestationObject.attStmt,
      authDataBytes,
      clientDataHash,
      authenticatorData.attestedCredentialData.publicKey
    );
    attestationVerified = result.verified;
    attestationVerification = result.detail;
  }
  const credential = {
    uid,
    id: bytesToBase64(authenticatorData.attestedCredentialData.credentialId),
    idHex: bytesToHex(authenticatorData.attestedCredentialData.credentialId),
    transports: attestation.transports,
    enabled: true,
    metadata: {
      rpId: expectedRpId,
      userName: attestation?.metadata?.userName,
      residentKey: !!attestation?.metadata?.residentKey
    },
    creationData: {
      publicKey: JSON.stringify(authenticatorData.attestedCredentialData.publicKey),
      publicKeySummary: authenticatorData.attestedCredentialData.publicKey.kty,
      publicKeyHex: authenticatorData.attestedCredentialData.publicKeyHex,
      aaguid: authenticatorData.attestedCredentialData.aaguid,
      attestationStatementHex: attStmtHex || "UNAVAILABLE",
      attestationStatementSummary: fmt,
      attestationVerified,
      attestationVerification,
      attestationStatementChainJSON: "none",
      authenticatorDataSummary: summarizeAuthenticatorData(authenticatorData),
      authenticatorDataHex: bytesToHex(authDataBytes),
      extensionDataHex: authenticatorData.extensionDataHex,
      fullResponseJSON: attestation && typeof attestation.fullResponseJSON !== "undefined" ? attestation.fullResponseJSON : null,
      fullRequestJSON: attestation && typeof attestation.fullRequestJSON !== "undefined" ? attestation.fullRequestJSON : null,
      authenticatorData: attestation.authenticatorData,
      attestationObject: attestation.attestationObjectHex,
      clientDataJSON: attestation.clientDataJSON,
      clientDataJSONHex: bytesToHex(utf8ToBytes(attestation.clientDataJSON)),
      publicKey2: attestation.publicKey,
      publicKeyAlgorithm: attestation.publicKeyAlgorithm,
      authenticatorAttachment: attestation.authenticatorAttachment,
      prfEnabled: attestation.prfEnabled,
      prfFirst: attestation.prfFirst,
      prfSecond: attestation.prfSecond
    },
    authenticationData: {
      authenticatorDataSummary: "No authentications",
      signCount: authenticatorData.signCount,
      userHandleHex: "none",
      authenticatorDataHex: "none",
      clientDataJSON: "none",
      clientDataJSONHex: "none",
      signatureHex: "none",
      extensionDataHex: "No extension data",
      authenticatorAttachment: "none",
      fullRequestJSON: null,
      prfFirst: "none",
      prfSecond: "none"
    }
  };
  return credential;
}
async function verifyAssertion(credential, assertion, hostname) {
  if (!credential) throw new Error("Credential not found");
  let clientData;
  try {
    clientData = JSON.parse(assertion.clientDataJSON);
  } catch {
    throw new Error("clientDataJSON could not be parsed");
  }
  let origin;
  try {
    origin = new URL(clientData.origin);
  } catch {
    throw new Error("Invalid origin in collectedClientData");
  }
  if (origin.hostname !== hostname) throw new Error(`Invalid origin in collectedClientData. Expected hostname ${hostname}`);
  if (hostname !== "localhost" && origin.protocol !== "https:") throw new Error("Invalid origin in collectedClientData. Expected HTTPS protocol.");
  const authData = base64ToBytes(assertion.authenticatorData);
  const sig = base64ToBytes(assertion.signature);
  const authenticatorData = parseAuthenticatorData(authData);
  const expectedRpId = assertion && assertion.metadata && typeof assertion.metadata.rpId !== "undefined" ? assertion.metadata.rpId : hostname;
  const expectedRpIdHash = await sha256Utf8(expectedRpId);
  if (bytesToHex(authenticatorData.rpIdHash) !== bytesToHex(expectedRpIdHash)) {
    throw new Error(`RPID hash does not match expected value: sha256(${expectedRpId})`);
  }
  if ((authenticatorData.flags & 1) === 0) throw new Error("User Present bit was not set.");
  const clientHash = await sha256Utf8(assertion.clientDataJSON);
  const data = new Uint8Array(authData.length + clientHash.length);
  data.set(authData, 0);
  data.set(clientHash, authData.length);
  const publicKey = JSON.parse(credential.creationData.publicKey);
  const ok = await verifySignature(publicKey, data, sig);
  if (!ok) throw new Error("Could not verify signature");
  const prevSignCount = credential?.authenticationData?.signCount ?? 0;
  if (authenticatorData.signCount !== 0 && authenticatorData.signCount < prevSignCount) {
    throw new Error(`Received signCount of ${authenticatorData.signCount} expected signCount > ${prevSignCount}`);
  }
  credential.authenticationData = {
    authenticatorDataSummary: summarizeAuthenticatorData(authenticatorData),
    signCount: authenticatorData.signCount,
    userHandleHex: assertion.userHandle ? bytesToHex(base64ToBytes(assertion.userHandle)) : "none",
    authenticatorDataHex: bytesToHex(authData),
    clientDataJSON: assertion.clientDataJSON,
    clientDataJSONHex: bytesToHex(utf8ToBytes(assertion.clientDataJSON)),
    signatureHex: bytesToHex(sig),
    extensionDataHex: authenticatorData.extensionDataHex,
    authenticatorAttachment: assertion.authenticatorAttachment,
    fullResponseJSON: assertion && typeof assertion.fullResponseJSON !== "undefined" ? assertion.fullResponseJSON : null,
    fullRequestJSON: assertion && typeof assertion.fullRequestJSON !== "undefined" ? assertion.fullRequestJSON : null,
    prfFirst: assertion.prfFirst,
    prfSecond: assertion.prfSecond
  };
  return credential;
}

// src/client-backend.js
var DB_NAME = "passkey-playground";
var DB_VERSION = 1;
var STORE_NAME = "credentials";
var CHALLENGES_KEY = "passkey.pendingChallenges";
var CHALLENGE_TTL_MS = 5 * 60 * 1e3;
function requestResult(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error("IndexedDB request failed"));
  });
}
function transactionDone(transaction) {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(transaction.error || new Error("IndexedDB transaction aborted"));
    transaction.onerror = () => reject(transaction.error || new Error("IndexedDB transaction failed"));
  });
}
function openDatabase() {
  if (!globalThis.indexedDB) {
    return Promise.reject(new Error("IndexedDB is not available in this browser"));
  }
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      const store = db.createObjectStore(STORE_NAME, { keyPath: "key" });
      store.createIndex("uidRpId", ["uid", "rpId"], { unique: false });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error("Unable to open IndexedDB"));
  });
}
async function userId(username) {
  const normalized = normalizeUsername(username);
  if (!normalized || normalized.length < 3 || normalized.includes(" ")) {
    throw new Error("Invalid username. Please sign out and sign back in.");
  }
  return hashUsername(normalized);
}
function credentialKey(uid, id2) {
  return `${uid}:${id2}`;
}
function loadPendingChallenges() {
  try {
    const parsed = JSON.parse(sessionStorage.getItem(CHALLENGES_KEY) || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}
function savePendingChallenges(challenges) {
  sessionStorage.setItem(CHALLENGES_KEY, JSON.stringify(challenges));
}
function prunePendingChallenges(challenges, now = Date.now()) {
  return challenges.filter((entry) => entry && entry.challenge && entry.expiresAt > now);
}
function validateClientData(payload, expectedType) {
  let clientData;
  try {
    clientData = JSON.parse(payload?.clientDataJSON);
  } catch {
    throw new Error("clientDataJSON could not be parsed");
  }
  if (clientData.type !== expectedType) {
    throw new Error(`collectedClientData type was expected to be ${expectedType}`);
  }
  const challenge = normalizeBase64Url(clientData.challenge);
  const now = Date.now();
  const pending = prunePendingChallenges(loadPendingChallenges(), now);
  const matchIndex = pending.findIndex(
    (entry) => entry.challenge === challenge && entry.type === expectedType
  );
  if (matchIndex < 0) {
    savePendingChallenges(pending);
    throw new Error("Challenge is missing, expired, or has already been used");
  }
  return pending[matchIndex].challenge;
}
function consumeChallenge(challenge) {
  const pending = prunePendingChallenges(loadPendingChallenges());
  const matchIndex = pending.findIndex((entry) => entry.challenge === challenge);
  if (matchIndex >= 0) pending.splice(matchIndex, 1);
  savePendingChallenges(pending);
}
async function getRecord(uid, id2) {
  const db = await openDatabase();
  try {
    const transaction = db.transaction(STORE_NAME, "readonly");
    return await requestResult(transaction.objectStore(STORE_NAME).get(credentialKey(uid, id2)));
  } finally {
    db.close();
  }
}
async function putCredential(credential, createdAt = Date.now()) {
  const db = await openDatabase();
  try {
    const transaction = db.transaction(STORE_NAME, "readwrite");
    transaction.objectStore(STORE_NAME).put({
      key: credentialKey(credential.uid, credential.id),
      uid: credential.uid,
      rpId: credential.metadata.rpId,
      createdAt,
      data: credential
    });
    await transactionDone(transaction);
  } finally {
    db.close();
  }
  return credential;
}
function createChallenge(type = "webauthn.get") {
  if (type !== "webauthn.get" && type !== "webauthn.create") {
    throw new Error("Invalid challenge type");
  }
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const challenge = bytesToBase64Url(bytes);
  const pending = prunePendingChallenges(loadPendingChallenges());
  pending.push({ challenge, type, expiresAt: Date.now() + CHALLENGE_TTL_MS });
  savePendingChallenges(pending);
  return bytes.buffer;
}
async function listCredentials(username, rpId) {
  const uid = await userId(username);
  const db = await openDatabase();
  try {
    const transaction = db.transaction(STORE_NAME, "readonly");
    const index = transaction.objectStore(STORE_NAME).index("uidRpId");
    const records = await requestResult(index.getAll(IDBKeyRange.only([uid, rpId])));
    return records.sort((a, b) => b.createdAt - a.createdAt).map((record) => record.data);
  } finally {
    db.close();
  }
}
async function saveRegistration(username, attestation, hostname) {
  const challenge = validateClientData(attestation, "webauthn.create");
  const uid = await userId(username);
  const credential = await makeCredential(uid, attestation, hostname);
  await putCredential(credential);
  consumeChallenge(challenge);
  return { id: credential.id };
}
async function saveAssertion(username, assertion, hostname) {
  const challenge = validateClientData(assertion, "webauthn.get");
  const uid = await userId(username);
  const record = await getRecord(uid, assertion.id);
  if (!record) throw new Error("Credential not found in this browser");
  if (record.data.enabled === false) throw new Error("Credential is disabled");
  const credential = await verifyAssertion(record.data, assertion, hostname);
  await putCredential(credential, record.createdAt);
  consumeChallenge(challenge);
  return credential;
}
async function deleteCredential(username, id2) {
  const uid = await userId(username);
  const db = await openDatabase();
  try {
    const transaction = db.transaction(STORE_NAME, "readwrite");
    transaction.objectStore(STORE_NAME).delete(credentialKey(uid, id2));
    await transactionDone(transaction);
  } finally {
    db.close();
  }
}
async function updateCredentialTransports(username, id2, transports) {
  const allowed = /* @__PURE__ */ new Set(["internal", "usb", "nfc", "ble", "hybrid"]);
  const clean2 = Array.isArray(transports) ? transports.filter((transport, index) => allowed.has(transport) && transports.indexOf(transport) === index) : [];
  const uid = await userId(username);
  const record = await getRecord(uid, id2);
  if (!record) throw new Error("Credential not found in this browser");
  record.data.transports = clean2;
  await putCredential(record.data, record.createdAt);
  return { id: id2, transports: clean2 };
}
async function updateCredentialEnabled(username, id2, enabled) {
  if (typeof enabled !== "boolean") throw new Error("enabled must be boolean");
  const uid = await userId(username);
  const record = await getRecord(uid, id2);
  if (!record) throw new Error("Credential not found in this browser");
  record.data.enabled = enabled;
  await putCredential(record.data, record.createdAt);
  return { id: id2, enabled };
}
export {
  createChallenge,
  deleteCredential,
  listCredentials,
  saveAssertion,
  saveRegistration,
  updateCredentialEnabled,
  updateCredentialTransports
};
/*! Bundled license information:

@noble/curves/utils.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@noble/post-quantum/utils.js:
@noble/post-quantum/_crystals.js:
@noble/post-quantum/ml-dsa.js:
  (*! noble-post-quantum - MIT License (c) 2024 Paul Miller (paulmillr.com) *)
*/
