var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
import { connect } from "cloudflare:sockets";
function tlsToUint8Array(data) {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return new Uint8Array(data || 0);
}
__name(tlsToUint8Array, "tlsToUint8Array");
var TLS_VERSION_10 = 769;
var TLS_VERSION_12 = 771;
var TLS_VERSION_13 = 772;
var CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20;
var CONTENT_TYPE_ALERT = 21;
var CONTENT_TYPE_HANDSHAKE = 22;
var CONTENT_TYPE_APPLICATION_DATA = 23;
var HANDSHAKE_TYPE_CLIENT_HELLO = 1;
var HANDSHAKE_TYPE_SERVER_HELLO = 2;
var HANDSHAKE_TYPE_NEW_SESSION_TICKET = 4;
var HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 8;
var HANDSHAKE_TYPE_CERTIFICATE = 11;
var HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 12;
var HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 13;
var HANDSHAKE_TYPE_SERVER_HELLO_DONE = 14;
var HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 15;
var HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 16;
var HANDSHAKE_TYPE_FINISHED = 20;
var HANDSHAKE_TYPE_KEY_UPDATE = 24;
var EXT_SERVER_NAME = 0;
var EXT_SUPPORTED_GROUPS = 10;
var EXT_EC_POINT_FORMATS = 11;
var EXT_SIGNATURE_ALGORITHMS = 13;
var EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16;
var EXT_SUPPORTED_VERSIONS = 43;
var EXT_PSK_KEY_EXCHANGE_MODES = 45;
var EXT_KEY_SHARE = 51;
var ALERT_CLOSE_NOTIFY = 0;
var ALERT_LEVEL_WARNING = 1;
var ALERT_UNRECOGNIZED_NAME = 112;
var shouldIgnoreTlsAlert = (fragment) => fragment?.[0] === ALERT_LEVEL_WARNING && fragment?.[1] === ALERT_UNRECOGNIZED_NAME;
var textEncoder = new TextEncoder();
var textDecoder = new TextDecoder();
var EMPTY_BYTES = new Uint8Array(0);
var CIPHER_SUITES_BY_ID = new Map([
  [4865, { id: 4865, keyLen: 16, ivLen: 12, hash: "SHA-256", tls13: true }],
  [4866, { id: 4866, keyLen: 32, ivLen: 12, hash: "SHA-384", tls13: true }],
  [4867, { id: 4867, keyLen: 32, ivLen: 12, hash: "SHA-256", tls13: true, chacha: true }],
  [49199, { id: 49199, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE" }],
  [49200, { id: 49200, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE" }],
  [52392, { id: 52392, keyLen: 32, ivLen: 12, hash: "SHA-256", kex: "ECDHE", chacha: true }],
  [49195, { id: 49195, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE" }],
  [49196, { id: 49196, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE" }],
  [52393, { id: 52393, keyLen: 32, ivLen: 12, hash: "SHA-256", kex: "ECDHE", chacha: true }]
]);
var GROUPS_BY_ID = new Map([[29, "X25519"], [23, "P-256"]]);
var SUPPORTED_SIGNATURE_ALGORITHMS = [2052, 2053, 2054, 1025, 1281, 1537, 1027, 1283, 1539];
var tlsBytes = (...parts) => {
  const flattenBytes = (values) => values.flatMap((value) => value instanceof Uint8Array ? [...value] : Array.isArray(value) ? flattenBytes(value) : "number" == typeof value ? [value] : []);
  return new Uint8Array(flattenBytes(parts));
};
var uint16be = (value) => [value >> 8 & 255, 255 & value];
var readUint16 = (buffer, offset) => buffer[offset] << 8 | buffer[offset + 1];
var readUint24 = (buffer, offset) => buffer[offset] << 16 | buffer[offset + 1] << 8 | buffer[offset + 2];
var concatBytes = (...chunks) => {
  const nonEmptyChunks = chunks.filter(((chunk) => chunk && chunk.length > 0)), length = nonEmptyChunks.reduce(((total, chunk) => total + chunk.length), 0), result = new Uint8Array(length);
  let offset = 0;
  for (const chunk of nonEmptyChunks) result.set(chunk, offset), offset += chunk.length;
  return result;
};
var randomBytes = (length) => crypto.getRandomValues(new Uint8Array(length));
var constantTimeEqual = (left, right) => {
  if (!left || !right || left.length !== right.length) return false;
  let diff = 0;
  for (let index = 0; index < left.length; index++) diff |= left[index] ^ right[index];
  return 0 === diff;
};
var hashByteLength = (hash) => "SHA-512" === hash ? 64 : "SHA-384" === hash ? 48 : 32;
async function hmac(hash, key, data) {
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, data));
}
__name(hmac, "hmac");
async function digestBytes(hash, data) {
  return new Uint8Array(await crypto.subtle.digest(hash, data));
}
__name(digestBytes, "digestBytes");
async function tls12Prf(secret, label, seed, length, hash = "SHA-256") {
  const labelSeed = concatBytes(textEncoder.encode(label), seed);
  let output = new Uint8Array(0), currentA = labelSeed;
  for (; output.length < length; ) {
    currentA = await hmac(hash, secret, currentA);
    const block = await hmac(hash, secret, concatBytes(currentA, labelSeed));
    output = concatBytes(output, block);
  }
  return output.slice(0, length);
}
__name(tls12Prf, "tls12Prf");
async function hkdfExtract(hash, salt, inputKeyMaterial) {
  return salt && salt.length || (salt = new Uint8Array(hashByteLength(hash))), hmac(hash, salt, inputKeyMaterial);
}
__name(hkdfExtract, "hkdfExtract");
async function hkdfExpandLabel(hash, secret, label, context, length) {
  const fullLabel = textEncoder.encode("tls13 " + label);
  return (async function(hash2, secret2, info, length2) {
    const hashLen = hashByteLength(hash2), roundCount = Math.ceil(length2 / hashLen);
    let output = new Uint8Array(0), previousBlock = new Uint8Array(0);
    for (let round = 1; round <= roundCount; round++) previousBlock = await hmac(hash2, secret2, concatBytes(previousBlock, info, [round])), output = concatBytes(output, previousBlock);
    return output.slice(0, length2);
  })(hash, secret, tlsBytes(uint16be(length), fullLabel.length, fullLabel, context.length, context), length);
}
__name(hkdfExpandLabel, "hkdfExpandLabel");
async function generateKeyShare(group = "P-256") {
  const algorithm = "X25519" === group ? { name: "X25519" } : { name: "ECDH", namedCurve: group };
  const keyPair = await crypto.subtle.generateKey(algorithm, true, ["deriveBits"]);
  const publicKeyRaw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
  return { keyPair, publicKeyRaw: new Uint8Array(publicKeyRaw) };
}
__name(generateKeyShare, "generateKeyShare");
async function deriveSharedSecret(privateKey, peerPublicKey, group = "P-256") {
  const algorithm = "X25519" === group ? { name: "X25519" } : { name: "ECDH", namedCurve: group }, peerKey = await crypto.subtle.importKey("raw", peerPublicKey, algorithm, false, []), bits = "P-384" === group ? 384 : "P-521" === group ? 528 : 256;
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: algorithm.name, public: peerKey },
    privateKey,
    bits
  ));
}
__name(deriveSharedSecret, "deriveSharedSecret");
async function importAesGcmKey(key, usages) {
  return crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, usages);
}
__name(importAesGcmKey, "importAesGcmKey");
async function aesGcmEncryptWithKey(cryptoKey, initializationVector, plaintext, additionalData) {
  return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: initializationVector, additionalData, tagLength: 128 }, cryptoKey, plaintext));
}
__name(aesGcmEncryptWithKey, "aesGcmEncryptWithKey");
async function aesGcmDecryptWithKey(cryptoKey, initializationVector, ciphertext, additionalData) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: initializationVector, additionalData, tagLength: 128 }, cryptoKey, ciphertext));
}
__name(aesGcmDecryptWithKey, "aesGcmDecryptWithKey");
function rotateLeft32(value, bits) {
  return (value << bits | value >>> 32 - bits) >>> 0;
}
__name(rotateLeft32, "rotateLeft32");
function chachaQuarterRound(state, indexA, indexB, indexC, indexD) {
  state[indexA] = state[indexA] + state[indexB] >>> 0, state[indexD] = rotateLeft32(state[indexD] ^ state[indexA], 16), state[indexC] = state[indexC] + state[indexD] >>> 0, state[indexB] = rotateLeft32(state[indexB] ^ state[indexC], 12), state[indexA] = state[indexA] + state[indexB] >>> 0, state[indexD] = rotateLeft32(state[indexD] ^ state[indexA], 8), state[indexC] = state[indexC] + state[indexD] >>> 0, state[indexB] = rotateLeft32(state[indexB] ^ state[indexC], 7);
}
__name(chachaQuarterRound, "chachaQuarterRound");
function chacha20Block(key, counter, nonce) {
  const state = new Uint32Array(16);
  state[0] = 1634760805, state[1] = 857760878, state[2] = 2036477234, state[3] = 1797285236;
  const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
  for (let wordIndex = 0; wordIndex < 8; wordIndex++) state[4 + wordIndex] = keyView.getUint32(4 * wordIndex, true);
  state[12] = counter;
  const nonceView = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
  state[13] = nonceView.getUint32(0, true), state[14] = nonceView.getUint32(4, true), state[15] = nonceView.getUint32(8, true);
  const workingState = new Uint32Array(state);
  for (let round = 0; round < 10; round++) chachaQuarterRound(workingState, 0, 4, 8, 12), chachaQuarterRound(workingState, 1, 5, 9, 13), chachaQuarterRound(workingState, 2, 6, 10, 14), chachaQuarterRound(workingState, 3, 7, 11, 15), chachaQuarterRound(workingState, 0, 5, 10, 15), chachaQuarterRound(workingState, 1, 6, 11, 12), chachaQuarterRound(workingState, 2, 7, 8, 13), chachaQuarterRound(workingState, 3, 4, 9, 14);
  for (let wordIndex = 0; wordIndex < 16; wordIndex++) workingState[wordIndex] = workingState[wordIndex] + state[wordIndex] >>> 0;
  return new Uint8Array(workingState.buffer.slice(0));
}
__name(chacha20Block, "chacha20Block");
function chacha20Xor(key, nonce, data) {
  const output = new Uint8Array(data.length);
  let counter = 1;
  for (let offset = 0; offset < data.length; offset += 64) {
    const block = chacha20Block(key, counter++, nonce), blockLength = Math.min(64, data.length - offset);
    for (let index = 0; index < blockLength; index++) output[offset + index] = data[offset + index] ^ block[index];
  }
  return output;
}
__name(chacha20Xor, "chacha20Xor");
function poly1305Mac(key, message) {
  const rKey = (function(rBytes) {
    const clamped = new Uint8Array(rBytes);
    return clamped[3] &= 15, clamped[7] &= 15, clamped[11] &= 15, clamped[15] &= 15, clamped[4] &= 252, clamped[8] &= 252, clamped[12] &= 252, clamped;
  })(key.slice(0, 16)), sKey = key.slice(16, 32);
  let accumulator = [0n, 0n, 0n, 0n, 0n];
  const rLimbs = [0x3ffffffn & BigInt(rKey[0] | rKey[1] << 8 | rKey[2] << 16 | rKey[3] << 24), 0x3ffffffn & BigInt(rKey[3] >> 2 | rKey[4] << 6 | rKey[5] << 14 | rKey[6] << 22), 0x3ffffffn & BigInt(rKey[6] >> 4 | rKey[7] << 4 | rKey[8] << 12 | rKey[9] << 20), 0x3ffffffn & BigInt(rKey[9] >> 6 | rKey[10] << 2 | rKey[11] << 10 | rKey[12] << 18), 0x3ffffffn & BigInt(rKey[13] | rKey[14] << 8 | rKey[15] << 16)];
  for (let offset = 0; offset < message.length; offset += 16) {
    const chunk = message.slice(offset, offset + 16), paddedChunk = new Uint8Array(17);
    paddedChunk.set(chunk), paddedChunk[chunk.length] = 1, accumulator[0] += BigInt(paddedChunk[0] | paddedChunk[1] << 8 | paddedChunk[2] << 16 | (3 & paddedChunk[3]) << 24), accumulator[1] += BigInt(paddedChunk[3] >> 2 | paddedChunk[4] << 6 | paddedChunk[5] << 14 | (15 & paddedChunk[6]) << 22), accumulator[2] += BigInt(paddedChunk[6] >> 4 | paddedChunk[7] << 4 | paddedChunk[8] << 12 | (63 & paddedChunk[9]) << 20), accumulator[3] += BigInt(paddedChunk[9] >> 6 | paddedChunk[10] << 2 | paddedChunk[11] << 10 | paddedChunk[12] << 18), accumulator[4] += BigInt(paddedChunk[13] | paddedChunk[14] << 8 | paddedChunk[15] << 16 | paddedChunk[16] << 24);
    const product = [0n, 0n, 0n, 0n, 0n];
    for (let accIndex = 0; accIndex < 5; accIndex++)
      for (let rIndex = 0; rIndex < 5; rIndex++) {
        const limbIndex = accIndex + rIndex;
        limbIndex < 5 ? product[limbIndex] += accumulator[accIndex] * rLimbs[rIndex] : product[limbIndex - 5] += accumulator[accIndex] * rLimbs[rIndex] * 5n;
      }
    let carry = 0n;
    for (let index = 0; index < 5; index++) product[index] += carry, accumulator[index] = 0x3ffffffn & product[index], carry = product[index] >> 26n;
    accumulator[0] += 5n * carry, carry = accumulator[0] >> 26n, accumulator[0] &= 0x3ffffffn, accumulator[1] += carry;
  }
  let tagValue = accumulator[0] | accumulator[1] << 26n | accumulator[2] << 52n | accumulator[3] << 78n | accumulator[4] << 104n;
  tagValue = tagValue + sKey.reduce(((total, byte, index) => total + (BigInt(byte) << BigInt(8 * index))), 0n) & (1n << 128n) - 1n;
  const tag = new Uint8Array(16);
  for (let index = 0; index < 16; index++) tag[index] = Number(tagValue >> BigInt(8 * index) & 0xffn);
  return tag;
}
__name(poly1305Mac, "poly1305Mac");
function chacha20Poly1305Encrypt(key, nonce, plaintext, additionalData) {
  const polyKey = chacha20Block(key, 0, nonce).slice(0, 32), ciphertext = chacha20Xor(key, nonce, plaintext), aadPadding = (16 - additionalData.length % 16) % 16, ciphertextPadding = (16 - ciphertext.length % 16) % 16, macData = new Uint8Array(additionalData.length + aadPadding + ciphertext.length + ciphertextPadding + 16);
  macData.set(additionalData, 0), macData.set(ciphertext, additionalData.length + aadPadding);
  const lengthView = new DataView(macData.buffer, additionalData.length + aadPadding + ciphertext.length + ciphertextPadding);
  lengthView.setBigUint64(0, BigInt(additionalData.length), true), lengthView.setBigUint64(8, BigInt(ciphertext.length), true);
  const tag = poly1305Mac(polyKey, macData);
  return concatBytes(ciphertext, tag);
}
__name(chacha20Poly1305Encrypt, "chacha20Poly1305Encrypt");
function chacha20Poly1305Decrypt(key, nonce, ciphertext, additionalData) {
  if (ciphertext.length < 16) throw new Error("Ciphertext too short");
  const tag = ciphertext.slice(-16), encryptedData = ciphertext.slice(0, -16), polyKey = chacha20Block(key, 0, nonce).slice(0, 32), aadPadding = (16 - additionalData.length % 16) % 16, ciphertextPadding = (16 - encryptedData.length % 16) % 16, macData = new Uint8Array(additionalData.length + aadPadding + encryptedData.length + ciphertextPadding + 16);
  macData.set(additionalData, 0), macData.set(encryptedData, additionalData.length + aadPadding);
  const lengthView = new DataView(macData.buffer, additionalData.length + aadPadding + encryptedData.length + ciphertextPadding);
  lengthView.setBigUint64(0, BigInt(additionalData.length), true), lengthView.setBigUint64(8, BigInt(encryptedData.length), true);
  const expectedTag = poly1305Mac(polyKey, macData);
  let diff = 0;
  for (let index = 0; index < 16; index++) diff |= tag[index] ^ expectedTag[index];
  if (0 !== diff) throw new Error("ChaCha20-Poly1305 authentication failed");
  return chacha20Xor(key, nonce, encryptedData);
}
__name(chacha20Poly1305Decrypt, "chacha20Poly1305Decrypt");
var TLS_MAX_PLAINTEXT_FRAGMENT = 16 * 1024;
function buildTlsRecord(contentType, fragment, version = TLS_VERSION_12) {
  const data = tlsToUint8Array(fragment);
  const record = new Uint8Array(5 + data.byteLength);
  record[0] = contentType;
  record[1] = version >> 8 & 255;
  record[2] = version & 255;
  record[3] = data.byteLength >> 8 & 255;
  record[4] = data.byteLength & 255;
  record.set(data, 5);
  return record;
}
__name(buildTlsRecord, "buildTlsRecord");
function buildHandshakeMessage(handshakeType, body) {
  return tlsBytes(handshakeType, ((length) => [length >> 16 & 255, length >> 8 & 255, 255 & length])(body.length), body);
}
__name(buildHandshakeMessage, "buildHandshakeMessage");
var TlsRecordParser = class {
  static {
    __name(this, "TlsRecordParser");
  }
  static {
  }
  constructor() {
    this.buffer = new Uint8Array(0);
  }
  feed(chunk) {
    const bytes = tlsToUint8Array(chunk);
    this.buffer = this.buffer.length ? concatBytes(this.buffer, bytes) : bytes;
  }
  next() {
    if (this.buffer.length < 5) return null;
    const contentType = this.buffer[0], version = readUint16(this.buffer, 1), length = readUint16(this.buffer, 3);
    if (this.buffer.length < 5 + length) return null;
    const fragment = this.buffer.subarray(5, 5 + length);
    return this.buffer = this.buffer.subarray(5 + length), { type: contentType, version, length, fragment };
  }
};
var TlsHandshakeParser = class {
  static {
    __name(this, "TlsHandshakeParser");
  }
  static {
  }
  constructor() {
    this.buffer = new Uint8Array(0);
  }
  feed(chunk) {
    const bytes = tlsToUint8Array(chunk);
    this.buffer = this.buffer.length ? concatBytes(this.buffer, bytes) : bytes;
  }
  next() {
    if (this.buffer.length < 4) return null;
    const handshakeType = this.buffer[0], length = readUint24(this.buffer, 1);
    if (this.buffer.length < 4 + length) return null;
    const body = this.buffer.subarray(4, 4 + length), raw = this.buffer.subarray(0, 4 + length);
    return this.buffer = this.buffer.subarray(4 + length), { type: handshakeType, length, body, raw };
  }
};
function parseServerHello(body) {
  let offset = 0;
  const legacyVersion = readUint16(body, offset);
  offset += 2;
  const serverRandom = body.slice(offset, offset + 32);
  offset += 32;
  const sessionIdLength = body[offset++], sessionId = body.slice(offset, offset + sessionIdLength);
  offset += sessionIdLength;
  const cipherSuite = readUint16(body, offset);
  offset += 2;
  const compression = body[offset++];
  let selectedVersion = legacyVersion, keyShare = null, alpn = null;
  if (offset < body.length) {
    const extensionsLength = readUint16(body, offset);
    offset += 2;
    const extensionsEnd = offset + extensionsLength;
    for (; offset + 4 <= extensionsEnd; ) {
      const extensionType = readUint16(body, offset);
      offset += 2;
      const extensionLength = readUint16(body, offset);
      offset += 2;
      const extensionData = body.slice(offset, offset + extensionLength);
      if (offset += extensionLength, extensionType === EXT_SUPPORTED_VERSIONS && extensionLength >= 2) selectedVersion = readUint16(extensionData, 0);
      else if (extensionType === EXT_KEY_SHARE && extensionLength >= 4) {
        const group = readUint16(extensionData, 0), keyLength = readUint16(extensionData, 2);
        keyShare = { group, key: extensionData.slice(4, 4 + keyLength) };
      } else extensionType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION && extensionLength >= 3 && (alpn = textDecoder.decode(extensionData.slice(3, 3 + extensionData[2])));
    }
  }
  const helloRetryRequestRandom = new Uint8Array([207, 33, 173, 116, 229, 154, 97, 17, 190, 29, 140, 2, 30, 101, 184, 145, 194, 162, 17, 22, 122, 187, 140, 94, 7, 158, 9, 226, 200, 168, 51, 156]);
  return { version: legacyVersion, serverRandom, sessionId, cipherSuite, compression, selectedVersion, keyShare, alpn, isHRR: constantTimeEqual(serverRandom, helloRetryRequestRandom), isTls13: selectedVersion === TLS_VERSION_13 };
}
__name(parseServerHello, "parseServerHello");
function parseServerKeyExchange(body) {
  let offset = 1;
  const namedCurve = readUint16(body, offset);
  offset += 2;
  const keyLength = body[offset++];
  return { namedCurve, serverPublicKey: body.slice(offset, offset + keyLength) };
}
__name(parseServerKeyExchange, "parseServerKeyExchange");
function extractLeafCertificate(body, hasContext = 0) {
  let offset = 0;
  if (hasContext) {
    const contextLength = body[offset++];
    offset += contextLength;
  }
  if (offset + 3 > body.length) return null;
  const certificateListLength = readUint24(body, offset);
  if (offset += 3, !certificateListLength || offset + 3 > body.length) return null;
  const certificateLength = readUint24(body, offset);
  return offset += 3, certificateLength ? body.slice(offset, offset + certificateLength) : null;
}
__name(extractLeafCertificate, "extractLeafCertificate");
function parseEncryptedExtensions(body) {
  const parsed = { alpn: null };
  let offset = 2;
  const extensionsEnd = 2 + readUint16(body, 0);
  for (; offset + 4 <= extensionsEnd; ) {
    const extensionType = readUint16(body, offset);
    offset += 2;
    const extensionLength = readUint16(body, offset);
    if (offset += 2, extensionType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION && extensionLength >= 3) {
      const protocolLength = body[offset + 2];
      protocolLength > 0 && offset + 3 + protocolLength <= offset + extensionLength && (parsed.alpn = textDecoder.decode(body.slice(offset + 3, offset + 3 + protocolLength)));
    }
    offset += extensionLength;
  }
  return parsed;
}
__name(parseEncryptedExtensions, "parseEncryptedExtensions");
function buildClientHello(clientRandom, serverName, keyShares, { tls13: enableTls13 = true, tls12: enableTls12 = true, alpn = null, chacha = true } = {}) {
  const cipherIds = [];
  enableTls13 && cipherIds.push(4865, 4866, ...chacha ? [4867] : []), enableTls12 && cipherIds.push(49199, 49200, 49195, 49196, ...chacha ? [52392, 52393] : []);
  const cipherBytes = tlsBytes(...cipherIds.flatMap(uint16be)), extensions = [tlsBytes(255, 1, 0, 1, 0)];
  if (serverName) {
    const serverNameBytes = textEncoder.encode(serverName), serverNameList = tlsBytes(0, uint16be(serverNameBytes.length), serverNameBytes);
    extensions.push(tlsBytes(uint16be(EXT_SERVER_NAME), uint16be(serverNameList.length + 2), uint16be(serverNameList.length), serverNameList));
  }
  extensions.push(tlsBytes(uint16be(EXT_EC_POINT_FORMATS), 0, 2, 1, 0)), extensions.push(tlsBytes(uint16be(EXT_SUPPORTED_GROUPS), 0, 6, 0, 4, 0, 29, 0, 23));
  const signatureBytes = tlsBytes(...SUPPORTED_SIGNATURE_ALGORITHMS.flatMap(uint16be));
  extensions.push(tlsBytes(uint16be(EXT_SIGNATURE_ALGORITHMS), uint16be(signatureBytes.length + 2), uint16be(signatureBytes.length), signatureBytes));
  const protocols = Array.isArray(alpn) ? alpn.filter(Boolean) : alpn ? [alpn] : [];
  if (protocols.length) {
    const alpnBytes = concatBytes(...protocols.map(((protocol) => {
      const protocolBytes = textEncoder.encode(protocol);
      return tlsBytes(protocolBytes.length, protocolBytes);
    })));
    extensions.push(tlsBytes(uint16be(EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION), uint16be(alpnBytes.length + 2), uint16be(alpnBytes.length), alpnBytes));
  }
  if (enableTls13 && keyShares) {
    let keyShareBytes;
    if (extensions.push(enableTls12 ? tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0, 5, 4, 3, 4, 3, 3) : tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0, 3, 2, 3, 4)), extensions.push(tlsBytes(uint16be(EXT_PSK_KEY_EXCHANGE_MODES), 0, 2, 1, 1)), keyShares?.x25519 && keyShares?.p256) keyShareBytes = concatBytes(tlsBytes(0, 29, uint16be(keyShares.x25519.length), keyShares.x25519), tlsBytes(0, 23, uint16be(keyShares.p256.length), keyShares.p256));
    else if (keyShares?.x25519) keyShareBytes = tlsBytes(0, 29, uint16be(keyShares.x25519.length), keyShares.x25519);
    else if (keyShares?.p256) keyShareBytes = tlsBytes(0, 23, uint16be(keyShares.p256.length), keyShares.p256);
    else {
      if (!(keyShares instanceof Uint8Array)) throw new Error("Invalid keyShares");
      keyShareBytes = tlsBytes(0, 23, uint16be(keyShares.length), keyShares);
    }
    extensions.push(tlsBytes(uint16be(EXT_KEY_SHARE), uint16be(keyShareBytes.length + 2), uint16be(keyShareBytes.length), keyShareBytes));
  }
  const extensionsBytes = concatBytes(...extensions);
  return buildHandshakeMessage(HANDSHAKE_TYPE_CLIENT_HELLO, tlsBytes(uint16be(TLS_VERSION_12), clientRandom, 0, uint16be(cipherBytes.length), cipherBytes, 1, 0, uint16be(extensionsBytes.length), extensionsBytes));
}
__name(buildClientHello, "buildClientHello");
var uint64be = (sequenceNumber) => {
  const bytes = new Uint8Array(8);
  return new DataView(bytes.buffer).setBigUint64(0, sequenceNumber, false), bytes;
};
var xorSequenceIntoIv = (initializationVector, sequenceNumber) => {
  const nonce = initializationVector.slice(), sequenceBytes = uint64be(sequenceNumber);
  for (let index = 0; index < 8; index++) nonce[nonce.length - 8 + index] ^= sequenceBytes[index];
  return nonce;
};
var deriveTrafficKeys = (hash, secret, keyLen, ivLen) => Promise.all([hkdfExpandLabel(hash, secret, "key", EMPTY_BYTES, keyLen), hkdfExpandLabel(hash, secret, "iv", EMPTY_BYTES, ivLen)]);
var UserlandTlsClient = class {
  static {
    __name(this, "UserlandTlsClient");
  }
  static {
  }
  constructor(socket, options = {}) {
    if (this.socket = socket, this.serverName = options.serverName || "", this.supportTls13 = false !== options.tls13, this.supportTls12 = false !== options.tls12, !this.supportTls13 && !this.supportTls12) throw new Error("At least one TLS version must be enabled");
    this.alpnProtocols = Array.isArray(options.alpn) ? options.alpn : options.alpn ? [options.alpn] : null, this.allowChacha = options.allowChacha !== false, this.timeout = options.timeout ?? 3e4, this.clientRandom = randomBytes(32), this.serverRandom = null, this.handshakeChunks = [], this.handshakeComplete = false, this.negotiatedAlpn = null, this.cipherSuite = null, this.cipherConfig = null, this.isTls13 = false, this.masterSecret = null, this.handshakeSecret = null, this.clientWriteKey = null, this.serverWriteKey = null, this.clientWriteIv = null, this.serverWriteIv = null, this.clientHandshakeKey = null, this.serverHandshakeKey = null, this.clientHandshakeIv = null, this.serverHandshakeIv = null, this.clientAppKey = null, this.serverAppKey = null, this.clientAppIv = null, this.serverAppIv = null, this.clientWriteCryptoKey = null, this.serverWriteCryptoKey = null, this.clientHandshakeCryptoKey = null, this.serverHandshakeCryptoKey = null, this.clientAppCryptoKey = null, this.serverAppCryptoKey = null, this.clientSeqNum = 0n, this.serverSeqNum = 0n, this.recordParser = new TlsRecordParser(), this.handshakeParser = new TlsHandshakeParser(), this.keyPairs = new Map(), this.ecdhKeyPair = null, this.sawCert = false;
  }
  recordHandshake(chunk) {
    this.handshakeChunks.push(chunk);
  }
  transcript() {
    return 1 === this.handshakeChunks.length ? this.handshakeChunks[0] : concatBytes(...this.handshakeChunks);
  }
  getCipherConfig(cipherSuite) {
    return CIPHER_SUITES_BY_ID.get(cipherSuite) || null;
  }
  async readChunk(reader) {
    return this.timeout ? Promise.race([reader.read(), new Promise(((resolve, reject) => setTimeout((() => reject(new Error("TLS read timeout"))), this.timeout)))]) : reader.read();
  }
  async readRecordsUntil(reader, predicate, closedError) {
    for (; ; ) {
      let record;
      for (; record = this.recordParser.next(); )
        if (await predicate(record)) return;
      const { value, done } = await this.readChunk(reader);
      if (done) throw new Error(closedError);
      this.recordParser.feed(value);
    }
  }
  async readHandshakeUntil(reader, predicate, closedError) {
    for (let message; message = this.handshakeParser.next(); )
      if (await predicate(message)) return;
    return this.readRecordsUntil(reader, (async (record) => {
      if (record.type === CONTENT_TYPE_ALERT) {
        if (shouldIgnoreTlsAlert(record.fragment)) return;
        throw new Error(`TLS Alert: ${record.fragment[1]}`);
      }
      if (record.type === CONTENT_TYPE_HANDSHAKE) {
        this.handshakeParser.feed(record.fragment);
        for (let message; message = this.handshakeParser.next(); )
          if (await predicate(message)) return 1;
      }
    }), closedError);
  }
  async acceptCertificate(certificate) {
    if (!certificate?.length) throw new Error("Empty certificate");
    this.sawCert = true;
  }
  async handshake() {
    const [p256Share, x25519Share] = await Promise.all([generateKeyShare("P-256"), generateKeyShare("X25519")]);
    this.keyPairs = new Map([[23, p256Share], [29, x25519Share]]), this.ecdhKeyPair = p256Share.keyPair;
    const reader = this.socket.readable.getReader(), writer = this.socket.writable.getWriter();
    try {
      const clientHello = buildClientHello(this.clientRandom, this.serverName, { x25519: x25519Share.publicKeyRaw, p256: p256Share.publicKeyRaw }, { tls13: this.supportTls13, tls12: this.supportTls12, alpn: this.alpnProtocols, chacha: this.allowChacha });
      this.recordHandshake(clientHello), await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientHello, TLS_VERSION_10));
      const serverHello = await this.receiveServerHello(reader);
      if (serverHello.isHRR) throw new Error("HelloRetryRequest is not supported by TLSClientMini");
      if (serverHello.keyShare?.group && this.keyPairs.has(serverHello.keyShare.group)) {
        const selectedKeyPair = this.keyPairs.get(serverHello.keyShare.group);
        this.ecdhKeyPair = selectedKeyPair.keyPair;
      }
      serverHello.isTls13 ? await this.handshakeTls13(reader, writer, serverHello) : await this.handshakeTls12(reader, writer), this.handshakeComplete = true;
    } finally {
      safeReleaseLock(reader, "TLS reader"), safeReleaseLock(writer, "TLS writer");
    }
  }
  async receiveServerHello(reader) {
    for (; ; ) {
      const { value, done } = await this.readChunk(reader);
      if (done) throw new Error("Connection closed waiting for ServerHello");
      let record;
      for (this.recordParser.feed(value); record = this.recordParser.next(); ) {
        if (record.type === CONTENT_TYPE_ALERT) {
          if (shouldIgnoreTlsAlert(record.fragment)) continue;
          throw new Error(`TLS Alert: level=${record.fragment[0]}, desc=${record.fragment[1]}`);
        }
        if (record.type !== CONTENT_TYPE_HANDSHAKE) continue;
        let message;
        for (this.handshakeParser.feed(record.fragment); message = this.handshakeParser.next(); ) {
          if (message.type !== HANDSHAKE_TYPE_SERVER_HELLO) continue;
          this.recordHandshake(message.raw);
          const serverHello = parseServerHello(message.body);
          if (this.serverRandom = serverHello.serverRandom, this.cipherSuite = serverHello.cipherSuite, this.cipherConfig = this.getCipherConfig(serverHello.cipherSuite), this.isTls13 = serverHello.isTls13, this.negotiatedAlpn = serverHello.alpn || null, !this.cipherConfig) throw new Error(`Unsupported cipher suite: 0x${serverHello.cipherSuite.toString(16)}`);
          return serverHello;
        }
      }
    }
  }
  async handshakeTls12(reader, writer) {
    let serverKeyExchange = null;
    let sawServerHelloDone = false;
    if (await this.readHandshakeUntil(reader, (async (message) => {
      switch (message.type) {
        case HANDSHAKE_TYPE_CERTIFICATE: {
          this.recordHandshake(message.raw);
          const certificate = extractLeafCertificate(message.body, 1);
          if (!certificate) throw new Error("Missing TLS 1.2 certificate");
          await this.acceptCertificate(certificate);
          break;
        }
        case HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE:
          this.recordHandshake(message.raw), serverKeyExchange = parseServerKeyExchange(message.body);
          break;
        case HANDSHAKE_TYPE_SERVER_HELLO_DONE:
          return this.recordHandshake(message.raw), sawServerHelloDone = true, 1;
        case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
          throw new Error("Client certificate is not supported");
        default:
          this.recordHandshake(message.raw);
      }
    }), "Connection closed during TLS 1.2 handshake"), !this.sawCert) throw new Error("Missing TLS 1.2 leaf certificate");
    const serverKeyExchangeData = (
      serverKeyExchange
    );
    if (!serverKeyExchangeData) throw new Error("Missing TLS 1.2 ServerKeyExchange");
    const curveName = GROUPS_BY_ID.get(serverKeyExchangeData.namedCurve);
    if (!curveName) throw new Error(`Unsupported named curve: 0x${serverKeyExchangeData.namedCurve.toString(16)}`);
    const keyShare = this.keyPairs.get(serverKeyExchangeData.namedCurve);
    if (!keyShare) throw new Error(`Missing key pair for curve: 0x${serverKeyExchangeData.namedCurve.toString(16)}`);
    const preMasterSecret = await deriveSharedSecret(keyShare.keyPair.privateKey, serverKeyExchangeData.serverPublicKey, curveName), clientKeyExchange = buildHandshakeMessage(HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, tlsBytes(keyShare.publicKeyRaw.length, keyShare.publicKeyRaw));
    this.recordHandshake(clientKeyExchange);
    const hashName = this.cipherConfig.hash;
    this.masterSecret = await tls12Prf(preMasterSecret, "master secret", concatBytes(this.clientRandom, this.serverRandom), 48, hashName);
    const keyLen = this.cipherConfig.keyLen, ivLen = this.cipherConfig.ivLen, keyBlock = await tls12Prf(this.masterSecret, "key expansion", concatBytes(this.serverRandom, this.clientRandom), 2 * keyLen + 2 * ivLen, hashName);
    this.clientWriteKey = keyBlock.slice(0, keyLen), this.serverWriteKey = keyBlock.slice(keyLen, 2 * keyLen), this.clientWriteIv = keyBlock.slice(2 * keyLen, 2 * keyLen + ivLen), this.serverWriteIv = keyBlock.slice(2 * keyLen + ivLen, 2 * keyLen + 2 * ivLen);
    if (!this.cipherConfig.chacha) [this.clientWriteCryptoKey, this.serverWriteCryptoKey] = await Promise.all([importAesGcmKey(this.clientWriteKey, ["encrypt"]), importAesGcmKey(this.serverWriteKey, ["decrypt"])]);
    await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientKeyExchange)), await writer.write(buildTlsRecord(CONTENT_TYPE_CHANGE_CIPHER_SPEC, tlsBytes(1)));
    const clientVerifyData = await tls12Prf(this.masterSecret, "client finished", await digestBytes(hashName, this.transcript()), 12, hashName), finishedMessage = buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED, clientVerifyData);
    this.recordHandshake(finishedMessage), await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, await this.encryptTls12(finishedMessage, CONTENT_TYPE_HANDSHAKE)));
    let sawChangeCipherSpec = false;
    await this.readRecordsUntil(reader, (async (record) => {
      if (record.type === CONTENT_TYPE_ALERT) {
        if (shouldIgnoreTlsAlert(record.fragment)) return;
        throw new Error(`TLS Alert: ${record.fragment[1]}`);
      }
      if (record.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC) return void (sawChangeCipherSpec = true);
      if (record.type !== CONTENT_TYPE_HANDSHAKE || !sawChangeCipherSpec) return;
      const decrypted = await this.decryptTls12(record.fragment, CONTENT_TYPE_HANDSHAKE);
      if (decrypted[0] !== HANDSHAKE_TYPE_FINISHED) return;
      const verifyLength = readUint24(decrypted, 1), verifyData = decrypted.slice(4, 4 + verifyLength), expectedVerifyData = await tls12Prf(this.masterSecret, "server finished", await digestBytes(hashName, this.transcript()), 12, hashName);
      if (!constantTimeEqual(verifyData, expectedVerifyData)) throw new Error("TLS 1.2 server Finished verify failed");
      return 1;
    }), "Connection closed waiting for TLS 1.2 Finished");
  }
  async handshakeTls13(reader, writer, serverHello) {
    const groupName = GROUPS_BY_ID.get(serverHello.keyShare?.group);
    if (!groupName || !serverHello.keyShare?.key?.length) throw new Error("Missing TLS 1.3 key_share");
    const hashName = this.cipherConfig.hash, hashLen = hashByteLength(hashName), keyLen = this.cipherConfig.keyLen, ivLen = this.cipherConfig.ivLen, sharedSecret = await deriveSharedSecret(this.ecdhKeyPair.privateKey, serverHello.keyShare.key, groupName), earlySecret = await hkdfExtract(hashName, null, new Uint8Array(hashLen)), derivedSecret = await hkdfExpandLabel(hashName, earlySecret, "derived", await digestBytes(hashName, EMPTY_BYTES), hashLen);
    this.handshakeSecret = await hkdfExtract(hashName, derivedSecret, sharedSecret);
    const transcriptHash = await digestBytes(hashName, this.transcript()), clientHandshakeTrafficSecret = await hkdfExpandLabel(hashName, this.handshakeSecret, "c hs traffic", transcriptHash, hashLen), serverHandshakeTrafficSecret = await hkdfExpandLabel(hashName, this.handshakeSecret, "s hs traffic", transcriptHash, hashLen);
    [this.clientHandshakeKey, this.clientHandshakeIv] = await deriveTrafficKeys(hashName, clientHandshakeTrafficSecret, keyLen, ivLen), [this.serverHandshakeKey, this.serverHandshakeIv] = await deriveTrafficKeys(hashName, serverHandshakeTrafficSecret, keyLen, ivLen);
    if (!this.cipherConfig.chacha) [this.clientHandshakeCryptoKey, this.serverHandshakeCryptoKey] = await Promise.all([importAesGcmKey(this.clientHandshakeKey, ["encrypt"]), importAesGcmKey(this.serverHandshakeKey, ["decrypt"])]);
    const serverFinishedKey = await hkdfExpandLabel(hashName, serverHandshakeTrafficSecret, "finished", EMPTY_BYTES, hashLen);
    let serverFinishedReceived = false;
    const handleHandshakeMessage = async (message) => {
      switch (message.type) {
        case HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: {
          const encryptedExtensions = parseEncryptedExtensions(message.body);
          encryptedExtensions.alpn && (this.negotiatedAlpn = encryptedExtensions.alpn), this.recordHandshake(message.raw);
          break;
        }
        case HANDSHAKE_TYPE_CERTIFICATE: {
          const certificate = extractLeafCertificate(message.body);
          if (!certificate) throw new Error("Missing TLS 1.3 certificate");
          await this.acceptCertificate(certificate), this.recordHandshake(message.raw);
          break;
        }
        case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
          throw new Error("Client certificate is not supported");
        case HANDSHAKE_TYPE_CERTIFICATE_VERIFY:
          this.recordHandshake(message.raw);
          break;
        case HANDSHAKE_TYPE_FINISHED: {
          const expectedVerifyData = await hmac(hashName, serverFinishedKey, await digestBytes(hashName, this.transcript()));
          if (!constantTimeEqual(expectedVerifyData, message.body)) throw new Error("TLS 1.3 server Finished verify failed");
          this.recordHandshake(message.raw), serverFinishedReceived = true;
          break;
        }
        default:
          this.recordHandshake(message.raw);
      }
    };
    await this.readRecordsUntil(reader, (async (record) => {
      if (record.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC || record.type === CONTENT_TYPE_HANDSHAKE) return;
      if (record.type === CONTENT_TYPE_ALERT) {
        if (shouldIgnoreTlsAlert(record.fragment)) return;
        throw new Error(`TLS Alert: ${record.fragment[1]}`);
      }
      if (record.type !== CONTENT_TYPE_APPLICATION_DATA) return;
      const decrypted = await this.decryptTls13Handshake(record.fragment), innerType = decrypted[decrypted.length - 1], plaintext = decrypted.slice(0, -1);
      if (innerType === CONTENT_TYPE_HANDSHAKE) {
        this.handshakeParser.feed(plaintext);
        for (let message; message = this.handshakeParser.next(); )
          if (await handleHandshakeMessage(message), serverFinishedReceived) return 1;
      }
    }), "Connection closed during TLS 1.3 handshake");
    const applicationTranscriptHash = await digestBytes(hashName, this.transcript()), masterDerivedSecret = await hkdfExpandLabel(hashName, this.handshakeSecret, "derived", await digestBytes(hashName, EMPTY_BYTES), hashLen), masterSecret = await hkdfExtract(hashName, masterDerivedSecret, new Uint8Array(hashLen)), clientAppTrafficSecret = await hkdfExpandLabel(hashName, masterSecret, "c ap traffic", applicationTranscriptHash, hashLen), serverAppTrafficSecret = await hkdfExpandLabel(hashName, masterSecret, "s ap traffic", applicationTranscriptHash, hashLen);
    [this.clientAppKey, this.clientAppIv] = await deriveTrafficKeys(hashName, clientAppTrafficSecret, keyLen, ivLen), [this.serverAppKey, this.serverAppIv] = await deriveTrafficKeys(hashName, serverAppTrafficSecret, keyLen, ivLen);
    if (!this.cipherConfig.chacha) [this.clientAppCryptoKey, this.serverAppCryptoKey] = await Promise.all([importAesGcmKey(this.clientAppKey, ["encrypt"]), importAesGcmKey(this.serverAppKey, ["decrypt"])]);
    const clientFinishedKey = await hkdfExpandLabel(hashName, clientHandshakeTrafficSecret, "finished", EMPTY_BYTES, hashLen), clientFinishedVerifyData = await hmac(hashName, clientFinishedKey, await digestBytes(hashName, this.transcript())), clientFinishedMessage = buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED, clientFinishedVerifyData);
    this.recordHandshake(clientFinishedMessage), await writer.write(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, await this.encryptTls13Handshake(concatBytes(clientFinishedMessage, [CONTENT_TYPE_HANDSHAKE])))), this.clientSeqNum = 0n, this.serverSeqNum = 0n;
  }
  async encryptTls12(plaintext, contentType) {
    const sequenceNumber = this.clientSeqNum++, sequenceBytes = uint64be(sequenceNumber), additionalData = concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(plaintext.length));
    if (this.cipherConfig.chacha) {
      const nonce = xorSequenceIntoIv(this.clientWriteIv, sequenceNumber);
      return chacha20Poly1305Encrypt(this.clientWriteKey, nonce, plaintext, additionalData);
    }
    const explicitNonce = randomBytes(8);
    if (!this.clientWriteCryptoKey) this.clientWriteCryptoKey = await importAesGcmKey(this.clientWriteKey, ["encrypt"]);
    return concatBytes(explicitNonce, await aesGcmEncryptWithKey(this.clientWriteCryptoKey, concatBytes(this.clientWriteIv, explicitNonce), plaintext, additionalData));
  }
  async decryptTls12(ciphertext, contentType) {
    const sequenceNumber = this.serverSeqNum++, sequenceBytes = uint64be(sequenceNumber);
    if (this.cipherConfig.chacha) {
      const nonce = xorSequenceIntoIv(this.serverWriteIv, sequenceNumber);
      return chacha20Poly1305Decrypt(this.serverWriteKey, nonce, ciphertext, concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(ciphertext.length - 16)));
    }
    const explicitNonce = ciphertext.subarray(0, 8), encryptedData = ciphertext.subarray(8);
    if (!this.serverWriteCryptoKey) this.serverWriteCryptoKey = await importAesGcmKey(this.serverWriteKey, ["decrypt"]);
    return aesGcmDecryptWithKey(this.serverWriteCryptoKey, concatBytes(this.serverWriteIv, explicitNonce), encryptedData, concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(encryptedData.length - 16)));
  }
  async encryptTls13Handshake(plaintext) {
    const nonce = xorSequenceIntoIv(this.clientHandshakeIv, this.clientSeqNum++), additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(plaintext.length + 16));
    if (this.cipherConfig.chacha) return chacha20Poly1305Encrypt(this.clientHandshakeKey, nonce, plaintext, additionalData);
    if (!this.clientHandshakeCryptoKey) this.clientHandshakeCryptoKey = await importAesGcmKey(this.clientHandshakeKey, ["encrypt"]);
    return aesGcmEncryptWithKey(this.clientHandshakeCryptoKey, nonce, plaintext, additionalData);
  }
  async decryptTls13Handshake(ciphertext) {
    const nonce = xorSequenceIntoIv(this.serverHandshakeIv, this.serverSeqNum++), additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(ciphertext.length));
    const decrypted = this.cipherConfig.chacha ? await chacha20Poly1305Decrypt(this.serverHandshakeKey, nonce, ciphertext, additionalData) : await aesGcmDecryptWithKey(this.serverHandshakeCryptoKey || (this.serverHandshakeCryptoKey = await importAesGcmKey(this.serverHandshakeKey, ["decrypt"])), nonce, ciphertext, additionalData);
    let innerTypeIndex = decrypted.length - 1;
    for (; innerTypeIndex >= 0 && !decrypted[innerTypeIndex]; ) innerTypeIndex--;
    return innerTypeIndex < 0 ? EMPTY_BYTES : decrypted.slice(0, innerTypeIndex + 1);
  }
  async encryptTls13(data) {
    const plaintext = concatBytes(data, [CONTENT_TYPE_APPLICATION_DATA]), nonce = xorSequenceIntoIv(this.clientAppIv, this.clientSeqNum++), additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(plaintext.length + 16));
    if (this.cipherConfig.chacha) return chacha20Poly1305Encrypt(this.clientAppKey, nonce, plaintext, additionalData);
    if (!this.clientAppCryptoKey) this.clientAppCryptoKey = await importAesGcmKey(this.clientAppKey, ["encrypt"]);
    return aesGcmEncryptWithKey(this.clientAppCryptoKey, nonce, plaintext, additionalData);
  }
  async decryptTls13(ciphertext) {
    const nonce = xorSequenceIntoIv(this.serverAppIv, this.serverSeqNum++), additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(ciphertext.length)), plaintext = this.cipherConfig.chacha ? await chacha20Poly1305Decrypt(this.serverAppKey, nonce, ciphertext, additionalData) : await aesGcmDecryptWithKey(this.serverAppCryptoKey || (this.serverAppCryptoKey = await importAesGcmKey(this.serverAppKey, ["decrypt"])), nonce, ciphertext, additionalData);
    let innerTypeIndex = plaintext.length - 1;
    for (; innerTypeIndex >= 0 && !plaintext[innerTypeIndex]; ) innerTypeIndex--;
    if (innerTypeIndex < 0) return {
      data: EMPTY_BYTES,
      type: 0
    };
    return {
      data: plaintext.slice(0, innerTypeIndex),
      type: plaintext[innerTypeIndex]
    };
  }
  async write(data) {
    if (!this.handshakeComplete) throw new Error("Handshake not complete");
    const plaintext = tlsToUint8Array(data);
    if (!plaintext.byteLength) return;
    const writer = this.socket.writable.getWriter();
    try {
      const records = [];
      for (let offset = 0; offset < plaintext.byteLength; offset += TLS_MAX_PLAINTEXT_FRAGMENT) {
        const chunk = plaintext.subarray(offset, Math.min(offset + TLS_MAX_PLAINTEXT_FRAGMENT, plaintext.byteLength));
        const encrypted = this.isTls13 ? await this.encryptTls13(chunk) : await this.encryptTls12(chunk, CONTENT_TYPE_APPLICATION_DATA);
        records.push(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, encrypted));
      }
      await writer.write(records.length === 1 ? records[0] : concatBytes(...records));
    } finally {
      safeReleaseLock(writer, "TLS writer");
    }
  }
  async read() {
    for (; ; ) {
      let record;
      for (; record = this.recordParser.next(); ) {
        if (record.type === CONTENT_TYPE_ALERT) {
          if (record.fragment[1] === ALERT_CLOSE_NOTIFY) return null;
          throw new Error(`TLS Alert: ${record.fragment[1]}`);
        }
        if (record.type !== CONTENT_TYPE_APPLICATION_DATA) continue;
        if (!this.isTls13) return this.decryptTls12(record.fragment, CONTENT_TYPE_APPLICATION_DATA);
        const { data, type } = await this.decryptTls13(record.fragment);
        if (type === CONTENT_TYPE_APPLICATION_DATA) return data;
        if (type === CONTENT_TYPE_ALERT) {
          if (data[1] === ALERT_CLOSE_NOTIFY) return null;
          throw new Error(`TLS Alert: ${data[1]}`);
        }
        if (type !== CONTENT_TYPE_HANDSHAKE) continue;
        let message;
        for (this.handshakeParser.feed(data); message = this.handshakeParser.next(); )
          if (message.type !== HANDSHAKE_TYPE_NEW_SESSION_TICKET && message.type === HANDSHAKE_TYPE_KEY_UPDATE) throw new Error("TLS 1.3 KeyUpdate is not supported by TLSClientMini");
      }
      const reader = this.socket.readable.getReader();
      try {
        const { value, done } = await this.readChunk(reader);
        if (done) return null;
        this.recordParser.feed(value);
      } finally {
        safeReleaseLock(reader, "TLS reader");
      }
    }
  }
  close() {
    this.socket.close();
  }
};
var CONFIG_KV_KEY = "pg.json";
var ENTRY_ENDPOINTS_KV_KEY = "rk.txt";
var PROXY_HEALTH_KV_KEY = "fd.jk.json";
var PROXY_AUTO_KV_KEY = "fd.zd.json";
var PROXY_AUTO_STATE_KV_KEY = "fd.zt.json";
var SUB_RATE_LIMIT_PREFIX = "SUB.rate.";
var SUB_RESPONSE_CACHE_TTL_SECONDS = 300;
var SUB_URL_VERSION = "2026-06-13-v6";
var DEFAULTS = Object.freeze({
  DEFAULT_PORT: 443,
  CONNECT_TIMEOUT_MS: 8e3,
  MAX_FIRST_PACKET_BYTES: 65536,
  MAX_ADMIN_BODY_BYTES: 524288,
  ROTATE_HOURS: 3,
  PROXY_FAIL_TTL_HOURS: 24
});
var SUBSCRIPTION_GUARD = Object.freeze({
  RATE_LIMIT_PER_MINUTE: 30,
  RATE_LIMIT_WINDOW_SECONDS: 60
});
var subscriptionRateMemory = new Map();
var KV_CACHE_TTL_MS = 5 * 60 * 1e3;
var KV_AUTO_CACHE_TTL_MS = 60 * 1e3;
var KV_AUTO_STATE_CACHE_TTL_MS = 30 * 1e3;
var KV_HEALTH_CACHE_TTL_MS = 2 * 60 * 1e3;
var PROXY_HEALTH_WRITE_DEBOUNCE_MS = 5 * 60 * 1e3;
var kvReadCache = globalThis.__WORKER_KV_READ_CACHE || (globalThis.__WORKER_KV_READ_CACHE = new Map());
var proxyHealthWriteCache = globalThis.__WORKER_PROXY_HEALTH_WRITE_CACHE || (globalThis.__WORKER_PROXY_HEALTH_WRITE_CACHE = new Map());
var JSON_HEADERS = Object.freeze({
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store"
});
var TEXT_HEADERS = Object.freeze({
  "Content-Type": "text/plain; charset=utf-8",
  "Cache-Control": "no-store"
});
var ADMIN_CORS_HEADERS = Object.freeze({
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Admin-Password",
  "Access-Control-Max-Age": "86400"
});
var ROUTES = Object.freeze({
  PUBLIC_ROOT: "/",
  ADMIN_ROOT: "/a",
  ADMIN_ALIAS: "/admin",
  SUBSCRIPTION: "/sub"
});
var PROXYIP_CATALOG_SUMMARY_URL = "";
var PROXYIP_CATALOG_IPV4_URL = "";
var PROXYIP_CATALOG_IPV6_URL = "";
var PROXYIP_CATALOG_QUERY_URL = "";
var ENTRY_CANDIDATE_FETCH_TIMEOUT_MS = 12e3;
var WETEST_CLOUDFLARE_IPV4_API_URL = "https://www.wetest.vip/api/cf2dns/get_cloudflare_ip";
var WETEST_CLOUDFLARE_API_KEY = "o1zrmHAF";
var HOSTMONIT_CLOUDFLARE_IPV4_API_URL = "https://api.hostmonit.com/get_optimization_ip";
var HOSTMONIT_CLOUDFLARE_API_KEY = "iDetkOys";
var UOUIN_CLOUDFLARE_API_URL = "https://api.uouin.com/app/cloudflare";
var PROXYIP_TRACE_HOST = "speed.cloudflare.com";
var PROXYIP_TRACE_PATH = "/cdn-cgi/trace";
var PROXYIP_TRACE_MAX_BYTES = 64 * 1024;
var DEFAULT_SUB_CONVERTER_URL = "https://sub.ip168.dpdns.org";
var DEFAULT_SUB_NAME = "\u5F52\u6765\u4ECD\u5C11\u5E74";
var ADMIN_PAGE_CACHE_TTL_SECONDS = 86400;
var ADMIN_PAGE_KV_KEY = "ym:index.v6.html";
var ADMIN_PAGE_KV_CACHE_VERSION = "2026-06-13-sub-v7";
var ADMIN_PAGE_KV_CACHE_TTL_MS = 24 * 60 * 60 * 1e3;
var VENDOR_QRCODE_PATH = "/vendor/qrcode.min.js";
var VENDOR_QRCODE_KV_KEY = "vendor/qrcode.min.js";
var DEFAULT_PROXY_AUTO_SETTINGS = Object.freeze({
  enabled: false,
  ipVersion: "4",
  country: "US",
  port: "",
  portMode: "all",
  status: "verified,usable",
  candidateLimit: 20,
  saveCount: 3,
  timeoutMs: 1500,
  concurrency: 4,
  keepCurrentIfHealthy: true,
  failureThreshold: 3,
  requireCountryMatch: true,
  autoHealOnAllFailed: true,
  autoHealCooldownMinutes: 10,
  standbyGroupCount: 2,
  standbyGroupSize: 3
});
function normalizePathAlias(raw) {
  const value = String(raw || "").trim();
  if (!value) {
    return "";
  }
  const stripped = value.replace(/^\/+/, "").replace(/\/+$/, "");
  if (!stripped) {
    return "";
  }
  return `/${stripped}`;
}
__name(normalizePathAlias, "normalizePathAlias");
function getAdminBasePath(env) {
  const raw = env?.admin_n || "";
  return normalizePathAlias(raw) || ROUTES.ADMIN_ROOT;
}
__name(getAdminBasePath, "getAdminBasePath");
function getAdminEntryBasePath(pathname, basePath) {
  const path = String(pathname || "");
  const bases = [normalizePathAlias(basePath), ROUTES.ADMIN_ALIAS].filter(Boolean);
  for (const base of bases) {
    const baseWithSlash = `${base}/`;
    if (path === base || path.startsWith(baseWithSlash)) {
      return base;
    }
  }
  return "";
}
__name(getAdminEntryBasePath, "getAdminEntryBasePath");
function envText(env, ...names) {
  for (const name of names) {
    const value = String(env?.[name] || "").trim();
    if (value) {
      return value;
    }
  }
  return "";
}
__name(envText, "envText");
function normalizeOptionalUrl(value) {
  const raw = String(value || "").trim();
  if (!raw) {
    return "";
  }
  try {
    const url = new URL(raw);
    if (url.protocol !== "https:" && url.protocol !== "http:") {
      return "";
    }
    return url.href.replace(/\/+$/, "");
  } catch (error) {
    return "";
  }
}
__name(normalizeOptionalUrl, "normalizeOptionalUrl");
function getProxyIpCatalogUrl(env, kind) {
  const normalized = String(kind || "summary").trim().toLowerCase().replace(/\.json$/, "");
  if (normalized === "summary") {
    return normalizeOptionalUrl(envText(env, "PROXYIP_CATALOG_SUMMARY_URL")) || PROXYIP_CATALOG_SUMMARY_URL;
  }
  if (normalized === "ipv4" || normalized === "v4" || normalized === "4") {
    return normalizeOptionalUrl(envText(env, "PROXYIP_CATALOG_IPV4_URL")) || PROXYIP_CATALOG_IPV4_URL;
  }
  if (normalized === "ipv6" || normalized === "v6" || normalized === "6") {
    return normalizeOptionalUrl(envText(env, "PROXYIP_CATALOG_IPV6_URL")) || PROXYIP_CATALOG_IPV6_URL;
  }
  if (normalized === "query") {
    return normalizeOptionalUrl(envText(env, "PROXYIP_CATALOG_QUERY_URL")) || PROXYIP_CATALOG_QUERY_URL;
  }
  return "";
}
__name(getProxyIpCatalogUrl, "getProxyIpCatalogUrl");
function validatePort(rawPort, defaultPort) {
  if (rawPort === void 0 || rawPort === null || rawPort === "") {
    return defaultPort;
  }
  if (!/^\d+$/.test(String(rawPort))) {
    throw new Error("endpoint port must be numeric");
  }
  const port = Number(rawPort);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("endpoint port must be between 1 and 65535");
  }
  return port;
}
__name(validatePort, "validatePort");
function normalizeHostname(rawHost) {
  const host = String(rawHost || "").trim().toLowerCase();
  if (!host || /[\s/?#@]/.test(host)) {
    throw new Error("endpoint hostname is invalid");
  }
  return host;
}
__name(normalizeHostname, "normalizeHostname");
function isIpv4Hostname(hostname) {
  const parts = String(hostname || "").split(".");
  return parts.length === 4 && parts.every((part) => /^\d+$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}
__name(isIpv4Hostname, "isIpv4Hostname");
function isValidTlsHostname(hostname) {
  const host = normalizeHostname(hostname).replace(/\.$/, "");
  if (!host.includes(".") || host.includes(":") || isIpv4Hostname(host) || host.length > 253) {
    return false;
  }
  return host.split(".").every((part) => part.length > 0 && part.length <= 63 && /^[a-z0-9-]+$/.test(part) && !part.startsWith("-") && !part.endsWith("-"));
}
__name(isValidTlsHostname, "isValidTlsHostname");
function parseEndpoint(rawValue, defaultPort = DEFAULTS.DEFAULT_PORT) {
  const value = String(rawValue || "").trim();
  if (!value) {
    throw new Error("endpoint is empty");
  }
  const bracketed = value.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (bracketed) {
    const hostname = normalizeHostname(bracketed[1]);
    if (!hostname.includes(":")) {
      throw new Error("brackets are only valid for IPv6 endpoints");
    }
    return {
      hostname,
      port: validatePort(bracketed[2], defaultPort),
      isIPv6: true
    };
  }
  const colonCount = (value.match(/:/g) || []).length;
  if (colonCount > 1) {
    return {
      hostname: normalizeHostname(value),
      port: defaultPort,
      isIPv6: true
    };
  }
  if (colonCount === 1) {
    const colonIndex = value.lastIndexOf(":");
    return {
      hostname: normalizeHostname(value.slice(0, colonIndex)),
      port: validatePort(value.slice(colonIndex + 1), defaultPort),
      isIPv6: false
    };
  }
  return {
    hostname: normalizeHostname(value),
    port: defaultPort,
    isIPv6: false
  };
}
__name(parseEndpoint, "parseEndpoint");
function formatEndpoint(endpoint) {
  const host = endpoint.isIPv6 || String(endpoint.hostname).includes(":") ? `[${endpoint.hostname}]` : endpoint.hostname;
  return `${host}:${endpoint.port}`;
}
__name(formatEndpoint, "formatEndpoint");
function endpointKey(endpoint) {
  return formatEndpoint(endpoint).toLowerCase();
}
__name(endpointKey, "endpointKey");
function parseEntryEndpoints(text) {
  const endpoints = [];
  const seen = new Set();
  for (const rawLine of String(text || "").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }
    const marker = line.lastIndexOf("#");
    const endpointText = marker === -1 ? line : line.slice(0, marker).trim();
    const label = marker === -1 ? "" : line.slice(marker + 1).trim();
    try {
      const endpoint = parseEndpoint(endpointText);
      const key = endpointKey(endpoint);
      if (!seen.has(key)) {
        seen.add(key);
        endpoints.push({ ...endpoint, label });
      }
    } catch (error) {
      console.warn(`[rk.txt] ignored invalid line: ${line}`, error);
    }
  }
  return endpoints;
}
__name(parseEntryEndpoints, "parseEntryEndpoints");
function parseProxyEndpoints(text) {
  const endpoints = [];
  const seen = new Set();
  for (const rawValue of String(text || "").split(/[\r\n\t,;]+/)) {
    const value = rawValue.trim();
    if (!value || value.toLowerCase() === "auto") {
      continue;
    }
    const endpoint = parseEndpoint(value);
    const key = endpointKey(endpoint);
    if (!seen.has(key)) {
      seen.add(key);
      endpoints.push(endpoint);
    }
  }
  return endpoints;
}
__name(parseProxyEndpoints, "parseProxyEndpoints");
function parseIPv4(hostname) {
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
    return null;
  }
  const octets = hostname.split(".").map(Number);
  if (octets.length !== 4 || octets.some((value) => value < 0 || value > 255)) {
    throw new Error("IPv4 address is invalid");
  }
  return octets;
}
__name(parseIPv4, "parseIPv4");
function ipv4ToUint32(octets) {
  return (octets[0] << 24 >>> 0) + (octets[1] << 16) + (octets[2] << 8) + octets[3] >>> 0;
}
__name(ipv4ToUint32, "ipv4ToUint32");
function ipv4InCidr(octets, cidr) {
  const [networkText, bitsText] = cidr.split("/");
  const network = parseIPv4(networkText);
  const bits = Number(bitsText);
  const mask = bits === 0 ? 0 : 4294967295 << 32 - bits >>> 0;
  return (ipv4ToUint32(octets) & mask) === (ipv4ToUint32(network) & mask);
}
__name(ipv4InCidr, "ipv4InCidr");
var CLOUDFLARE_IPV4_CIDRS = Object.freeze([
  "173.245.48.0/20",
  "103.21.244.0/22",
  "103.22.200.0/22",
  "103.31.4.0/22",
  "141.101.64.0/18",
  "108.162.192.0/18",
  "190.93.240.0/20",
  "188.114.96.0/20",
  "197.234.240.0/22",
  "198.41.128.0/17",
  "162.158.0.0/15",
  "104.16.0.0/13",
  "104.24.0.0/14",
  "172.64.0.0/13",
  "131.0.72.0/22"
]);
function isBlockedIPv4(octets) {
  const [a, b] = octets;
  return a === 0 || a === 10 || a === 127 || a === 100 && b >= 64 && b <= 127 || a === 169 && b === 254 || a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168 || a === 198 && (b === 18 || b === 19) || a >= 224;
}
__name(isBlockedIPv4, "isBlockedIPv4");
function isKnownCloudflareIPv4(octets) {
  return CLOUDFLARE_IPV4_CIDRS.some((cidr) => ipv4InCidr(octets, cidr));
}
__name(isKnownCloudflareIPv4, "isKnownCloudflareIPv4");
function isBlockedIPv6(hostname) {
  const host = hostname.toLowerCase();
  return host === "::" || host === "::1" || host.startsWith("fc") || host.startsWith("fd") || /^fe[89ab]/.test(host);
}
__name(isBlockedIPv6, "isBlockedIPv6");
function isKnownCloudflareIPv6(hostname) {
  const host = hostname.toLowerCase();
  return host.startsWith("2400:cb00:") || host.startsWith("2606:4700:") || host.startsWith("2803:f800:") || host.startsWith("2405:b500:") || host.startsWith("2405:8100:") || /^2a06:98c[0-7]:/.test(host) || host.startsWith("2c0f:f248:");
}
__name(isKnownCloudflareIPv6, "isKnownCloudflareIPv6");
function assertAllowedDialTarget(endpoint, workerHostname = "") {
  const hostname = normalizeHostname(endpoint.hostname);
  const workerHost = String(workerHostname || "").trim().toLowerCase();
  if (hostname === "localhost" || hostname.endsWith(".localhost") || hostname === workerHost) {
    throw new Error("dial target is blocked");
  }
  const ipv4 = parseIPv4(hostname);
  if (ipv4 && isBlockedIPv4(ipv4)) {
    throw new Error("private, local, or reserved IPv4 dial target is blocked");
  }
  if (ipv4 && isKnownCloudflareIPv4(ipv4)) {
    throw new Error("Cloudflare IPv4 dial target is blocked by Workers TCP sockets");
  }
  if (hostname.includes(":") && isBlockedIPv6(hostname)) {
    throw new Error("private or local IPv6 dial target is blocked");
  }
  if (hostname.includes(":") && isKnownCloudflareIPv6(hostname)) {
    throw new Error("Cloudflare IPv6 dial target is blocked by Workers TCP sockets");
  }
  validatePort(endpoint.port, DEFAULTS.DEFAULT_PORT);
}
__name(assertAllowedDialTarget, "assertAllowedDialTarget");
var PROXY_KEY = "\u53CD\u4EE3";
var SUB_KEY = "\u8BA2\u9605\u751F\u6210";
var SUB_KEY_LEGACY = "\u4F18\u9009\u8BA2\u9605\u751F\u6210";
var FULL_PATH_KEY = "\u5B8C\u6574\u8282\u70B9\u8DEF\u5F84";
function isUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    String(value || "").trim()
  );
}
__name(isUuid, "isUuid");
function normalizeWorkerHost(rawValue, fallbackHostname) {
  const fallback = String(fallbackHostname || "").trim().toLowerCase();
  const source = String(rawValue || fallback).trim();
  if (!source) {
    throw new Error("HOST is required");
  }
  let host = source;
  try {
    host = new URL(source.includes("://") ? source : `https://${source}`).hostname;
  } catch (error) {
    console.warn("[config] invalid HOST value", error);
    throw new Error("HOST is invalid");
  }
  host = host.toLowerCase().replace(/\.$/, "");
  if (!isValidTlsHostname(host)) {
    throw new Error("HOST must be a domain name");
  }
  return host;
}
__name(normalizeWorkerHost, "normalizeWorkerHost");
function normalizeBasePath(rawValue) {
  const value = String(rawValue || "/").trim();
  if (!value || value === "/") {
    return "/";
  }
  return `/${value.replace(/^\/+|\/+$/g, "")}`;
}
__name(normalizeBasePath, "normalizeBasePath");
function makeWsPath(config) {
  return normalizeBasePath(config.PATH);
}
__name(makeWsPath, "makeWsPath");
function normalizeProxyMode(value) {
  const mode = String(value || "").trim().toLowerCase();
  return mode === "proxy-only" ? "proxy-only" : "proxy-first-fallback-direct";
}
__name(normalizeProxyMode, "normalizeProxyMode");
function newUuid(env) {
  const envUuid = String(env?.UUID || "").trim();
  return isUuid(envUuid) ? envUuid.toLowerCase() : crypto.randomUUID();
}
__name(newUuid, "newUuid");
function hasEnvConfigFallback(env) {
  return Boolean(isUuid(String(env?.UUID || "").trim()) && envText(env, "SUB_TOKEN"));
}
__name(hasEnvConfigFallback, "hasEnvConfigFallback");
function createDefaultConfig(requestHostname, env = {}) {
  const host = normalizeWorkerHost(env.HOST, requestHostname);
  const envProxyip = envText(env, "PROXYIP");
  const envToken = envText(env, "SUB_TOKEN");
  const subscription = {
    TOKEN: envToken || crypto.randomUUID().replace(/-/g, ""),
    SUBNAME: DEFAULT_SUB_NAME,
    SUBUpdateTime: DEFAULTS.ROTATE_HOURS,
    local: true
  };
  return {
    UUID: newUuid(env),
    HOST: host,
    HOSTS: [host],
    PATH: "/",
    [FULL_PATH_KEY]: "/",
    LINK: "",
    Fingerprint: "chrome",
    [PROXY_KEY]: {
      PROXYIP: envProxyip,
      Mode: "proxy-first-fallback-direct",
      Select: "hash",
      RotateHours: DEFAULTS.ROTATE_HOURS,
      FailTtlHours: DEFAULTS.PROXY_FAIL_TTL_HOURS
    },
    [SUB_KEY]: subscription,
    [SUB_KEY_LEGACY]: subscription
  };
}
__name(createDefaultConfig, "createDefaultConfig");
function getSubscriptionInputBlock(input) {
  const current = input?.[SUB_KEY];
  if (current && typeof current === "object") {
    return current;
  }
  const legacy = input?.[SUB_KEY_LEGACY];
  if (legacy && typeof legacy === "object") {
    return legacy;
  }
  return {};
}
__name(getSubscriptionInputBlock, "getSubscriptionInputBlock");
function normalizeConfig(rawConfig, requestHostname, env = {}) {
  const defaults = createDefaultConfig(requestHostname, env);
  const input = rawConfig && typeof rawConfig === "object" && !Array.isArray(rawConfig) ? rawConfig : {};
  const knownInput = {};
  for (const key of ["UUID", "HOST", "HOSTS", "PATH", FULL_PATH_KEY, "LINK", "Fingerprint", PROXY_KEY]) {
    if (Object.prototype.hasOwnProperty.call(input, key)) {
      knownInput[key] = input[key];
    }
  }
  const hostCandidate = input.HOST || input.HOSTS?.[0] || defaults.HOST;
  const host = normalizeWorkerHost(hostCandidate, requestHostname);
  const uuid = isUuid(input.UUID) ? String(input.UUID).toLowerCase() : defaults.UUID;
  const proxyInput = input[PROXY_KEY] && typeof input[PROXY_KEY] === "object" ? input[PROXY_KEY] : {};
  const subInput = getSubscriptionInputBlock(input);
  const rotateHoursRaw = Number(proxyInput.RotateHours);
  const rotateHours = Number.isFinite(rotateHoursRaw) && rotateHoursRaw > 0 ? Math.min(rotateHoursRaw, 168) : DEFAULTS.ROTATE_HOURS;
  const failTtlHoursRaw = Number(proxyInput.FailTtlHours);
  const failTtlHours = Number.isFinite(failTtlHoursRaw) && failTtlHoursRaw > 0 ? Math.min(failTtlHoursRaw, 720) : DEFAULTS.PROXY_FAIL_TTL_HOURS;
  const subscription = {
    ...defaults[SUB_KEY],
    ...subInput,
    TOKEN: String(subInput.TOKEN || defaults[SUB_KEY].TOKEN).trim(),
    SUBNAME: String(subInput.SUBNAME || defaults[SUB_KEY].SUBNAME).trim() || DEFAULT_SUB_NAME
  };
  const config = {
    ...defaults,
    ...knownInput,
    UUID: uuid,
    HOST: host,
    HOSTS: Array.isArray(input.HOSTS) && input.HOSTS.length ? input.HOSTS : [host],
    PATH: normalizeBasePath(input.PATH),
    Fingerprint: String(input.Fingerprint || defaults.Fingerprint).trim() || "chrome",
    [PROXY_KEY]: {
      ...defaults[PROXY_KEY],
      ...proxyInput,
      PROXYIP: String(proxyInput.PROXYIP || "").trim(),
      Mode: normalizeProxyMode(proxyInput.Mode || defaults[PROXY_KEY].Mode),
      RotateHours: rotateHours,
      FailTtlHours: failTtlHours
    }
  };
  config[SUB_KEY] = subscription;
  config[SUB_KEY_LEGACY] = subscription;
  delete config.ECH;
  delete config.ECHConfig;
  config[FULL_PATH_KEY] = makeWsPath(config);
  return config;
}
__name(normalizeConfig, "normalizeConfig");
function getProxyConfig(config) {
  return config[PROXY_KEY] || {};
}
__name(getProxyConfig, "getProxyConfig");
function getSubscriptionConfig(config) {
  const current = config[SUB_KEY];
  if (current && typeof current === "object") {
    return current;
  }
  const legacy = config[SUB_KEY_LEGACY];
  if (legacy && typeof legacy === "object") {
    return legacy;
  }
  return {};
}
__name(getSubscriptionConfig, "getSubscriptionConfig");
function requireKv(env) {
  if (!env?.KV || typeof env.KV.get !== "function" || typeof env.KV.put !== "function") {
    throw new Error("KV binding named KV is required");
  }
  return env.KV;
}
__name(requireKv, "requireKv");
function isKvReadLimitError(error) {
  return /KV get\(\) limit exceeded|limit exceeded for the day/i.test(String(error?.message || error || ""));
}
__name(isKvReadLimitError, "isKvReadLimitError");
function cacheKvText(key, value, ttlMs, nowMs = Date.now()) {
  const text = value === null || value === void 0 ? "" : String(value);
  kvReadCache.set(key, {
    value: text,
    expiresAt: nowMs + Math.max(1e3, Number(ttlMs || KV_CACHE_TTL_MS))
  });
  if (kvReadCache.size > 64) {
    for (const [cacheKey, record] of kvReadCache.entries()) {
      if (!record || Number(record.expiresAt || 0) <= nowMs) {
        kvReadCache.delete(cacheKey);
      }
    }
  }
  return text;
}
__name(cacheKvText, "cacheKvText");
function cachedKvText(key, nowMs = Date.now()) {
  const record = kvReadCache.get(key);
  if (!record) {
    return null;
  }
  if (Number(record.expiresAt || 0) > nowMs) {
    return record.value;
  }
  return null;
}
__name(cachedKvText, "cachedKvText");
async function readCachedKvText(env, key, ttlMs = KV_CACHE_TTL_MS, options = {}) {
  const nowMs = Date.now();
  const cached = cachedKvText(key, nowMs);
  if (cached !== null) {
    return cached;
  }
  const stale = kvReadCache.get(key);
  if (options.useCacheOnly) {
    return stale?.value ?? String(options.fallback || "");
  }
  try {
    return cacheKvText(key, await requireKv(env).get(key), ttlMs, nowMs);
  } catch (error) {
    if (stale && Object.prototype.hasOwnProperty.call(stale, "value")) {
      console.warn(`[KV] using stale cache for ${key}`, error);
      return stale.value;
    }
    if (options.allowFallback !== false && isKvReadLimitError(error)) {
      console.warn(`[KV] read limit reached for ${key}; using fallback`);
      return String(options.fallback || "");
    }
    throw error;
  }
}
__name(readCachedKvText, "readCachedKvText");
async function writeKvTextAndCache(env, key, value, ttlMs = KV_CACHE_TTL_MS) {
  const text = value === null || value === void 0 ? "" : String(value);
  await requireKv(env).put(key, text);
  cacheKvText(key, text, ttlMs);
  return text;
}
__name(writeKvTextAndCache, "writeKvTextAndCache");
async function loadConfig(env, requestHostname, options = {}) {
  let stored = "";
  try {
    stored = await readCachedKvText(env, CONFIG_KV_KEY, KV_CACHE_TTL_MS, { allowFallback: false });
  } catch (error) {
    if (options.allowDefaultFallback === false && !hasEnvConfigFallback(env)) {
      throw error;
    }
    console.warn("[KV] pg.json unavailable; using env/default config", error);
    const fallback = createDefaultConfig(requestHostname, env);
    if (hasEnvConfigFallback(env)) {
      cacheKvText(CONFIG_KV_KEY, JSON.stringify(fallback), KV_CACHE_TTL_MS);
    }
    return fallback;
  }
  if (!stored) {
    const created = createDefaultConfig(requestHostname, env);
    await writeKvTextAndCache(env, CONFIG_KV_KEY, JSON.stringify(created, null, 2), KV_CACHE_TTL_MS);
    return created;
  }
  try {
    return normalizeConfig(JSON.parse(stored), requestHostname, env);
  } catch (error) {
    console.error("[KV] pg.json is invalid", error);
    throw new Error("KV pg.json is invalid JSON");
  }
}
__name(loadConfig, "loadConfig");
async function saveConfig(env, config, requestHostname) {
  const normalized = normalizeConfig(config, requestHostname, env);
  await writeKvTextAndCache(env, CONFIG_KV_KEY, JSON.stringify(normalized, null, 2), KV_CACHE_TTL_MS);
  return normalized;
}
__name(saveConfig, "saveConfig");
async function loadEntryEndpointsText(env) {
  return await readCachedKvText(env, ENTRY_ENDPOINTS_KV_KEY, KV_CACHE_TTL_MS, {
    fallback: ""
  }) || "";
}
__name(loadEntryEndpointsText, "loadEntryEndpointsText");
async function saveEntryEndpointsText(env, text) {
  await writeKvTextAndCache(env, ENTRY_ENDPOINTS_KV_KEY, String(text || ""), KV_CACHE_TTL_MS);
}
__name(saveEntryEndpointsText, "saveEntryEndpointsText");
function hashTextHex(value) {
  const text = String(value || "");
  let hash = 2166136261;
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}
__name(hashTextHex, "hashTextHex");
function subscriptionClientKey(request) {
  const ip = request.headers.get("CF-Connecting-IP") || request.headers.get("True-Client-IP") || request.headers.get("X-Forwarded-For") || "unknown";
  return hashTextHex(ip.split(",")[0].trim() || "unknown");
}
__name(subscriptionClientKey, "subscriptionClientKey");
function subscriptionRateLimitKey(request, nowMs = Date.now()) {
  const bucket = Math.floor(nowMs / (SUBSCRIPTION_GUARD.RATE_LIMIT_WINDOW_SECONDS * 1e3));
  return `${SUB_RATE_LIMIT_PREFIX}${bucket}.${subscriptionClientKey(request)}`;
}
__name(subscriptionRateLimitKey, "subscriptionRateLimitKey");
function subscriptionRateLimitResponse() {
  return new Response("Too Many Requests", {
    status: 429,
    headers: {
      ...TEXT_HEADERS,
      "Retry-After": String(SUBSCRIPTION_GUARD.RATE_LIMIT_WINDOW_SECONDS)
    }
  });
}
__name(subscriptionRateLimitResponse, "subscriptionRateLimitResponse");
function enforceSubscriptionMemoryRateLimit(request, nowMs = Date.now()) {
  const key = subscriptionRateLimitKey(request, nowMs);
  const expiresAt = nowMs + SUBSCRIPTION_GUARD.RATE_LIMIT_WINDOW_SECONDS * 1e3;
  const record = subscriptionRateMemory.get(key);
  const count = record && record.expiresAt > nowMs ? Number(record.count || 0) : 0;
  if (count >= SUBSCRIPTION_GUARD.RATE_LIMIT_PER_MINUTE) {
    return subscriptionRateLimitResponse();
  }
  subscriptionRateMemory.set(key, { count: count + 1, expiresAt });
  if (subscriptionRateMemory.size > 2048) {
    for (const [memoryKey, memoryRecord] of subscriptionRateMemory.entries()) {
      if (!memoryRecord || memoryRecord.expiresAt <= nowMs) {
        subscriptionRateMemory.delete(memoryKey);
      }
    }
  }
  return null;
}
__name(enforceSubscriptionMemoryRateLimit, "enforceSubscriptionMemoryRateLimit");
function enforceSubscriptionRateLimit(request, nowMs = Date.now()) {
  const memoryLimited = enforceSubscriptionMemoryRateLimit(request, nowMs);
  if (memoryLimited) {
    return memoryLimited;
  }
  return null;
}
__name(enforceSubscriptionRateLimit, "enforceSubscriptionRateLimit");
function proxyHealthSource(config) {
  return String(getProxyConfig(config).PROXYIP || "").trim();
}
__name(proxyHealthSource, "proxyHealthSource");
function proxyFailTtlMs(config) {
  const ttlHours = Number(getProxyConfig(config).FailTtlHours) || DEFAULTS.PROXY_FAIL_TTL_HOURS;
  return Math.max(1, ttlHours) * 60 * 60 * 1e3;
}
__name(proxyFailTtlMs, "proxyFailTtlMs");
function normalizeProxyHealth(rawHealth, config, nowMs) {
  const source = proxyHealthSource(config);
  const disabled = {};
  if (!rawHealth || rawHealth.source !== source || typeof rawHealth.disabled !== "object") {
    return { version: 1, source, disabled };
  }
  for (const [key, record] of Object.entries(rawHealth.disabled)) {
    const untilMs = Number(record?.untilMs || 0);
    if (untilMs > nowMs) {
      disabled[key] = record;
    }
  }
  return { version: 1, source, disabled };
}
__name(normalizeProxyHealth, "normalizeProxyHealth");
async function loadProxyHealth(env, config, nowMs = Date.now(), options = {}) {
  const stored = await readCachedKvText(env, PROXY_HEALTH_KV_KEY, KV_HEALTH_CACHE_TTL_MS, {
    fallback: "",
    useCacheOnly: Boolean(options.useCacheOnly)
  });
  if (!stored) {
    const empty = normalizeProxyHealth(null, config, nowMs);
    return { ...empty, disabledKeys: new Set() };
  }
  try {
    const health = normalizeProxyHealth(JSON.parse(stored), config, nowMs);
    return { ...health, disabledKeys: new Set(Object.keys(health.disabled)) };
  } catch (error) {
    console.warn("[KV] ignored invalid fd.jk.json", error);
    const empty = normalizeProxyHealth(null, config, nowMs);
    return { ...empty, disabledKeys: new Set() };
  }
}
__name(loadProxyHealth, "loadProxyHealth");
function shouldWriteProxyHealth(endpoint, action, nowMs = Date.now()) {
  const key = `${action}:${endpointKey(endpoint)}`;
  const previous = Number(proxyHealthWriteCache.get(key) || 0);
  if (previous && nowMs - previous < PROXY_HEALTH_WRITE_DEBOUNCE_MS) {
    return false;
  }
  proxyHealthWriteCache.set(key, nowMs);
  if (proxyHealthWriteCache.size > 256) {
    for (const [cacheKey, timestamp] of proxyHealthWriteCache.entries()) {
      if (nowMs - Number(timestamp || 0) > PROXY_HEALTH_WRITE_DEBOUNCE_MS) {
        proxyHealthWriteCache.delete(cacheKey);
      }
    }
  }
  return true;
}
__name(shouldWriteProxyHealth, "shouldWriteProxyHealth");
async function markProxyEndpointFailed(env, config, endpoint, error, options = {}, nowMs = Date.now()) {
  if (typeof options === "number") {
    nowMs = options;
    options = {};
  }
  if (options.write === false || !shouldWriteProxyHealth(endpoint, "failed", nowMs)) {
    return;
  }
  const health = await loadProxyHealth(env, config, nowMs);
  const key = endpointKey(endpoint);
  health.disabled[key] = {
    atMs: nowMs,
    untilMs: nowMs + proxyFailTtlMs(config),
    reason: String(error?.message || error || "TCP connect failed").slice(0, 200)
  };
  delete health.disabledKeys;
  await writeKvTextAndCache(env, PROXY_HEALTH_KV_KEY, JSON.stringify(health, null, 2), KV_HEALTH_CACHE_TTL_MS);
}
__name(markProxyEndpointFailed, "markProxyEndpointFailed");
async function markProxyEndpointHealthy(env, config, endpoint, options = {}, nowMs = Date.now()) {
  if (typeof options === "number") {
    nowMs = options;
    options = {};
  }
  if (options.write === false || !shouldWriteProxyHealth(endpoint, "healthy", nowMs)) {
    return;
  }
  const health = await loadProxyHealth(env, config, nowMs);
  const key = endpointKey(endpoint);
  if (!health.disabled[key]) {
    return;
  }
  delete health.disabled[key];
  delete health.disabledKeys;
  await writeKvTextAndCache(env, PROXY_HEALTH_KV_KEY, JSON.stringify(health, null, 2), KV_HEALTH_CACHE_TTL_MS);
}
__name(markProxyEndpointHealthy, "markProxyEndpointHealthy");
function normalizeProxyAutoCountry(rawValue, fallback = DEFAULT_PROXY_AUTO_SETTINGS.country) {
  const source = rawValue === void 0 || rawValue === null ? fallback : rawValue;
  const value = String(source || "").trim().toUpperCase();
  if (!value || value === "ALL") {
    return "";
  }
  const cleaned = value.replace(/[^A-Z]/g, "").slice(0, 3);
  return cleaned.length >= 2 ? cleaned : fallback;
}
__name(normalizeProxyAutoCountry, "normalizeProxyAutoCountry");
function normalizeProxyAutoPort(rawValue) {
  const value = String(rawValue || "").trim();
  if (!value || value.toLowerCase() === "all") {
    return "";
  }
  try {
    return String(validatePort(value, DEFAULTS.DEFAULT_PORT));
  } catch (error) {
    return "";
  }
}
__name(normalizeProxyAutoPort, "normalizeProxyAutoPort");
function normalizeProxyAutoStatus(rawValue) {
  const allowed = new Set(["verified", "usable", "verified,usable", "all"]);
  const value = String(rawValue || DEFAULT_PROXY_AUTO_SETTINGS.status).split(",").map((item) => item.trim().toLowerCase()).filter(Boolean).join(",");
  return allowed.has(value) ? value : DEFAULT_PROXY_AUTO_SETTINGS.status;
}
__name(normalizeProxyAutoStatus, "normalizeProxyAutoStatus");
function normalizeProxyAutoIpVersion(rawValue) {
  return String(rawValue || DEFAULT_PROXY_AUTO_SETTINGS.ipVersion).trim() === "6" ? "6" : "4";
}
__name(normalizeProxyAutoIpVersion, "normalizeProxyAutoIpVersion");
function normalizeProxyAutoSettings(rawSettings) {
  const input = rawSettings && typeof rawSettings === "object" && !Array.isArray(rawSettings) ? rawSettings : {};
  const normalizedPort = normalizeProxyAutoPort(input.port);
  const portMode = input.portMode === "explicit" ? "explicit" : "all";
  const hasExplicitEnabled = Object.prototype.hasOwnProperty.call(input, "enabled");
  return {
    enabled: hasExplicitEnabled ? Boolean(input.enabled) : DEFAULT_PROXY_AUTO_SETTINGS.enabled,
    ipVersion: normalizeProxyAutoIpVersion(input.ipVersion),
    country: normalizeProxyAutoCountry(input.country),
    port: portMode === "explicit" ? normalizedPort : "",
    portMode,
    status: normalizeProxyAutoStatus(input.status),
    candidateLimit: clampNumber(input.candidateLimit, DEFAULT_PROXY_AUTO_SETTINGS.candidateLimit, 1, 20),
    saveCount: clampNumber(input.saveCount, DEFAULT_PROXY_AUTO_SETTINGS.saveCount, 1, 10),
    timeoutMs: clampNumber(input.timeoutMs, DEFAULT_PROXY_AUTO_SETTINGS.timeoutMs, 1e3, 1500),
    concurrency: clampNumber(input.concurrency, DEFAULT_PROXY_AUTO_SETTINGS.concurrency, 1, 4),
    keepCurrentIfHealthy: input.keepCurrentIfHealthy !== false,
    failureThreshold: clampNumber(input.failureThreshold, DEFAULT_PROXY_AUTO_SETTINGS.failureThreshold, 1, 10),
    requireCountryMatch: input.requireCountryMatch !== false,
    autoHealOnAllFailed: input.autoHealOnAllFailed !== false,
    autoHealCooldownMinutes: clampNumber(
      input.autoHealCooldownMinutes,
      DEFAULT_PROXY_AUTO_SETTINGS.autoHealCooldownMinutes,
      1,
      120
    ),
    standbyGroupCount: clampNumber(
      input.standbyGroupCount,
      DEFAULT_PROXY_AUTO_SETTINGS.standbyGroupCount,
      1,
      4
    ),
    standbyGroupSize: clampNumber(
      input.standbyGroupSize,
      DEFAULT_PROXY_AUTO_SETTINGS.standbyGroupSize,
      1,
      10
    )
  };
}
__name(normalizeProxyAutoSettings, "normalizeProxyAutoSettings");
async function loadProxyAutoSettings(env) {
  const stored = await readCachedKvText(env, PROXY_AUTO_KV_KEY, KV_AUTO_CACHE_TTL_MS);
  if (!stored) {
    return normalizeProxyAutoSettings(DEFAULT_PROXY_AUTO_SETTINGS);
  }
  try {
    return normalizeProxyAutoSettings(JSON.parse(stored));
  } catch (error) {
    console.warn("[KV] ignored invalid fd.zd.json", error);
    return normalizeProxyAutoSettings(DEFAULT_PROXY_AUTO_SETTINGS);
  }
}
__name(loadProxyAutoSettings, "loadProxyAutoSettings");
async function saveProxyAutoSettings(env, settings) {
  const normalized = normalizeProxyAutoSettings(settings);
  await writeKvTextAndCache(env, PROXY_AUTO_KV_KEY, JSON.stringify(normalized, null, 2), KV_AUTO_CACHE_TTL_MS);
  return normalized;
}
__name(saveProxyAutoSettings, "saveProxyAutoSettings");
function normalizeProxyAutoState(rawState) {
  const input = rawState && typeof rawState === "object" && !Array.isArray(rawState) ? rawState : {};
  return {
    version: 1,
    status: String(input.status || "never-run"),
    action: String(input.action || "none"),
    reason: String(input.reason || ""),
    trigger: String(input.trigger || ""),
    startedAt: String(input.startedAt || ""),
    finishedAt: String(input.finishedAt || ""),
    currentProxyip: String(input.currentProxyip || ""),
    selectedProxyip: Array.isArray(input.selectedProxyip) ? input.selectedProxyip.map(String).filter(Boolean) : [],
    currentFailureCount: Math.max(0, Number(input.currentFailureCount || 0)),
    lastAutoHealAt: String(input.lastAutoHealAt || ""),
    autoHealCooldownUntil: String(input.autoHealCooldownUntil || ""),
    autoHealReason: String(input.autoHealReason || ""),
    standbyProxyip: Array.isArray(input.standbyProxyip) ? input.standbyProxyip.map(String).filter(Boolean) : [],
    standbyGroups: Array.isArray(input.standbyGroups) ? input.standbyGroups.map((group) => Array.isArray(group) ? group.map(String).filter(Boolean) : []).filter((group) => group.length) : [],
    nextStandbyGroupIndex: Math.max(0, Number(input.nextStandbyGroupIndex || 0)),
    standbyUpdatedAt: String(input.standbyUpdatedAt || ""),
    standbyConsumedAt: String(input.standbyConsumedAt || ""),
    currentResults: Array.isArray(input.currentResults) ? input.currentResults : [],
    candidateResults: Array.isArray(input.candidateResults) ? input.candidateResults : []
  };
}
__name(normalizeProxyAutoState, "normalizeProxyAutoState");
async function loadProxyAutoState(env) {
  const stored = await readCachedKvText(env, PROXY_AUTO_STATE_KV_KEY, KV_AUTO_STATE_CACHE_TTL_MS);
  if (!stored) {
    return normalizeProxyAutoState(null);
  }
  try {
    return normalizeProxyAutoState(JSON.parse(stored));
  } catch (error) {
    console.warn("[KV] ignored invalid fd.zt.json", error);
    return normalizeProxyAutoState(null);
  }
}
__name(loadProxyAutoState, "loadProxyAutoState");
async function saveProxyAutoState(env, state) {
  const normalized = normalizeProxyAutoState(state);
  await writeKvTextAndCache(env, PROXY_AUTO_STATE_KV_KEY, JSON.stringify(normalized, null, 2), KV_AUTO_STATE_CACHE_TTL_MS);
  return normalized;
}
__name(saveProxyAutoState, "saveProxyAutoState");
function proxyAutoHostname(env, fallbackHostname = "") {
  const value = String(env?.HOST || fallbackHostname || "localhost").trim();
  try {
    return normalizeWorkerHost(value, "localhost");
  } catch (error) {
    return "localhost";
  }
}
__name(proxyAutoHostname, "proxyAutoHostname");
function slimProbeResult(result) {
  return {
    proxy: String(result?.proxy || ""),
    ok: Boolean(result?.ok),
    connectMs: result?.connectMs ?? null,
    traceMs: result?.traceMs ?? null,
    googleMs: result?.googleMs ?? null,
    httpStatus: result?.httpStatus ?? null,
    exitIp: String(result?.exitIp || ""),
    loc: String(result?.loc || ""),
    colo: String(result?.colo || ""),
    warp: String(result?.warp || ""),
    tls: String(result?.tls || ""),
    googleOk: result?.googleOk ?? null,
    googleStatus: result?.googleStatus ?? null,
    googleError: result?.googleError ? String(result.googleError).slice(0, 200) : null,
    error: result?.error ? String(result.error).slice(0, 200) : null
  };
}
__name(slimProbeResult, "slimProbeResult");
function isProxyAutoResultUsable(result, settings) {
  if (!result?.ok) {
    return false;
  }
  if (!settings.requireCountryMatch || !settings.country) {
    return true;
  }
  return String(result.loc || "").toUpperCase() === settings.country;
}
__name(isProxyAutoResultUsable, "isProxyAutoResultUsable");
function proxyAutoEntryExitMatches(result) {
  const entryIp = String(result?.proxy || "").split(":")[0].trim().toLowerCase();
  const exitIp = String(result?.exitIp || "").trim().toLowerCase();
  return Boolean(entryIp && exitIp && entryIp === exitIp);
}
__name(proxyAutoEntryExitMatches, "proxyAutoEntryExitMatches");
function sortProxyAutoResults(left, right) {
  const leftSame = proxyAutoEntryExitMatches(left);
  const rightSame = proxyAutoEntryExitMatches(right);
  if (leftSame !== rightSame) {
    return leftSame ? -1 : 1;
  }
  const leftScore = Number(left.traceMs || 999999) + Number(left.connectMs || 999999);
  const rightScore = Number(right.traceMs || 999999) + Number(right.connectMs || 999999);
  return leftScore - rightScore;
}
__name(sortProxyAutoResults, "sortProxyAutoResults");
function selectProxyAutoResults(results, settings, limit, excluded = new Set()) {
  const excludedSet = excluded instanceof Set ? excluded : new Set(excluded || []);
  return (Array.isArray(results) ? results : []).filter((result) => isProxyAutoResultUsable(result, settings)).filter((result) => !excludedSet.has(String(result.proxy || "").toLowerCase())).sort(sortProxyAutoResults).slice(0, limit).map((result) => result.proxy);
}
__name(selectProxyAutoResults, "selectProxyAutoResults");
function splitStandbyGroups(proxyList, settings) {
  const groups = [];
  const size = Math.max(1, Number(settings.standbyGroupSize || DEFAULT_PROXY_AUTO_SETTINGS.standbyGroupSize));
  const count = Math.max(1, Number(settings.standbyGroupCount || DEFAULT_PROXY_AUTO_SETTINGS.standbyGroupCount));
  for (let index = 0; index < count; index += 1) {
    const group = proxyList.slice(index * size, (index + 1) * size);
    if (group.length) {
      groups.push(group);
    }
  }
  return groups;
}
__name(splitStandbyGroups, "splitStandbyGroups");
function flattenStandbyGroups(groups) {
  return (Array.isArray(groups) ? groups : []).flatMap((group) => Array.isArray(group) ? group : []);
}
__name(flattenStandbyGroups, "flattenStandbyGroups");
function standbyStatePatch(groups, candidateResults = []) {
  const standbyGroups = Array.isArray(groups) ? groups : [];
  return {
    standbyGroups,
    standbyProxyip: flattenStandbyGroups(standbyGroups),
    nextStandbyGroupIndex: 0,
    standbyUpdatedAt: (new Date()).toISOString(),
    candidateResults
  };
}
__name(standbyStatePatch, "standbyStatePatch");
function proxyAutoShuffleNodes(nodes) {
  const shuffled = Array.isArray(nodes) ? [...nodes] : [];
  for (let index = shuffled.length - 1; index > 0; index -= 1) {
    const randomValue = crypto.getRandomValues(new Uint32Array(1))[0];
    const swapIndex = randomValue % (index + 1);
    const current = shuffled[index];
    shuffled[index] = shuffled[swapIndex];
    shuffled[swapIndex] = current;
  }
  return shuffled;
}
__name(proxyAutoShuffleNodes, "proxyAutoShuffleNodes");
function proxyAutoStatusMatches(node, status) {
  const normalizedStatus = String(status || DEFAULT_PROXY_AUTO_SETTINGS.status).trim().toLowerCase();
  if (!normalizedStatus || normalizedStatus === "all") {
    return true;
  }
  const allowedStatuses = new Set(normalizedStatus.split(",").map((item) => item.trim()).filter(Boolean));
  return allowedStatuses.has(String(node?.status || "").trim().toLowerCase());
}
__name(proxyAutoStatusMatches, "proxyAutoStatusMatches");
function proxyAutoNodeMatchesSettings(node, settings) {
  if (!node) {
    return false;
  }
  if (settings.country && String(node.country || "").trim().toUpperCase() !== settings.country) {
    return false;
  }
  if (settings.port && String(node.port || "").trim() !== String(settings.port).trim()) {
    return false;
  }
  return proxyAutoStatusMatches(node, settings.status);
}
__name(proxyAutoNodeMatchesSettings, "proxyAutoNodeMatchesSettings");
function proxyAutoCandidateNodesFromCatalog(nodes, settings) {
  const matchingNodes = (Array.isArray(nodes) ? nodes : []).filter((node) => proxyAutoNodeMatchesSettings(node, settings));
  return proxyAutoShuffleNodes(matchingNodes).slice(0, settings.candidateLimit);
}
__name(proxyAutoCandidateNodesFromCatalog, "proxyAutoCandidateNodesFromCatalog");
async function fetchProxyAutoCandidates(settings, env) {
  const catalogUrl = getProxyIpCatalogUrl(env, settings.ipVersion === "6" ? "ipv6" : "ipv4");
  if (!catalogUrl) {
    throw new Error("PROXYIP catalog URL is not configured");
  }
  const response = await fetch(catalogUrl, { headers: { Accept: "application/json" } });
  const text = await response.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch (error) {
    throw new Error("catalog response is not JSON");
  }
  if (!response.ok) {
    throw new Error(data?.error || `catalog HTTP ${response.status}`);
  }
  return proxyAutoCandidateNodesFromCatalog(data.nodes, settings);
}
__name(fetchProxyAutoCandidates, "fetchProxyAutoCandidates");
function proxyAutoEndpointsFromNodes(nodes, maxTargets) {
  const targets = (Array.isArray(nodes) ? nodes : []).map((node) => node?.proxy || (node?.ip && node?.port ? `${node.ip}:${node.port}` : "")).filter(Boolean);
  return parseProbeTargets(targets, maxTargets).endpoints;
}
__name(proxyAutoEndpointsFromNodes, "proxyAutoEndpointsFromNodes");
async function refreshProxyStandbyPool(env, settings, hostname, excludedProxyip = []) {
  const nodes = await fetchProxyAutoCandidates(settings, env);
  const candidateEndpoints = proxyAutoEndpointsFromNodes(nodes, settings.candidateLimit);
  if (!candidateEndpoints.length) {
    return {
      standbyGroups: [],
      standbyProxyip: [],
      candidateResults: [],
      reason: "catalog returned no valid standby candidates"
    };
  }
  const candidateResults = await runLimited(
    candidateEndpoints,
    settings.concurrency,
    (endpoint) => probeProxyEndpoint(endpoint, hostname, randomProxyProbeTimeoutMs(settings.timeoutMs))
  );
  const slimCandidateResults = candidateResults.map(slimProbeResult);
  const needed = settings.standbyGroupCount * settings.standbyGroupSize;
  const excluded = new Set(
    (Array.isArray(excludedProxyip) ? excludedProxyip : []).map((proxy) => String(proxy || "").toLowerCase()).filter(Boolean)
  );
  const standbyProxyip = selectProxyAutoResults(slimCandidateResults, settings, needed, excluded);
  const standbyGroups = splitStandbyGroups(standbyProxyip, settings);
  return {
    standbyGroups,
    standbyProxyip,
    candidateResults: slimCandidateResults,
    reason: standbyProxyip.length ? "standby pool refreshed" : "no usable standby candidate matched the auto policy"
  };
}
__name(refreshProxyStandbyPool, "refreshProxyStandbyPool");
function buildStandbyGroupsFromResults(results, settings, excludedProxyip = []) {
  const needed = settings.standbyGroupCount * settings.standbyGroupSize;
  const excluded = new Set(
    (Array.isArray(excludedProxyip) ? excludedProxyip : []).map((proxy) => String(proxy || "").toLowerCase()).filter(Boolean)
  );
  const standbyProxyip = selectProxyAutoResults(results, settings, needed, excluded);
  return splitStandbyGroups(standbyProxyip, settings);
}
__name(buildStandbyGroupsFromResults, "buildStandbyGroupsFromResults");
function shouldRefreshProxyStandbyPool(state, settings, trigger) {
  const required = settings.standbyGroupCount * settings.standbyGroupSize;
  if (flattenStandbyGroups(state.standbyGroups).length < required) {
    return true;
  }
  if (trigger === "scheduled") {
    return true;
  }
  const consumedMs = parseStateTimeMs(state.standbyConsumedAt);
  const updatedMs = parseStateTimeMs(state.standbyUpdatedAt);
  return consumedMs > updatedMs;
}
__name(shouldRefreshProxyStandbyPool, "shouldRefreshProxyStandbyPool");
async function promoteStandbyProxyip(env, config, settings, reason, nowMs = Date.now()) {
  const state = await loadProxyAutoState(env);
  const groups = Array.isArray(state.standbyGroups) ? state.standbyGroups.filter((group) => Array.isArray(group) && group.length) : [];
  if (!groups.length) {
    return { promoted: false, reason: "standby pool is empty" };
  }
  const index = Math.min(groups.length - 1, Math.max(0, Number(state.nextStandbyGroupIndex || 0) % groups.length));
  const selectedProxyip = groups[index];
  const remainingGroups = groups.filter((_, groupIndex) => groupIndex !== index);
  const currentProxyip = selectedProxyip.join(",");
  const timestamp = new Date(nowMs).toISOString();
  const savedState = await saveProxyAutoState(env, {
    ...state,
    status: "success",
    action: "promoted-standby",
    reason: "promoted standby PROXYIP after active pool failed",
    trigger: "auto-heal",
    startedAt: timestamp,
    finishedAt: timestamp,
    currentProxyip,
    selectedProxyip,
    currentFailureCount: 0,
    lastAutoHealAt: timestamp,
    autoHealReason: String(reason?.message || reason || "all configured PROXYIP failed").slice(0, 200),
    standbyGroups: remainingGroups,
    standbyProxyip: flattenStandbyGroups(remainingGroups),
    nextStandbyGroupIndex: 0,
    standbyConsumedAt: timestamp
  });
  return {
    promoted: true,
    reason: savedState.reason,
    config,
    state: savedState
  };
}
__name(promoteStandbyProxyip, "promoteStandbyProxyip");
function parseCurrentProxyAutoEndpoints(config) {
  try {
    return parseProxyEndpoints(getProxyConfig(config).PROXYIP || "");
  } catch (error) {
    console.warn("[proxy-auto] ignored invalid current PROXYIP", error);
    return [];
  }
}
__name(parseCurrentProxyAutoEndpoints, "parseCurrentProxyAutoEndpoints");
function proxyAutoStateProxyip(state) {
  const current = String(state?.currentProxyip || "").trim();
  if (current) {
    return current;
  }
  if (Array.isArray(state?.selectedProxyip)) {
    return state.selectedProxyip.map((proxy) => String(proxy || "").trim()).filter(Boolean).join(",");
  }
  return "";
}
__name(proxyAutoStateProxyip, "proxyAutoStateProxyip");
var currentProxyipForAdmin = (settings, state, config) => settings?.enabled !== false ? proxyAutoStateProxyip(state) : String(getProxyConfig(config).PROXYIP || "").trim();
function parseProxyAutoStateEndpoints(state) {
  const source = proxyAutoStateProxyip(state);
  if (!source) {
    return [];
  }
  try {
    return parseProxyEndpoints(source);
  } catch (error) {
    console.warn("[proxy-auto] ignored invalid active auto PROXYIP", error);
    return [];
  }
}
__name(parseProxyAutoStateEndpoints, "parseProxyAutoStateEndpoints");
async function loadRuntimeProxyInfo(env, config) {
  const proxyConfig = getProxyConfig(config);
  const proxyMode = normalizeProxyMode(proxyConfig.Mode);
  let source = String(proxyConfig.PROXYIP || "").trim();
  let autoEnabled = false;
  let autoState = null;
  try {
    const settings = await loadProxyAutoSettings(env);
    autoEnabled = settings.enabled !== false;
    if (autoEnabled) {
      autoState = await loadProxyAutoState(env);
      const autoSource = proxyAutoStateProxyip(autoState);
      if (autoSource) {
        source = autoSource;
      }
    }
  } catch (error) {
    console.warn("[proxy-auto] failed to load runtime auto state; using manual PROXYIP", error);
  }
  let endpoints = [];
  try {
    endpoints = source ? parseProxyEndpoints(source) : [];
  } catch (error) {
    console.warn("[proxy-auto] ignored invalid runtime PROXYIP", error);
  }
  return { source, endpoints, proxyMode, autoEnabled, autoState };
}
__name(loadRuntimeProxyInfo, "loadRuntimeProxyInfo");
function buildProxyAutoState(base, patch) {
  const finishedAt = (new Date()).toISOString();
  return normalizeProxyAutoState({
    ...base,
    ...patch,
    finishedAt
  });
}
__name(buildProxyAutoState, "buildProxyAutoState");
async function runProxyAutoMaintenance(env, options = {}) {
  const trigger = String(options.trigger || "manual");
  const hostname = proxyAutoHostname(env, options.hostname);
  const settings = options.settings ? normalizeProxyAutoSettings(options.settings) : await loadProxyAutoSettings(env);
  const previousState = await loadProxyAutoState(env);
  const startedAt = (new Date()).toISOString();
  const baseState = {
    version: 1,
    trigger,
    startedAt,
    status: "running",
    action: "none",
    reason: "",
    currentFailureCount: previousState.currentFailureCount,
    lastAutoHealAt: options.lastAutoHealAt || previousState.lastAutoHealAt,
    autoHealCooldownUntil: options.autoHealCooldownUntil || previousState.autoHealCooldownUntil,
    autoHealReason: options.autoHealReason || previousState.autoHealReason,
    standbyProxyip: previousState.standbyProxyip,
    standbyGroups: previousState.standbyGroups,
    nextStandbyGroupIndex: previousState.nextStandbyGroupIndex,
    standbyUpdatedAt: previousState.standbyUpdatedAt,
    standbyConsumedAt: previousState.standbyConsumedAt
  };
  if (!settings.enabled && !options.forceEnabled) {
    const state2 = await saveProxyAutoState(env, buildProxyAutoState(baseState, {
      status: "skipped",
      action: "none",
      reason: "auto maintenance disabled",
      currentFailureCount: previousState.currentFailureCount
    }));
    return { success: true, settings, state: state2 };
  }
  const config = await loadConfig(env, hostname);
  const proxyConfig = getProxyConfig(config);
  const stateProxyip = proxyAutoStateProxyip(previousState);
  const currentProxyip = stateProxyip || String(proxyConfig.PROXYIP || "").trim();
  const currentEndpoints = stateProxyip ? parseProxyAutoStateEndpoints(previousState) : parseCurrentProxyAutoEndpoints(config);
  let currentFailureCount = previousState.currentProxyip === currentProxyip ? Number(previousState.currentFailureCount || 0) : 0;
  if (settings.keepCurrentIfHealthy && currentEndpoints.length && !options.forceReplace) {
    const currentResults = await runLimited(
      currentEndpoints,
      settings.concurrency,
      (endpoint) => probeProxyEndpoint(endpoint, hostname, randomProxyProbeTimeoutMs(settings.timeoutMs))
    );
    const slimCurrentResults = currentResults.map(slimProbeResult);
    const usableCurrent = slimCurrentResults.filter((result) => isProxyAutoResultUsable(result, settings));
    if (usableCurrent.length) {
      const selectedCurrentProxyip = usableCurrent.map((result) => String(result.proxy || "").trim()).filter(Boolean);
      const filteredCurrentProxyip = selectedCurrentProxyip.join(",");
      const filteredCurrent = selectedCurrentProxyip.length !== currentEndpoints.length;
      let standbyPatch = {};
      if (shouldRefreshProxyStandbyPool(previousState, settings, trigger)) {
        const standby = await refreshProxyStandbyPool(
          env,
          settings,
          hostname,
          selectedCurrentProxyip
        );
        standbyPatch = standbyStatePatch(standby.standbyGroups, standby.candidateResults);
      }
      const state2 = await saveProxyAutoState(env, buildProxyAutoState(baseState, {
        status: "success",
        action: filteredCurrent ? "filtered-current" : "kept-current",
        reason: filteredCurrent ? "filtered current PROXYIP by auto policy" : "current PROXYIP is healthy",
        currentProxyip: filteredCurrentProxyip || currentProxyip,
        currentFailureCount: 0,
        currentResults: slimCurrentResults,
        selectedProxyip: selectedCurrentProxyip,
        ...standbyPatch
      }));
      return { success: true, settings, state: state2 };
    }
    currentFailureCount += 1;
    if (currentFailureCount < settings.failureThreshold) {
      const state2 = await saveProxyAutoState(env, buildProxyAutoState(baseState, {
        status: "deferred",
        action: "kept-current",
        reason: `current PROXYIP failed ${currentFailureCount}/${settings.failureThreshold}`,
        currentProxyip,
        currentFailureCount,
        currentResults: slimCurrentResults,
        selectedProxyip: currentEndpoints.map(formatEndpoint)
      }));
      return { success: true, settings, state: state2 };
    }
  }
  const nodes = await fetchProxyAutoCandidates(settings, env);
  const candidateEndpoints = proxyAutoEndpointsFromNodes(nodes, settings.candidateLimit);
  if (!candidateEndpoints.length) {
    const state2 = await saveProxyAutoState(env, buildProxyAutoState(baseState, {
      status: "failed",
      action: "none",
      reason: "catalog returned no valid candidates",
      currentProxyip,
      currentFailureCount,
      selectedProxyip: currentEndpoints.map(formatEndpoint)
    }));
    return { success: true, settings, state: state2 };
  }
  const candidateResults = await runLimited(
    candidateEndpoints,
    settings.concurrency,
    (endpoint) => probeProxyEndpoint(endpoint, hostname, randomProxyProbeTimeoutMs(settings.timeoutMs))
  );
  const slimCandidateResults = candidateResults.map(slimProbeResult);
  const selectedProxyip = selectProxyAutoResults(slimCandidateResults, settings, settings.saveCount);
  if (!selectedProxyip.length) {
    const state2 = await saveProxyAutoState(env, buildProxyAutoState(baseState, {
      status: "failed",
      action: "none",
      reason: "no usable candidate matched the auto policy",
      currentProxyip,
      currentFailureCount,
      selectedProxyip: currentEndpoints.map(formatEndpoint),
      candidateResults: slimCandidateResults
    }));
    return { success: true, settings, state: state2 };
  }
  const selectedProxyipText = selectedProxyip.join(",");
  const standbyGroups = buildStandbyGroupsFromResults(slimCandidateResults, settings, selectedProxyip);
  const state = await saveProxyAutoState(env, buildProxyAutoState(baseState, {
    status: "success",
    action: "updated",
    reason: "selected healthy PROXYIP candidates",
    currentProxyip: selectedProxyipText,
    currentFailureCount: 0,
    selectedProxyip,
    ...standbyStatePatch(standbyGroups, slimCandidateResults)
  }));
  return { success: true, settings, state };
}
__name(runProxyAutoMaintenance, "runProxyAutoMaintenance");
function parseStateTimeMs(value) {
  const ms = Date.parse(String(value || ""));
  return Number.isFinite(ms) ? ms : 0;
}
__name(parseStateTimeMs, "parseStateTimeMs");
async function runProxyAutoHealAfterAllFailed(env, config, reason) {
  const settings = await loadProxyAutoSettings(env);
  if (!settings.enabled || !settings.autoHealOnAllFailed) {
    return { healed: false, reason: "auto-heal disabled" };
  }
  const nowMs = Date.now();
  const promoted = await promoteStandbyProxyip(env, config, settings, reason, nowMs);
  if (promoted.promoted) {
    return {
      healed: true,
      reason: promoted.reason,
      config: promoted.config,
      result: { success: true, settings, state: promoted.state }
    };
  }
  const previousState = await loadProxyAutoState(env);
  const cooldownUntilMs = parseStateTimeMs(previousState.autoHealCooldownUntil);
  if (cooldownUntilMs > nowMs) {
    return {
      healed: false,
      reason: "auto-heal cooldown",
      cooldownUntil: previousState.autoHealCooldownUntil
    };
  }
  const lastAutoHealAt = new Date(nowMs).toISOString();
  const autoHealCooldownUntil = new Date(
    nowMs + settings.autoHealCooldownMinutes * 60 * 1e3
  ).toISOString();
  const result = await runProxyAutoMaintenance(env, {
    trigger: "auto-heal",
    hostname: config.HOST,
    forceEnabled: true,
    forceReplace: true,
    lastAutoHealAt,
    autoHealCooldownUntil,
    autoHealReason: String(reason?.message || reason || "all configured PROXYIP failed").slice(0, 200)
  });
  const selected = result?.state?.selectedProxyip || [];
  if (result?.state?.action !== "updated" || !selected.length) {
    return {
      healed: false,
      reason: result?.state?.reason || "auto-heal did not select a new PROXYIP",
      result
    };
  }
  return {
    healed: true,
    reason: result.state.reason,
    config,
    result
  };
}
__name(runProxyAutoHealAfterAllFailed, "runProxyAutoHealAfterAllFailed");
async function retryProxyDialAfterAutoHeal(env, config, failedError, initialPayload = new Uint8Array(0)) {
  const heal = await runProxyAutoHealAfterAllFailed(env, config, failedError);
  if (!heal.healed) {
    throw failedError;
  }
  const runtimeInfo = await loadRuntimeProxyInfo(env, heal.config);
  const healedProxies = runtimeInfo.endpoints;
  if (!healedProxies.length) {
    throw failedError;
  }
  const proxyHealth = await loadProxyHealth(env, heal.config);
  const candidates = buildProxyDialCandidates(healedProxies, proxyHealth.disabledKeys);
  if (!candidates.length) {
    throw failedError;
  }
  const dial = await openFirstProxyTcpSocket(candidates, env, heal.config, initialPayload);
  return {
    ...dial,
    config: heal.config,
    heal
  };
}
__name(retryProxyDialAfterAutoHeal, "retryProxyDialAfterAutoHeal");
function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
__name(bytesToHex, "bytesToHex");
function textBytes(value) {
  return new TextEncoder().encode(String(value));
}
__name(textBytes, "textBytes");
async function hmacHex(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    textBytes(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return bytesToHex(new Uint8Array(await crypto.subtle.sign("HMAC", key, textBytes(message))));
}
__name(hmacHex, "hmacHex");
function getAdminPassword(env) {
  const password = String(env?.ADMIN || "").trim();
  if (!password) {
    throw new Error("ADMIN secret is required");
  }
  return password;
}
__name(getAdminPassword, "getAdminPassword");
function getCookieValue(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";
  for (const part of cookieHeader.split(";")) {
    const [cookieName, ...rest] = part.trim().split("=");
    if (cookieName === name) {
      return rest.join("=");
    }
  }
  return "";
}
__name(getCookieValue, "getCookieValue");
function equalText(left, right) {
  const a = String(left || "");
  const b = String(right || "");
  if (a.length !== b.length) {
    return false;
  }
  let mismatch = 0;
  for (let index = 0; index < a.length; index += 1) {
    mismatch |= a.charCodeAt(index) ^ b.charCodeAt(index);
  }
  return mismatch === 0;
}
__name(equalText, "equalText");
async function makeSessionToken(env) {
  const password = getAdminPassword(env);
  return hmacHex(password, `worker-slim-admin:${password}`);
}
__name(makeSessionToken, "makeSessionToken");
function getAdminRequestPassword(request) {
  const explicit = String(request.headers.get("X-Admin-Password") || "").trim();
  if (explicit) {
    return explicit;
  }
  const authorization = String(request.headers.get("Authorization") || "").trim();
  if (/^Bearer\s+/i.test(authorization)) {
    return authorization.replace(/^Bearer\s+/i, "").trim();
  }
  return "";
}
__name(getAdminRequestPassword, "getAdminRequestPassword");
async function isAdminRequest(request, env) {
  const expected = await makeSessionToken(env);
  if (equalText(getCookieValue(request, "auth"), expected)) {
    return true;
  }
  const headerPassword = getAdminRequestPassword(request);
  return Boolean(headerPassword) && equalText(headerPassword, getAdminPassword(env));
}
__name(isAdminRequest, "isAdminRequest");
function loginHtml(message = "") {
  const note = message ? `<p class="error">${escapeHtml(message)}</p>` : "";
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>IP168 \u767B\u5F55</title>
<style>
:root{color-scheme:dark;--text:rgba(255,255,255,.92);--muted:rgba(255,255,255,.62);--line:rgba(255,255,255,.78);--line-strong:rgba(255,255,255,.96);--control-bg:rgba(255,255,255,.018);--control-bg-hover:rgba(255,255,255,.075);--control-bg-active:rgba(255,255,255,.175);--danger:#ffd1d1;--hairline:rgba(255,255,255,.34);font-family:"Microsoft YaHei","PingFang SC","Noto Sans SC","Noto Sans CJK SC",Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
*{box-sizing:border-box}
html,body{min-height:100%}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;position:relative;overflow:hidden;color:var(--text);background:linear-gradient(90deg,rgba(68,45,45,.92) 0%,rgba(43,37,41,.96) 42%,#202028 100%),linear-gradient(180deg,#3b2d2d 0%,#222229 100%)}
body::before,body::after{content:"";position:fixed;inset:-12%;pointer-events:none}
body::before{background:linear-gradient(rgba(255,255,255,.055) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.05) 1px,transparent 1px);background-size:66px 66px;opacity:.38;transform:rotate(-13deg) scale(1.35);transform-origin:center}
body::after{background:linear-gradient(118deg,rgba(255,255,255,.08),transparent 24%,rgba(0,0,0,.18) 58%,transparent 88%),repeating-linear-gradient(152deg,transparent 0 118px,rgba(255,255,255,.035) 119px,transparent 120px),radial-gradient(circle at 50% 52%,transparent 0 30%,rgba(0,0,0,.34) 78%);opacity:.74}
main{width:min(560px,calc(100vw - 48px));display:grid;position:relative;z-index:1;padding:0;text-align:center}
main::before,main::after{content:"";position:absolute;top:50%;width:72px;height:1px;pointer-events:none;opacity:.72}
main::before{left:-96px;background:linear-gradient(90deg,transparent,var(--hairline))}
main::after{right:-96px;background:linear-gradient(90deg,var(--hairline),transparent)}
form{display:grid;gap:14px;justify-items:center;margin:0;padding:28px 0;position:relative;border-top:1px solid var(--line);border-bottom:1px solid var(--line)}
form::before,form::after{content:"";position:absolute;left:0;right:0;height:28px;pointer-events:none;opacity:.86;background:linear-gradient(var(--line-strong),var(--line-strong)) left top/64px 1px no-repeat,linear-gradient(var(--line-strong),var(--line-strong)) right top/64px 1px no-repeat,linear-gradient(var(--hairline),var(--hairline)) left top/1px 22px no-repeat,linear-gradient(var(--hairline),var(--hairline)) right top/1px 22px no-repeat}
form::before{top:-1px}
form::after{bottom:-1px;transform:rotate(180deg)}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
input,button{width:min(360px,100%);min-height:58px;border:1px solid var(--line);border-radius:4px;background:var(--control-bg);color:var(--text);font:inherit;letter-spacing:0;box-shadow:inset 0 0 0 1px rgba(255,255,255,.055),0 16px 34px rgba(0,0,0,.12);backdrop-filter:blur(2px) saturate(1.06);-webkit-backdrop-filter:blur(2px) saturate(1.06);transition:background-color .2s ease-in-out,border-color .2s ease-in-out,box-shadow .2s ease-in-out,color .2s ease-in-out,transform .2s ease-in-out}
input{padding:0 18px;text-align:center}
input::placeholder{color:var(--muted);opacity:1}
input:hover,button:hover{border-color:var(--line-strong);background-color:var(--control-bg-hover);transform:translateY(-1px);box-shadow:inset 0 0 0 1px rgba(255,255,255,.16),0 18px 42px rgba(0,0,0,.18)}
input:focus{outline:0;border-color:var(--line-strong);background-color:var(--control-bg-active);box-shadow:inset 0 0 0 1px rgba(255,255,255,.24),0 0 0 3px rgba(255,255,255,.1),0 18px 42px rgba(0,0,0,.18)}
button{cursor:pointer;text-transform:none;font-weight:520}
button:active{background-color:var(--control-bg-active);transform:translateY(0)}
.error{margin:-4px 0 0;color:var(--danger);font-size:14px;line-height:1.45;text-shadow:0 1px 14px rgba(0,0,0,.36)}
@media (max-width:420px){main{width:min(100%,340px)}main::before,main::after{display:none}input,button{min-height:54px}}
</style>
</head>
<body>
<main>
${note}
<form method="post" autocomplete="off">
<label class="sr-only" for="accessKey">\u8BBF\u95EE\u5BC6\u7801</label>
<input id="accessKey" name="access_key" type="password" autocomplete="new-password" autocapitalize="off" autocorrect="off" spellcheck="false" placeholder="\u8BBF\u95EE\u5BC6\u7801" required>
<button type="submit">\u767B\u5F55</button>
</form>
</main>
</body>
</html>`;
}
__name(loginHtml, "loginHtml");
async function handleLogin(request, env, redirectTo = ROUTES.ADMIN_ROOT) {
  if (request.method === "GET") {
    return new Response(loginHtml(), {
      headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" }
    });
  }
  if (request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }
  const contentType = request.headers.get("Content-Type") || "";
  let submitted = "";
  if (contentType.includes("application/json")) {
    const body = await request.json();
    submitted = String(body?.password || body?.access_key || "");
  } else {
    const form = new URLSearchParams(await request.text());
    submitted = String(form.get("access_key") || form.get("password") || "");
  }
  if (!equalText(submitted, getAdminPassword(env))) {
    if (contentType.includes("application/json")) {
      return new Response(JSON.stringify({ success: false }), { status: 403, headers: JSON_HEADERS });
    }
    return new Response(loginHtml("\u5BC6\u7801\u9519\u8BEF"), {
      status: 403,
      headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" }
    });
  }
  if (contentType.includes("application/json")) {
    const response2 = new Response(JSON.stringify({ success: true }), { headers: JSON_HEADERS });
    response2.headers.set(
      "Set-Cookie",
      `auth=${await makeSessionToken(env)}; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Strict`
    );
    return response2;
  }
  const response = new Response(null, {
    status: 302,
    headers: { Location: redirectTo, "Cache-Control": "no-store" }
  });
  response.headers.set(
    "Set-Cookie",
    `auth=${await makeSessionToken(env)}; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Strict`
  );
  return response;
}
__name(handleLogin, "handleLogin");
var PRIMARY_PROTOCOL = "vless";
function uriHost(endpoint) {
  return endpoint.isIPv6 || String(endpoint.hostname).includes(":") ? `[${endpoint.hostname}]` : endpoint.hostname;
}
__name(uriHost, "uriHost");
function utf8ToBase64(value) {
  const bytes = new TextEncoder().encode(String(value));
  let binary = "";
  const chunkSize = 8192;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}
__name(utf8ToBase64, "utf8ToBase64");
function makeProfileTitleHeaderValue(value) {
  const title = String(value || DEFAULT_SUB_NAME).trim() || DEFAULT_SUB_NAME;
  return /^[\x20-\x7E]+$/.test(title) ? title : `base64:${utf8ToBase64(title)}`;
}
__name(makeProfileTitleHeaderValue, "makeProfileTitleHeaderValue");
function makePrimaryUri(config, entry, name) {
  const host = config.HOST;
  const params = new URLSearchParams({
    security: "tls",
    type: "ws",
    host,
    fp: config.Fingerprint || "chrome",
    sni: host,
    alpn: "http/1.1",
    path: makeWsPath(config),
    encryption: "none"
  });
  return `${PRIMARY_PROTOCOL}://${config.UUID}@${uriHost(entry)}:${entry.port}?${params.toString()}#${encodeURIComponent(name)}`;
}
__name(makePrimaryUri, "makePrimaryUri");
function withRenderedLink(config) {
  const sub = getSubscriptionConfig(config);
  const entry = { hostname: config.HOST, port: 443, isIPv6: false };
  return {
    ...config,
    LINK: makePrimaryUri(config, entry, sub.SUBNAME || DEFAULT_SUB_NAME)
  };
}
__name(withRenderedLink, "withRenderedLink");
function buildNodeRecords(config, addText) {
  const sub = getSubscriptionConfig(config);
  const entries = parseEntryEndpoints(addText);
  const sourceEntries = entries.length ? entries : [{ hostname: config.HOST, port: 443, isIPv6: false, label: "" }];
  return sourceEntries.map((entry, index) => {
    const name = entry.label || `${sub.SUBNAME || DEFAULT_SUB_NAME}-${index + 1}`;
    return {
      name,
      entry,
      wsPath: makeWsPath(config),
      uri: makePrimaryUri(config, entry, name)
    };
  });
}
__name(buildNodeRecords, "buildNodeRecords");
function renderMixedSubscription(records) {
  return `${records.map((record) => record.uri).join("\n")}
`;
}
__name(renderMixedSubscription, "renderMixedSubscription");
function renderBase64Subscription(records) {
  return utf8ToBase64(renderMixedSubscription(records));
}
__name(renderBase64Subscription, "renderBase64Subscription");
function subscriptionResponseHeaders(config, url, env, contentType = TEXT_HEADERS["Content-Type"], request = null) {
  const sub = getSubscriptionConfig(config);
  const subName = String(sub.SUBNAME || DEFAULT_SUB_NAME).trim() || DEFAULT_SUB_NAME;
  const updateHours = Number(sub.SUBUpdateTime || DEFAULTS.ROTATE_HOURS) || DEFAULTS.ROTATE_HOURS;
  const headers = {
    ...TEXT_HEADERS,
    "Content-Type": contentType,
    "Cache-Control": "no-store",
    "Profile-Title": makeProfileTitleHeaderValue(subName),
    "Profile-Update-Interval": String(updateHours),
    "Profile-web-page-url": `${url.origin}${getAdminBasePath(env)}`
  };
  const ua = String(request?.headers?.get("User-Agent") || "").toLowerCase();
  if (!ua.includes("mozilla")) {
    headers["Content-Disposition"] = `attachment; filename*=utf-8''${encodeURIComponent(subName)}`;
  }
  return headers;
}
__name(subscriptionResponseHeaders, "subscriptionResponseHeaders");
function wantsBase64Subscription(request, url) {
  if (url.searchParams.has("b64") || url.searchParams.has("base64")) {
    return true;
  }
  if (url.searchParams.has("clash") || url.searchParams.has("sb") || url.searchParams.has("singbox")) {
    return false;
  }
  const ua = String(request.headers.get("User-Agent") || "").toLowerCase();
  return Boolean(ua && !ua.includes("mozilla"));
}
__name(wantsBase64Subscription, "wantsBase64Subscription");
function subscriptionOutputKind(request, url) {
  if (url.searchParams.has("clash")) {
    return "clash";
  }
  if (url.searchParams.has("sb") || url.searchParams.has("singbox")) {
    return "singbox";
  }
  return wantsBase64Subscription(request, url) ? "b64" : "mixed";
}
__name(subscriptionOutputKind, "subscriptionOutputKind");
function subscriptionCacheRequest(request, url, outputKind) {
  const cacheUrl = new URL(url.href);
  cacheUrl.searchParams.sort();
  cacheUrl.searchParams.set("__ip168_output", outputKind);
  return new Request(cacheUrl.href, { method: "GET" });
}
__name(subscriptionCacheRequest, "subscriptionCacheRequest");
function responseWithHeaders(response, headersPatch = {}) {
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries(headersPatch)) {
    headers.set(key, value);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}
__name(responseWithHeaders, "responseWithHeaders");
async function matchSubscriptionCache(request, url, outputKind) {
  if (!outputKind || !globalThis.caches?.default) {
    return null;
  }
  const cached = await globalThis.caches.default.match(subscriptionCacheRequest(request, url, outputKind));
  return cached ? responseWithHeaders(cached, { "X-IP168-Cache": "HIT", "Cache-Control": "no-store" }) : null;
}
__name(matchSubscriptionCache, "matchSubscriptionCache");
async function cacheSubscriptionResponse(request, url, outputKind, response, ctx) {
  if (!outputKind || !globalThis.caches?.default || response.status !== 200) {
    return response;
  }
  const headersPatch = {
    "Cache-Control": `public, max-age=${SUB_RESPONSE_CACHE_TTL_SECONDS}, s-maxage=${SUB_RESPONSE_CACHE_TTL_SECONDS}`,
    "X-IP168-Cache": "MISS"
  };
  const cacheResponse = responseWithHeaders(response.clone(), headersPatch);
  const outgoing = responseWithHeaders(response, { "X-IP168-Cache": "MISS" });
  const putPromise = globalThis.caches.default.put(subscriptionCacheRequest(request, url, outputKind), cacheResponse).catch((error) => {
    console.warn("[subscription-cache] put failed", error);
  });
  await putPromise;
  return outgoing;
}
__name(cacheSubscriptionResponse, "cacheSubscriptionResponse");
function getSubscriptionConverterBaseUrl(env) {
  return normalizeOptionalUrl(envText(env, "SUB_CONVERTER_URL") || DEFAULT_SUB_CONVERTER_URL);
}
__name(getSubscriptionConverterBaseUrl, "getSubscriptionConverterBaseUrl");
function buildConvertedSubscriptionUrl(url, env, target, token) {
  const converterBase = getSubscriptionConverterBaseUrl(env);
  if (!converterBase) {
    throw new Error("SUB_CONVERTER_URL is not configured");
  }
  const sourceUrl = new URL(ROUTES.SUBSCRIPTION, url.origin);
  sourceUrl.searchParams.set("token", token);
  sourceUrl.searchParams.set("b64", "");
  sourceUrl.searchParams.set("v", SUB_URL_VERSION);
  const outputPath = target === "singbox" ? "/singbox" : "/clash";
  const convertedUrl = new URL(outputPath, `${converterBase}/`);
  convertedUrl.searchParams.set("config", sourceUrl.href);
  convertedUrl.searchParams.set("selectedRules", url.searchParams.get("selectedRules") || "balanced");
  convertedUrl.searchParams.set("group_by_country", url.searchParams.get("group_by_country") || "true");
  for (const key of ["customRules", "include_auto_select", "enable_clash_ui", "external_controller", "external_ui_download_url", "singbox_version", "sb_version", "sb_ver", "ua", "configId"]) {
    const value = url.searchParams.get(key);
    if (value !== null) {
      convertedUrl.searchParams.set(key, value);
    }
  }
  return convertedUrl.href;
}
__name(buildConvertedSubscriptionUrl, "buildConvertedSubscriptionUrl");
async function fetchConvertedSubscriptionResponse(config, url, env, target, token, request) {
  let convertedUrl;
  try {
    convertedUrl = buildConvertedSubscriptionUrl(url, env, target, token);
  } catch (error) {
    return new Response(error.message || "subscription converter is not configured", {
      status: 501,
      headers: subscriptionResponseHeaders(config, url, env, TEXT_HEADERS["Content-Type"], request)
    });
  }
  const headers = {};
  const ua = String(request.headers.get("User-Agent") || "").trim();
  if (ua) {
    headers["User-Agent"] = ua;
  }
  const upstream = await fetch(convertedUrl, { method: "GET", headers });
  const body = await upstream.arrayBuffer();
  const responseHeaders = subscriptionResponseHeaders(
    config,
    url,
    env,
    upstream.headers.get("Content-Type") || (target === "singbox" ? JSON_HEADERS["Content-Type"] : "application/x-yaml; charset=utf-8"),
    request
  );
  const userinfo = upstream.headers.get("subscription-userinfo");
  if (userinfo) {
    responseHeaders["subscription-userinfo"] = userinfo;
  }
  if (!upstream.ok) {
    responseHeaders["Content-Type"] = TEXT_HEADERS["Content-Type"];
  }
  return new Response(body, {
    status: upstream.ok ? 200 : 502,
    headers: responseHeaders
  });
}
__name(fetchConvertedSubscriptionResponse, "fetchConvertedSubscriptionResponse");
function escapeHtml(value) {
  return String(value || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
__name(escapeHtml, "escapeHtml");
function safeScriptJson(value) {
  return JSON.stringify(value).replace(/</g, "\\u003c").replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
}
__name(safeScriptJson, "safeScriptJson");
function buildAdminBootstrap(requestUrl, adminBasePath, env) {
  const url = new URL(requestUrl);
  const base = normalizePathAlias(adminBasePath) || ROUTES.ADMIN_ROOT;
  return {
    version: 1,
    workerOrigin: url.origin,
    adminBase: base,
    subPath: ROUTES.SUBSCRIPTION,
    endpoints: {
      state: `${base}/pg/du`,
      save: `${base}/pg/xie`,
      entries: `${base}/rk/du`,
      proxyTest: `${base}/fd/jk/ce`,
      entryCandidates: `${base}/fd/jk/rk`,
      proxyAuto: `${base}/fd/zd/du`,
      proxyRun: `${base}/fd/zd/ce`,
      logout: `${base}/ht/tu`
    },
    converterUrl: getSubscriptionConverterBaseUrl(env),
    catalog: {
      summaryUrl: `${base}/fd/jk/summary`,
      queryUrl: getProxyIpCatalogUrl(env, "query"),
      ipv4Url: `${base}/fd/jk/ipv4`,
      ipv6Url: `${base}/fd/jk/ipv6`
    }
  };
}
__name(buildAdminBootstrap, "buildAdminBootstrap");
async function loadAdminPageHtml(env) {
  const cache = globalThis.caches?.default;
  const cacheKey = new Request("https://worker.local/admin-page-kv/" + ADMIN_PAGE_KV_CACHE_VERSION + "/" + ADMIN_PAGE_KV_KEY, { method: "GET" });
  if (cache) {
    try {
      const cached = await cache.match(cacheKey);
      if (cached) {
        return { ok: true, status: cached.status, html: await cached.text() };
      }
    } catch (error) {
      console.warn("[admin] cache read failed", error);
    }
  }
  try {
    const kvHtml = await readCachedKvText(env, ADMIN_PAGE_KV_KEY, ADMIN_PAGE_KV_CACHE_TTL_MS, { allowFallback: false });
    if (/<html[\s>]|<!doctype/i.test(kvHtml)) {
      if (cache) {
        try {
          await cache.put(cacheKey, new Response(kvHtml, {
            headers: {
              "Content-Type": "text/html; charset=utf-8",
              "Cache-Control": `public, max-age=${ADMIN_PAGE_CACHE_TTL_SECONDS}`
            }
          }));
        } catch (error) {
          console.warn("[admin] cache write failed", error);
        }
      }
      return { ok: true, status: 200, html: kvHtml };
    }
  } catch (error) {
    console.warn("[admin] KV page read failed", error);
  }
  return { ok: false, status: 404, html: "" };
}
__name(loadAdminPageHtml, "loadAdminPageHtml");
async function renderStaticAdminPage(request, env, adminBasePath) {
  const upstream = await loadAdminPageHtml(env);
  if (!upstream.ok) {
    return htmlResponse(
      `<!doctype html><html><meta charset="utf-8"><title>IP168 Admin</title><body><h1>IP168 Admin</h1><p>Admin page is not installed in KV.</p></body></html>`,
      { status: 404 }
    );
  }
  const bootstrap = `<script>window.IP168_BOOTSTRAP=${safeScriptJson(buildAdminBootstrap(request.url, adminBasePath, env))};<\/script>`;
  let html = upstream.html;
  html = html.replace(/url\.searchParams\.set\("v",\s*"2026-06-13-v[2-5]"\);/g, `url.searchParams.set("v", "${SUB_URL_VERSION}");`);
  if (!html.includes(`url.searchParams.set("v", "${SUB_URL_VERSION}")`) && html.includes('url.searchParams.set("token", token);')) {
    html = html.replace('url.searchParams.set("token", token);', `url.searchParams.set("token", token);\n      url.searchParams.set("v", "${SUB_URL_VERSION}");`);
  }
  if (html.includes('<script id="ip168-bootstrap-anchor"></script>')) {
    html = html.replace('<script id="ip168-bootstrap-anchor"></script>', bootstrap);
  } else if (/<\/head>/i.test(html)) {
    html = html.replace(/<\/head>/i, `${bootstrap}</head>`);
  } else {
    html = `${bootstrap}${html}`;
  }
  return htmlResponse(html);
}
__name(renderStaticAdminPage, "renderStaticAdminPage");
async function renderQrCodeVendorAsset(env) {
  const js = await readCachedKvText(env, VENDOR_QRCODE_KV_KEY, ADMIN_PAGE_KV_CACHE_TTL_MS, { allowFallback: false });
  if (!js) {
    return new Response("Not Found", { status: 404 });
  }
  return new Response(js, {
    headers: {
      "Content-Type": "application/javascript; charset=utf-8",
      "Cache-Control": "public, max-age=86400"
    }
  });
}
__name(renderQrCodeVendorAsset, "renderQrCodeVendorAsset");
var decoder = new TextDecoder("utf-8", { fatal: true });
function ensureAvailable(bytes, offset, length) {
  if (offset + length > bytes.byteLength) {
    throw new Error("protocol first packet is truncated");
  }
}
__name(ensureAvailable, "ensureAvailable");
function bytesToUuid(bytes) {
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
__name(bytesToUuid, "bytesToUuid");
function parseIPv6(bytes) {
  const groups = [];
  for (let offset = 0; offset < 16; offset += 2) {
    groups.push((bytes[offset] << 8 | bytes[offset + 1]).toString(16));
  }
  return groups.join(":");
}
__name(parseIPv6, "parseIPv6");
function parseTcpFirstPacket(input, expectedUuid) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (bytes.byteLength > DEFAULTS.MAX_FIRST_PACKET_BYTES) {
    throw new Error("protocol first packet exceeds size limit");
  }
  ensureAvailable(bytes, 0, 19);
  const version = bytes[0];
  const uuid = bytesToUuid(bytes.subarray(1, 17));
  if (uuid.toLowerCase() !== String(expectedUuid || "").toLowerCase()) {
    throw new Error("protocol UUID mismatch");
  }
  const addonLength = bytes[17];
  let offset = 18 + addonLength;
  ensureAvailable(bytes, offset, 4);
  const command = bytes[offset];
  offset += 1;
  if (command !== 1) {
    throw new Error("only TCP command is supported");
  }
  const port = bytes[offset] << 8 | bytes[offset + 1];
  offset += 2;
  if (port < 1) {
    throw new Error("destination port is invalid");
  }
  const addressType = bytes[offset];
  offset += 1;
  let hostname = "";
  let isIPv6 = false;
  if (addressType === 1) {
    ensureAvailable(bytes, offset, 4);
    hostname = Array.from(bytes.subarray(offset, offset + 4)).join(".");
    offset += 4;
  } else if (addressType === 2) {
    ensureAvailable(bytes, offset, 1);
    const length = bytes[offset];
    offset += 1;
    ensureAvailable(bytes, offset, length);
    hostname = decoder.decode(bytes.subarray(offset, offset + length));
    offset += length;
  } else if (addressType === 3) {
    ensureAvailable(bytes, offset, 16);
    hostname = parseIPv6(bytes.subarray(offset, offset + 16));
    offset += 16;
    isIPv6 = true;
  } else {
    throw new Error("address type is unsupported");
  }
  if (!hostname) {
    throw new Error("destination hostname is empty");
  }
  return {
    version,
    uuid,
    target: { hostname, port, isIPv6 },
    initialPayload: bytes.subarray(offset),
    responseHeader: new Uint8Array([version, 0])
  };
}
__name(parseTcpFirstPacket, "parseTcpFirstPacket");
function withTimeout(promise, timeoutMs, message) {
  let timeoutId;
  const timeout = new Promise((_, reject) => {
    timeoutId = setTimeout(() => reject(new Error(message)), timeoutMs);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timeoutId));
}
__name(withTimeout, "withTimeout");
function safeReleaseLock(lock, label) {
  try {
    lock.releaseLock();
  } catch (error) {
    console.warn(`[${label}] release failed`, error);
  }
}
__name(safeReleaseLock, "safeReleaseLock");
function concatBytes2(left, right) {
  const output = new Uint8Array(left.byteLength + right.byteLength);
  output.set(left, 0);
  output.set(right, left.byteLength);
  return output;
}
__name(concatBytes2, "concatBytes2");
function looksLikeTlsClientHello(bytes) {
  return bytes?.byteLength >= 5 && bytes[0] === 22 && bytes[1] === 3 && bytes[2] >= 1 && bytes[2] <= 4;
}
__name(looksLikeTlsClientHello, "looksLikeTlsClientHello");
function looksLikeFatalTlsAlert(bytes) {
  return bytes?.byteLength >= 7 && bytes[0] === 21 && bytes[1] === 3 && bytes[2] >= 1 && bytes[2] <= 4 && bytes[5] === 2;
}
__name(looksLikeFatalTlsAlert, "looksLikeFatalTlsAlert");
function classifyFirstPayloadForProxy(bytes) {
  if (!bytes?.byteLength) {
    return "empty";
  }
  if (bytes[0] !== 22) {
    return "non-tls";
  }
  if (bytes.byteLength < 5) {
    return "unknown";
  }
  return looksLikeTlsClientHello(bytes) ? "tls" : "non-tls";
}
__name(classifyFirstPayloadForProxy, "classifyFirstPayloadForProxy");
async function openTcpSocket(endpoint, workerHostname) {
  assertAllowedDialTarget(endpoint, workerHostname);
  const socket = connect(
    { hostname: endpoint.hostname, port: endpoint.port },
    { allowHalfOpen: true }
  );
  try {
    await withTimeout(
      socket.opened,
      DEFAULTS.CONNECT_TIMEOUT_MS,
      `TCP connect timeout: ${formatEndpoint(endpoint)}`
    );
    return socket;
  } catch (error) {
    console.error(`[TCP] connect failed: ${formatEndpoint(endpoint)}`, error);
    try {
      socket.close();
    } catch (closeError) {
      console.warn("[TCP] close after connect failure failed", closeError);
    }
    throw error;
  }
}
__name(openTcpSocket, "openTcpSocket");
async function closeTcpSocket(socket) {
  if (!socket) {
    return;
  }
  try {
    await socket.close();
  } catch (error) {
    console.warn("[TCP] socket close failed", error);
  }
}
__name(closeTcpSocket, "closeTcpSocket");
function clampNumber(value, fallback, min, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, Math.round(number)));
}
__name(clampNumber, "clampNumber");
function randomProxyProbeTimeoutMs(maxMs = DEFAULT_PROXY_AUTO_SETTINGS.timeoutMs) {
  const max = clampNumber(maxMs, DEFAULT_PROXY_AUTO_SETTINGS.timeoutMs, 1e3, 1500);
  return Math.floor(1e3 + Math.random() * (max - 1e3 + 1));
}
__name(randomProxyProbeTimeoutMs, "randomProxyProbeTimeoutMs");
function parseProbeTargets(rawTargets, maxTargets = 50) {
  const source = Array.isArray(rawTargets) ? rawTargets : [rawTargets];
  const values = source.flatMap((item) => String(item || "").split(/[\r\n\t,;]+/)).map((item) => item.trim()).filter(Boolean);
  const endpoints = [];
  const invalid = [];
  const seen = new Set();
  for (const value of values) {
    if (endpoints.length >= maxTargets) {
      break;
    }
    try {
      const endpoint = parseEndpoint(value);
      const key = endpointKey(endpoint);
      if (!seen.has(key)) {
        seen.add(key);
        endpoints.push(endpoint);
      }
    } catch (error) {
      invalid.push({
        proxy: value,
        ok: false,
        connectMs: null,
        error: error.message || "invalid endpoint"
      });
    }
  }
  return { endpoints, invalid };
}
__name(parseProbeTargets, "parseProbeTargets");
function parseTraceResponse(text) {
  const headerEnd = text.indexOf("\r\n\r\n");
  const headers = headerEnd === -1 ? "" : text.slice(0, headerEnd);
  const body = headerEnd === -1 ? text : text.slice(headerEnd + 4);
  const statusLine = headers.split("\r\n")[0] || "";
  const statusMatch = statusLine.match(/HTTP\/\d(?:\.\d)?\s+(\d+)/i);
  const status = statusMatch ? Number(statusMatch[1]) : null;
  if (status !== null && (status < 200 || status >= 300)) {
    throw new Error(`trace HTTP ${status}`);
  }
  const field = (name) => {
    const match = body.match(new RegExp(`(?:^|\\n)${name}=([^\\r\\n]*)`));
    return match ? match[1].trim() : "";
  };
  const exitIp = field("ip");
  const loc = field("loc");
  if (!exitIp || !loc) {
    throw new Error("trace response missing ip or loc");
  }
  return {
    httpStatus: status,
    exitIp,
    loc,
    colo: field("colo"),
    warp: field("warp"),
    tls: field("tls")
  };
}
__name(parseTraceResponse, "parseTraceResponse");
function parseHttpStatus(text) {
  const firstLine = String(text || "").split("\r\n", 1)[0] || "";
  const match = firstLine.match(/HTTP\/\d(?:\.\d)?\s+(\d+)/i);
  return match ? Number(match[1]) : null;
}
__name(parseHttpStatus, "parseHttpStatus");
async function traceProxyEndpoint(socket, timeoutMs) {
  const traceStarted = Date.now();
  const tls = new UserlandTlsClient(socket, {
    serverName: PROXYIP_TRACE_HOST,
    insecure: true,
    timeout: timeoutMs,
    alpn: null,
    allowChacha: true
  });
  await tls.handshake();
  const requestBytes = new TextEncoder().encode(
    `GET ${PROXYIP_TRACE_PATH}?_=${Date.now()} HTTP/1.1\r
Host: ${PROXYIP_TRACE_HOST}\r
User-Agent: ip168-proxyip-probe/2\r
Accept: text/plain\r
Connection: close\r
\r
`
  );
  await tls.write(requestBytes);
  let responseBuffer = new Uint8Array(0);
  while (responseBuffer.byteLength < PROXYIP_TRACE_MAX_BYTES) {
    const chunk = await tls.read();
    if (!chunk || !chunk.byteLength) {
      break;
    }
    responseBuffer = concatBytes2(responseBuffer, chunk);
    const text = new TextDecoder().decode(responseBuffer);
    if (text.includes("\r\n0\r\n\r\n") || text.includes("\nwarp=")) {
      const parsed = parseTraceResponse(text);
      return {
        traceMs: Date.now() - traceStarted,
        ...parsed
      };
    }
  }
  if (!responseBuffer.byteLength) {
    throw new Error("empty trace response");
  }
  return {
    traceMs: Date.now() - traceStarted,
    ...parseTraceResponse(new TextDecoder().decode(responseBuffer))
  };
}
__name(traceProxyEndpoint, "traceProxyEndpoint");
async function googleProxyEndpointCheck(endpoint, timeoutMs) {
  const started = Date.now();
  let socket = null;
  try {
    socket = connect(
      { hostname: endpoint.hostname, port: endpoint.port },
      { allowHalfOpen: true }
    );
    await withTimeout(
      socket.opened,
      timeoutMs,
      `TCP connect timeout: ${formatEndpoint(endpoint)}`
    );
    const tls = new UserlandTlsClient(socket, {
      serverName: "www.google.com",
      insecure: true,
      timeout: timeoutMs,
      alpn: ["http/1.1"],
      allowChacha: true
    });
    await tls.handshake();
    const requestBytes = new TextEncoder().encode(
      `GET /generate_204 HTTP/1.1\r
Host: www.google.com\r
User-Agent: Mozilla/5.0 ip168-proxyip-probe/2\r
Accept: */*\r
Connection: close\r
\r
`
    );
    await tls.write(requestBytes);
    let responseBuffer = new Uint8Array(0);
    while (responseBuffer.byteLength < PROXYIP_TRACE_MAX_BYTES) {
      const chunk = await tls.read();
      if (!chunk || !chunk.byteLength) {
        break;
      }
      responseBuffer = concatBytes2(responseBuffer, chunk);
      const status = parseHttpStatus(new TextDecoder().decode(responseBuffer));
      if (status !== null) {
        return {
          googleMs: Date.now() - started,
          googleOk: status >= 200 && status < 500,
          googleStatus: status,
          googleError: null
        };
      }
    }
    const status = parseHttpStatus(new TextDecoder().decode(responseBuffer));
    if (status !== null) {
      return {
        googleMs: Date.now() - started,
        googleOk: status >= 200 && status < 500,
        googleStatus: status,
        googleError: null
      };
    }
    throw new Error(responseBuffer.byteLength ? "google response missing HTTP status" : "empty google response");
  } catch (error) {
    return {
      googleMs: null,
      googleOk: false,
      googleStatus: null,
      googleError: String(error?.message || error || "google check failed").slice(0, 200)
    };
  } finally {
    await closeTcpSocket(socket);
  }
}
__name(googleProxyEndpointCheck, "googleProxyEndpointCheck");
async function probeProxyEndpoint(endpoint, workerHostname, timeoutMs) {
  const started = Date.now();
  let socket = null;
  try {
    assertAllowedDialTarget(endpoint, workerHostname);
    socket = connect(
      { hostname: endpoint.hostname, port: endpoint.port },
      { allowHalfOpen: true }
    );
    await withTimeout(
      socket.opened,
      timeoutMs,
      `TCP connect timeout: ${formatEndpoint(endpoint)}`
    );
    const connectMs = Date.now() - started;
    let trace = {};
    let traceError = null;
    try {
      trace = await traceProxyEndpoint(socket, timeoutMs);
    } catch (error) {
      traceError = String(error?.message || error || "trace check failed").slice(0, 200);
    }
    const traceOk = Boolean(trace.exitIp && trace.loc);
    return {
      proxy: formatEndpoint(endpoint),
      ok: traceOk,
      connectMs,
      ...trace,
      googleMs: null,
      googleOk: null,
      googleStatus: null,
      googleError: null,
      traceError,
      error: traceOk ? null : traceError || "proxy check failed"
    };
  } catch (error) {
    return {
      proxy: formatEndpoint(endpoint),
      ok: false,
      connectMs: null,
      googleMs: null,
      googleOk: false,
      googleStatus: null,
      googleError: null,
      error: String(error?.message || error || "TCP connect failed").slice(0, 200)
    };
  } finally {
    await closeTcpSocket(socket);
  }
}
__name(probeProxyEndpoint, "probeProxyEndpoint");
async function runLimited(items, concurrency, worker) {
  const output = new Array(items.length);
  let cursor = 0;
  const size = Math.min(Math.max(1, concurrency), items.length || 1);
  await Promise.all(Array.from({ length: size }, async () => {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      output[index] = await worker(items[index], index);
    }
  }));
  return output;
}
__name(runLimited, "runLimited");
function validateWebSocketRequest(request) {
  if (request.method !== "GET") {
    throw new Error("WebSocket request must use GET");
  }
  if ((request.headers.get("Upgrade") || "").toLowerCase() !== "websocket") {
    throw new Error("Upgrade header must be websocket");
  }
  const connection = request.headers.get("Connection") || "";
  if (!connection.split(",").some((value) => value.trim().toLowerCase() === "upgrade")) {
    throw new Error("Connection header must include upgrade");
  }
  if ((request.headers.get("Sec-WebSocket-Version") || "") !== "13") {
    throw new Error("Sec-WebSocket-Version must be 13");
  }
  const key = request.headers.get("Sec-WebSocket-Key") || "";
  if (!/^[A-Za-z0-9+/]{22}==$/.test(key)) {
    throw new Error("Sec-WebSocket-Key is invalid");
  }
}
__name(validateWebSocketRequest, "validateWebSocketRequest");
async function messageBytes(data) {
  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data);
  }
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  if (typeof Blob !== "undefined" && data instanceof Blob) {
    return new Uint8Array(await data.arrayBuffer());
  }
  throw new Error("WebSocket text frames are not supported");
}
__name(messageBytes, "messageBytes");
function safeCloseWebSocket(webSocket, code, reason) {
  try {
    webSocket.close(code, String(reason || "").slice(0, 120));
  } catch (error) {
    console.warn("[WS] close failed", error);
  }
}
__name(safeCloseWebSocket, "safeCloseWebSocket");
async function pipeTcpToWebSocket(socket, webSocket, responseHeader, shutdown, firstResponseChunk = null, failureContext = null) {
  const reader = socket.readable.getReader();
  let firstChunk = true;
  let sentAnyChunk = false;
  try {
    if (firstResponseChunk?.byteLength) {
      webSocket.send(concatBytes2(responseHeader, firstResponseChunk));
      firstChunk = false;
      sentAnyChunk = true;
    }
    while (true) {
      const { value, done } = await reader.read();
      if (done) {
        if (!sentAnyChunk && failureContext?.configured && failureContext.endpoint) {
          await markProxyEndpointFailed(failureContext.env, failureContext.config, failureContext.endpoint, new Error("TCP closed before upstream response")).catch((error) => {
            console.warn(`[proxy-health] failed to mark runtime failure: ${formatEndpoint(failureContext.endpoint)}`, error);
          });
        }
        break;
      }
      if (!value?.byteLength) {
        continue;
      }
      const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
      webSocket.send(firstChunk ? concatBytes2(responseHeader, bytes) : bytes);
      firstChunk = false;
      sentAnyChunk = true;
    }
    await shutdown(1e3, "TCP closed");
  } catch (error) {
    console.error("[TCP] downstream pipe failed", error);
    if (!sentAnyChunk && failureContext?.configured && failureContext.endpoint) {
      await markProxyEndpointFailed(failureContext.env, failureContext.config, failureContext.endpoint, error).catch((healthError) => {
        console.warn(`[proxy-health] failed to mark runtime failure: ${formatEndpoint(failureContext.endpoint)}`, healthError);
      });
    }
    await shutdown(1011, "TCP downstream failed");
  } finally {
    try {
      reader.releaseLock();
    } catch (error) {
      console.warn("[TCP] reader release failed", error);
    }
  }
}
__name(pipeTcpToWebSocket, "pipeTcpToWebSocket");
function addProxyCandidate(candidates, seen, endpoint, configured) {
  if (!endpoint) {
    return;
  }
  const key = endpointKey(endpoint);
  if (seen.has(key)) {
    return;
  }
  seen.add(key);
  candidates.push({ endpoint, configured });
}
__name(addProxyCandidate, "addProxyCandidate");
function buildProxyDialCandidates(configuredProxies, disabledKeys) {
  const candidates = [];
  const seen = new Set();
  const disabled = disabledKeys instanceof Set ? disabledKeys : new Set(disabledKeys || []);
  for (const proxy of configuredProxies) {
    if (!disabled.has(endpointKey(proxy))) {
      addProxyCandidate(candidates, seen, proxy, true);
    }
  }
  if (!candidates.length) {
    for (const proxy of configuredProxies) {
      addProxyCandidate(candidates, seen, proxy, true);
    }
  }
  return candidates;
}
__name(buildProxyDialCandidates, "buildProxyDialCandidates");
async function openFirstProxyTcpSocket(candidates, env, config, initialPayload = new Uint8Array(0)) {
  let lastError = null;
  const initialPayloadIsTls = looksLikeTlsClientHello(initialPayload);
  for (const candidate of candidates) {
    let socket = null;
    try {
      socket = await openTcpSocket(candidate.endpoint, config.HOST);
      let firstResponseChunk = null;
      if (initialPayload.byteLength) {
        const writer = socket.writable.getWriter();
        try {
          await withTimeout(writer.write(initialPayload), 2e3, `TCP initial write timeout: ${formatEndpoint(candidate.endpoint)}`);
        } finally {
          writer.releaseLock();
        }
        const reader = socket.readable.getReader();
        try {
          const firstRead = await withTimeout(reader.read(), 2e3, `TCP first response timeout: ${formatEndpoint(candidate.endpoint)}`);
          if (firstRead.done || !firstRead.value?.byteLength) {
            throw new Error("TCP closed before upstream response");
          }
          firstResponseChunk = firstRead.value instanceof Uint8Array ? firstRead.value : new Uint8Array(firstRead.value);
          if (initialPayloadIsTls && looksLikeFatalTlsAlert(firstResponseChunk)) {
            throw new Error(`PROXYIP returned fatal TLS alert: ${formatEndpoint(candidate.endpoint)}`);
          }
        } finally {
          reader.releaseLock();
        }
      }
      if (candidate.configured) {
        await markProxyEndpointHealthy(env, config, candidate.endpoint).catch((error) => {
          console.warn(`[proxy-health] failed to mark healthy: ${formatEndpoint(candidate.endpoint)}`, error);
        });
      }
      return { socket, endpoint: candidate.endpoint, configured: candidate.configured, firstResponseChunk, initialPayloadWritten: Boolean(initialPayload.byteLength) };
    } catch (error) {
      lastError = error;
      console.error(`[TCP] proxy candidate failed: ${formatEndpoint(candidate.endpoint)}`, error);
      await closeTcpSocket(socket);
      if (candidate.configured) {
        await markProxyEndpointFailed(env, config, candidate.endpoint, error).catch((healthError) => {
          console.warn(`[proxy-health] failed to mark failed: ${formatEndpoint(candidate.endpoint)}`, healthError);
        });
      }
    }
  }
  throw lastError || new Error("no proxy endpoint is available");
}
__name(openFirstProxyTcpSocket, "openFirstProxyTcpSocket");
async function handleWebSocket(request, env, config, url) {
  try {
    validateWebSocketRequest(request);
  } catch (error) {
    return new Response(error.message, { status: 400 });
  }
  const pair = new WebSocketPair();
  const [clientSocket, serverSocket] = Object.values(pair);
  serverSocket.binaryType = "arraybuffer";
  try {
    serverSocket.accept({ allowHalfOpen: true });
  } catch (error) {
    console.warn("[WS] accept options unsupported, using default accept", error);
    serverSocket.accept();
  }
  let tcpSocket = null;
  let tcpWriter = null;
  let initialized = false;
  let closed = false;
  let writeChain = Promise.resolve();
  let firstPacketBuffer = new Uint8Array(0);
  let pendingFirstPacket = null;
  let pendingFirstPayloadBuffer = new Uint8Array(0);
  let activeProxyEndpoint = null;
  let activeProxyConfigured = false;
  const shutdown = async (code, reason) => {
    if (closed) {
      return;
    }
    closed = true;
    if (tcpWriter) {
      try {
        tcpWriter.releaseLock();
      } catch (error) {
        console.warn("[TCP] writer release failed", error);
      }
    }
    await closeTcpSocket(tcpSocket);
    safeCloseWebSocket(serverSocket, code, reason);
  };
  const connectParsedTarget = async (parsed, firstPayload = new Uint8Array(0)) => {
    const payload = firstPayload instanceof Uint8Array ? firstPayload : new Uint8Array(firstPayload || 0);
    const runtimeProxy = await loadRuntimeProxyInfo(env, config);
    const configuredProxies = runtimeProxy.endpoints;
    const proxyMode = runtimeProxy.proxyMode;
    const proxyHealth = configuredProxies.length ? await loadProxyHealth(env, config, Date.now(), { useCacheOnly: true }) : { disabledKeys: new Set() };
    const proxyCandidates = buildProxyDialCandidates(configuredProxies, proxyHealth.disabledKeys);
    let firstResponseChunk = null;
    let initialPayloadWritten = false;
    const firstPayloadKind = classifyFirstPayloadForProxy(payload);
    const shouldBypassProxyForNonTls = firstPayloadKind === "non-tls";
    if (proxyCandidates.length && shouldBypassProxyForNonTls) {
      console.warn("[TCP] non-TLS first payload detected; bypassing PROXYIP");
      tcpSocket = await openTcpSocket(parsed.target, config.HOST);
    } else if (proxyCandidates.length) {
      try {
        const dial = await openFirstProxyTcpSocket(proxyCandidates, env, config, payload);
        tcpSocket = dial.socket;
        activeProxyEndpoint = dial.endpoint;
        activeProxyConfigured = Boolean(dial.configured);
        firstResponseChunk = dial.firstResponseChunk;
        initialPayloadWritten = Boolean(dial.initialPayloadWritten);
      } catch (proxyError) {
        let autoHealError = null;
        if (configuredProxies.length) {
          try {
            const retry = await retryProxyDialAfterAutoHeal(env, config, proxyError, payload);
            tcpSocket = retry.socket;
            config = retry.config;
            activeProxyEndpoint = retry.endpoint;
            activeProxyConfigured = Boolean(retry.configured);
            firstResponseChunk = retry.firstResponseChunk;
            initialPayloadWritten = Boolean(retry.initialPayloadWritten);
          } catch (error) {
            autoHealError = error;
            console.warn("[proxy-auto] auto-heal after all PROXYIP failed did not recover", error);
          }
        }
        if (!tcpSocket) {
          if (proxyMode !== "proxy-first-fallback-direct") {
            throw autoHealError || proxyError;
          }
          console.warn("[TCP] all proxy candidates failed, falling back to Worker direct outbound", proxyError);
          tcpSocket = await openTcpSocket(parsed.target, config.HOST);
        }
      }
    } else {
      tcpSocket = await openTcpSocket(parsed.target, config.HOST);
    }
    tcpWriter = tcpSocket.writable.getWriter();
    if (payload.byteLength && !initialPayloadWritten) {
      await tcpWriter.write(payload);
    }
    initialized = true;
    firstPacketBuffer = new Uint8Array(0);
    pipeTcpToWebSocket(tcpSocket, serverSocket, parsed.responseHeader, shutdown, firstResponseChunk, {
      env,
      config,
      endpoint: activeProxyEndpoint,
      configured: activeProxyConfigured
    }).catch((error) => {
      console.error("[TCP] unhandled downstream error", error);
    });
  };
  const handleMessage = async (event) => {
    const bytes = await messageBytes(event.data);
    if (pendingFirstPacket) {
      pendingFirstPayloadBuffer = concatBytes2(pendingFirstPayloadBuffer, bytes);
      if (pendingFirstPayloadBuffer.byteLength > DEFAULTS.MAX_FIRST_PACKET_BYTES) {
        throw new Error("protocol first payload exceeds size limit");
      }
      const firstPayloadKind = classifyFirstPayloadForProxy(pendingFirstPayloadBuffer);
      if (firstPayloadKind === "unknown") {
        return;
      }
      if (firstPayloadKind === "empty") {
        return;
      }
      const parsed = pendingFirstPacket;
      const payload = pendingFirstPayloadBuffer;
      pendingFirstPacket = null;
      pendingFirstPayloadBuffer = new Uint8Array(0);
      await connectParsedTarget(parsed, payload);
      return;
    }
    if (!initialized) {
      firstPacketBuffer = concatBytes2(firstPacketBuffer, bytes);
      if (firstPacketBuffer.byteLength > DEFAULTS.MAX_FIRST_PACKET_BYTES) {
        throw new Error("protocol first packet exceeds size limit");
      }
      let parsed;
      try {
        parsed = parseTcpFirstPacket(firstPacketBuffer, config.UUID);
      } catch (error) {
        if (error.message === "protocol first packet is truncated") {
          return;
        }
        throw error;
      }
      const runtimeProxy = await loadRuntimeProxyInfo(env, config);
      const configuredProxies = runtimeProxy.endpoints;
      const proxyHealth = configuredProxies.length ? await loadProxyHealth(env, config, Date.now(), { useCacheOnly: true }) : { disabledKeys: new Set() };
      const proxyCandidates = buildProxyDialCandidates(configuredProxies, proxyHealth.disabledKeys);
      const firstPayloadKind = classifyFirstPayloadForProxy(parsed.initialPayload);
      if (!parsed.initialPayload.byteLength && proxyCandidates.length) {
        pendingFirstPacket = parsed;
        pendingFirstPayloadBuffer = new Uint8Array(0);
        initialized = true;
        firstPacketBuffer = new Uint8Array(0);
        console.warn("[TCP] waiting for first payload before choosing PROXYIP route");
        return;
      }
      if (proxyCandidates.length && firstPayloadKind === "unknown") {
        pendingFirstPacket = parsed;
        pendingFirstPayloadBuffer = parsed.initialPayload;
        initialized = true;
        firstPacketBuffer = new Uint8Array(0);
        return;
      }
      await connectParsedTarget(parsed, parsed.initialPayload);
      return;
    }
    try {
      await tcpWriter.write(bytes);
    } catch (error) {
      if (activeProxyConfigured && activeProxyEndpoint) {
        await markProxyEndpointFailed(env, config, activeProxyEndpoint, error).catch((healthError) => {
          console.warn(`[proxy-health] failed to mark upstream write failure: ${formatEndpoint(activeProxyEndpoint)}`, healthError);
        });
      }
      throw error;
    }
  };
  serverSocket.addEventListener("message", (event) => {
    writeChain = writeChain.then(() => handleMessage(event)).catch(async (error) => {
      console.error("[WS] upstream handling failed", error);
      await shutdown(1011, "WS upstream failed");
    });
  });
  serverSocket.addEventListener("close", () => {
    shutdown(1e3, "WS closed").catch((error) => console.error("[WS] shutdown failed", error));
  });
  serverSocket.addEventListener("error", (event) => {
    console.error("[WS] socket error", event);
    shutdown(1011, "WS error").catch((error) => console.error("[WS] shutdown failed", error));
  });
  return new Response(null, { status: 101, webSocket: clientSocket });
}
__name(handleWebSocket, "handleWebSocket");
function jsonResponse(value, init = {}) {
  return new Response(JSON.stringify(value, null, 2), {
    ...init,
    headers: { ...JSON_HEADERS, ...init.headers || {} }
  });
}
__name(jsonResponse, "jsonResponse");
function htmlResponse(value, init = {}) {
  return new Response(value, {
    ...init,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      ...init.headers || {}
    }
  });
}
__name(htmlResponse, "htmlResponse");
function withAdminCors(response) {
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries(ADMIN_CORS_HEADERS)) {
    headers.set(key, value);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}
__name(withAdminCors, "withAdminCors");
function isWebSocketUpgrade(request) {
  return (request.headers.get("Upgrade") || "").toLowerCase() === "websocket";
}
__name(isWebSocketUpgrade, "isWebSocketUpgrade");
var ENTRY_CANDIDATE_LINE_NAMES = Object.freeze({
  CT: "电信",
  CU: "联通",
  CM: "移动",
  BGP: "多线"
});
var ENTRY_CANDIDATE_LINE_ORDER = Object.freeze(["CT", "CU", "CM", "BGP"]);
var UOUIN_ENTRY_CANDIDATE_NODES = Object.freeze([
  { nodeid: "ctcc", line: "CT" },
  { nodeid: "cucc", line: "CU" },
  { nodeid: "cmcc", line: "CM" },
  { nodeid: "bgp", line: "BGP" }
]);
function normalizeEntryCandidateLine(rawLine) {
  const value = String(rawLine || "").trim();
  const upper = value.toUpperCase();
  if (upper === "CT" || upper === "CTCC" || value === "电信") return "CT";
  if (upper === "CU" || upper === "CUCC" || value === "联通") return "CU";
  if (upper === "CM" || upper === "CMCC" || value === "移动") return "CM";
  if (upper === "BGP" || upper === "CN" || value === "多线" || value === "三网") return "BGP";
  return "";
}
__name(normalizeEntryCandidateLine, "normalizeEntryCandidateLine");
function entryCandidateLineName(line) {
  const normalized = normalizeEntryCandidateLine(line);
  return ENTRY_CANDIDATE_LINE_NAMES[normalized] || "";
}
__name(entryCandidateLineName, "entryCandidateLineName");
function entryCandidateLineRank(line) {
  const index = ENTRY_CANDIDATE_LINE_ORDER.indexOf(normalizeEntryCandidateLine(line));
  return index === -1 ? ENTRY_CANDIDATE_LINE_ORDER.length : index;
}
__name(entryCandidateLineRank, "entryCandidateLineRank");
function entryCandidateNumber(rawValue) {
  if (rawValue === null || rawValue === void 0 || rawValue === "") return null;
  const match = String(rawValue).match(/-?\d+(?:\.\d+)?/);
  if (!match) return null;
  const value = Number(match[0]);
  return Number.isFinite(value) ? value : null;
}
__name(entryCandidateNumber, "entryCandidateNumber");
function entryCandidateTime(rawValue) {
  if (rawValue === null || rawValue === void 0 || rawValue === "") return "";
  if (typeof rawValue === "number" || /^\d+$/.test(String(rawValue))) {
    const number = Number(rawValue);
    if (!Number.isFinite(number) || number <= 0) return "";
    const ms = number > 9999999999 ? number : number * 1e3;
    const date = new Date(ms);
    return Number.isNaN(date.getTime()) ? "" : date.toISOString();
  }
  return String(rawValue || "").trim();
}
__name(entryCandidateTime, "entryCandidateTime");
function normalizeEntryCandidate(rawValue, fallbackLine) {
  const raw = rawValue && typeof rawValue === "object" ? rawValue : {};
  const ip = String(raw.ip || raw.address || raw.host || "").trim();
  if (!ip || ip.includes(":")) return null;
  let octets;
  try {
    octets = parseIPv4(ip);
  } catch {
    return null;
  }
  if (!octets || !isKnownCloudflareIPv4(octets)) return null;
  const line = normalizeEntryCandidateLine(raw.line || raw.line_name || fallbackLine);
  if (!line) return null;
  const endpoint = { hostname: ip, port: 443, isIPv6: false };
  const latency = entryCandidateNumber(raw.latency ?? raw.rtt_avg ?? raw.ping);
  const speed = entryCandidateNumber(raw.speed);
  const proxy = formatEndpoint(endpoint);
  return {
    id: line + ":" + proxy.toLowerCase(),
    ip,
    port: "443",
    proxy,
    line,
    lineName: entryCandidateLineName(line),
    latency,
    latencyText: latency === null ? "" : String(raw.latency ?? raw.rtt_avg ?? raw.ping ?? latency),
    speed,
    speedText: speed === null ? "" : String(raw.speed),
    colo: String(raw.colo || raw.datacenter || "").trim(),
    time: entryCandidateTime(raw.time ?? raw.updated_at ?? raw.uptime)
  };
}
__name(normalizeEntryCandidate, "normalizeEntryCandidate");
async function readEntryCandidateJson(url, init = {}) {
  const response = await withTimeout(fetch(url, {
    ...init,
    headers: {
      Accept: "application/json",
      ...(init.headers || {})
    },
    cf: { cacheTtl: 0, cacheEverything: false }
  }), ENTRY_CANDIDATE_FETCH_TIMEOUT_MS, "entry candidate source timeout");
  const text = await response.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error("entry candidate source response is not JSON");
  }
  if (!response.ok) {
    throw new Error(data?.msg || data?.error || `entry candidate source HTTP ${response.status}`);
  }
  return data;
}
__name(readEntryCandidateJson, "readEntryCandidateJson");
async function fetchWetTestEntryCandidates() {
  const url = new URL(WETEST_CLOUDFLARE_IPV4_API_URL);
  url.searchParams.set("key", WETEST_CLOUDFLARE_API_KEY);
  url.searchParams.set("type", "v4");
  const data = await readEntryCandidateJson(url.href);
  if (data?.status !== true || Number(data?.code) !== 200) {
    throw new Error(data?.msg || "wetest entry candidates failed");
  }
  const nodes = [];
  const groups = data?.info && typeof data.info === "object" ? data.info : {};
  for (const [line, entries] of Object.entries(groups)) {
    for (const raw of Array.isArray(entries) ? entries : []) {
      const node = normalizeEntryCandidate(raw, line);
      if (node) nodes.push(node);
    }
  }
  return { nodes };
}
__name(fetchWetTestEntryCandidates, "fetchWetTestEntryCandidates");
async function fetchHostMonitEntryCandidates() {
  const data = await readEntryCandidateJson(HOSTMONIT_CLOUDFLARE_IPV4_API_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ key: HOSTMONIT_CLOUDFLARE_API_KEY })
  });
  if (Number(data?.code) !== 200) {
    throw new Error(data?.msg || "hostmonit entry candidates failed");
  }
  const nodes = [];
  for (const raw of Array.isArray(data?.info) ? data.info : []) {
    const node = normalizeEntryCandidate(raw, raw?.line);
    if (node) nodes.push(node);
  }
  return { nodes };
}
__name(fetchHostMonitEntryCandidates, "fetchHostMonitEntryCandidates");
function uouinEntryCandidateCredentials(env) {
  const username = envText(env, "UOUIN_CLOUDFLARE_USERNAME", "UOUIN_USERNAME");
  const key = envText(env, "UOUIN_CLOUDFLARE_KEY", "UOUIN_KEY");
  return { username, key };
}
__name(uouinEntryCandidateCredentials, "uouinEntryCandidateCredentials");
async function fetchUouinEntryCandidateGroup(credentials, group) {
  const url = new URL(UOUIN_CLOUDFLARE_API_URL);
  url.searchParams.set("username", credentials.username);
  url.searchParams.set("key", credentials.key);
  url.searchParams.set("url", "cloudflare.com");
  url.searchParams.set("nodeid", group.nodeid);
  const data = await readEntryCandidateJson(url.href);
  if (String(data?.code) !== "200" && Number(data?.code) !== 200) {
    throw new Error(data?.msg || "uouin entry candidates failed");
  }
  const source = data?.data?.[group.nodeid] || data?.data;
  if (Number(source?.code) !== 200) {
    throw new Error(data?.msg || "uouin entry candidate group failed");
  }
  return (Array.isArray(source?.info) ? source.info : []).map((raw) => ({
    ...raw,
    uptime: source?.uptime
  })).map((raw) => normalizeEntryCandidate(raw, group.line)).filter(Boolean);
}
__name(fetchUouinEntryCandidateGroup, "fetchUouinEntryCandidateGroup");
async function fetchUouinEntryCandidates(env) {
  const credentials = uouinEntryCandidateCredentials(env);
  if (!credentials.username || !credentials.key) {
    return { nodes: [], skipped: true, reason: "uouin credentials are not configured" };
  }
  const settled = await Promise.allSettled(
    UOUIN_ENTRY_CANDIDATE_NODES.map((group) => fetchUouinEntryCandidateGroup(credentials, group))
  );
  const nodes = settled.flatMap((result) => result.status === "fulfilled" ? result.value : []);
  const errors = settled.filter((result) => result.status === "rejected").map((result) => result.reason?.message || String(result.reason));
  if (!nodes.length && errors.length) {
    throw new Error(errors[0]);
  }
  return { nodes, errors };
}
__name(fetchUouinEntryCandidates, "fetchUouinEntryCandidates");
function mergeEntryCandidates(results) {
  const rows = [];
  const errors = [];
  let skipped = 0;
  for (const result of results) {
    if (result.status !== "fulfilled") {
      errors.push(result.reason?.message || String(result.reason));
      continue;
    }
    if (result.value?.skipped) {
      skipped += 1;
    }
    if (Array.isArray(result.value?.errors)) {
      errors.push(...result.value.errors);
    }
    rows.push(...(Array.isArray(result.value?.nodes) ? result.value.nodes : []));
  }
  const seen = new Set();
  const nodes = [];
  for (const row of rows) {
    if (!row?.id || seen.has(row.id)) continue;
    seen.add(row.id);
    nodes.push(row);
  }
  nodes.sort((left, right) => {
    const rankDiff = entryCandidateLineRank(left.line) - entryCandidateLineRank(right.line);
    if (rankDiff) return rankDiff;
    const latencyDiff = (left.latency ?? Number.POSITIVE_INFINITY) - (right.latency ?? Number.POSITIVE_INFINITY);
    if (latencyDiff) return latencyDiff;
    return (right.speed ?? 0) - (left.speed ?? 0);
  });
  return { nodes, errors, skipped };
}
__name(mergeEntryCandidates, "mergeEntryCandidates");
async function handleEntryCandidates(request, env) {
  if (request.method !== "GET") {
    return new Response("Method Not Allowed", { status: 405 });
  }
  const startedAt = Date.now();
  const merged = mergeEntryCandidates(await Promise.allSettled([
    fetchWetTestEntryCandidates(),
    fetchHostMonitEntryCandidates(),
    fetchUouinEntryCandidates(env)
  ]));
  const lineCounts = ENTRY_CANDIDATE_LINE_ORDER.map((line) => ({
    line,
    name: entryCandidateLineName(line),
    count: merged.nodes.filter((node) => node.line === line).length
  }));
  if (!merged.nodes.length) {
    return jsonResponse({
      success: false,
      error: "no entry candidates were fetched",
      count: 0,
      lineCounts,
      elapsedMs: Date.now() - startedAt
    }, { status: 502 });
  }
  return jsonResponse({
    success: true,
    ipVersion: "4",
    port: "443",
    count: merged.nodes.length,
    lineCounts,
    nodes: merged.nodes,
    partial: Boolean(merged.errors.length || merged.skipped),
    elapsedMs: Date.now() - startedAt
  });
}
__name(handleEntryCandidates, "handleEntryCandidates");
async function readLimitedText(request) {
  const declaredLength = Number(request.headers.get("Content-Length") || 0);
  if (declaredLength > DEFAULTS.MAX_ADMIN_BODY_BYTES) {
    throw new Error("request body is too large");
  }
  const text = await request.text();
  if (new TextEncoder().encode(text).byteLength > DEFAULTS.MAX_ADMIN_BODY_BYTES) {
    throw new Error("request body is too large");
  }
  return text;
}
__name(readLimitedText, "readLimitedText");
function equalSubscriptionToken(left, right) {
  const a = String(left || "");
  const b = String(right || "");
  if (a.length !== b.length) {
    return false;
  }
  let mismatch = 0;
  for (let index = 0; index < a.length; index += 1) {
    mismatch |= a.charCodeAt(index) ^ b.charCodeAt(index);
  }
  return mismatch === 0;
}
__name(equalSubscriptionToken, "equalSubscriptionToken");
function proxyIpCatalogSource(kind, env) {
  const normalized = String(kind || "summary").trim().toLowerCase().replace(/\.json$/, "");
  if (normalized === "summary") return getProxyIpCatalogUrl(env, "summary");
  if (normalized === "ipv4" || normalized === "v4" || normalized === "4") return getProxyIpCatalogUrl(env, "ipv4");
  if (normalized === "ipv6" || normalized === "v6" || normalized === "6") return getProxyIpCatalogUrl(env, "ipv6");
  if (normalized === "query") return getProxyIpCatalogUrl(env, "query");
  return "";
}
__name(proxyIpCatalogSource, "proxyIpCatalogSource");
async function handleProxyIpCatalog(request, env, url, catalogBasePath) {
  if (request.method !== "GET") {
    return new Response("Method Not Allowed", { status: 405 });
  }
  const suffix = url.pathname.slice(catalogBasePath.length).replace(/^\/+/, "");
  const sourceUrl = proxyIpCatalogSource(suffix || url.searchParams.get("file") || "summary", env);
  if (!sourceUrl) {
    return jsonResponse({ success: false, error: "PROXYIP catalog URL is not configured" }, { status: 501 });
  }
  const upstream = await fetch(sourceUrl, {
    headers: { Accept: "application/json" },
    cf: { cacheEverything: true, cacheTtl: 300 }
  });
  const text = await upstream.text();
  if (!upstream.ok) {
    return jsonResponse({ success: false, error: `catalog HTTP ${upstream.status}` }, { status: 502 });
  }
  return new Response(text, {
    headers: {
      ...JSON_HEADERS,
      "Cache-Control": "public, max-age=60"
    }
  });
}
__name(handleProxyIpCatalog, "handleProxyIpCatalog");
async function handleProxyIpProbe(request, env, url) {
  if (request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }
  let body;
  try {
    body = JSON.parse(await readLimitedText(request));
  } catch (error) {
    return jsonResponse({ success: false, error: "invalid JSON" }, { status: 400 });
  }
  const timeoutMs = clampNumber(body.timeoutMs, randomProxyProbeTimeoutMs(), 1e3, 1500);
  const concurrency = clampNumber(body.concurrency, 4, 1, 8);
  const { endpoints, invalid } = parseProbeTargets(body.targets, 50);
  if (!endpoints.length && !invalid.length) {
    return jsonResponse({ success: false, error: "targets is required" }, { status: 400 });
  }
  const checked = await runLimited(
    endpoints,
    concurrency,
    (endpoint) => probeProxyEndpoint(endpoint, url.hostname, timeoutMs)
  );
  const results = [...invalid, ...checked];
  return jsonResponse({
    success: true,
    timeoutMs,
    concurrency,
    count: results.length,
    ok: results.filter((result) => result.ok).length,
    results
  });
}
__name(handleProxyIpProbe, "handleProxyIpProbe");
async function handleProxyIpAuto(request, env, url) {
  if (request.method === "GET") {
    const [settings, state, config] = await Promise.all([
      loadProxyAutoSettings(env),
      loadProxyAutoState(env),
      loadConfig(env, url.hostname)
    ]);
    return jsonResponse({
      success: true,
      settings,
      state,
      currentProxyip: currentProxyipForAdmin(settings, state, config)
    });
  }
  if (request.method === "POST") {
    let body;
    try {
      body = JSON.parse(await readLimitedText(request));
    } catch (error) {
      return jsonResponse({ success: false, error: "invalid JSON" }, { status: 400 });
    }
    const settings = await saveProxyAutoSettings(env, body);
    const state = await loadProxyAutoState(env);
    return jsonResponse({ success: true, settings, state });
  }
  return new Response("Method Not Allowed", { status: 405 });
}
__name(handleProxyIpAuto, "handleProxyIpAuto");
async function handleProxyIpAutoRun(request, env, url) {
  if (request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }
  let body = {};
  const rawText = await readLimitedText(request);
  if (rawText.trim()) {
    try {
      body = JSON.parse(rawText);
    } catch (error) {
      return jsonResponse({ success: false, error: "invalid JSON" }, { status: 400 });
    }
  }
  const selectedInput = body.selectedProxyip ?? body.selectedProxyipText ?? body.currentProxyip;
  if (selectedInput !== void 0) {
    const rawItems = Array.isArray(selectedInput) ? selectedInput : String(selectedInput || "").split(/[\r\n,;]+/);
    const parsed = parseProbeTargets(rawItems);
    const selectedProxyip = parsed.endpoints.map(formatEndpoint);
    if (!selectedProxyip.length) {
      return jsonResponse({ success: false, error: "selectedProxyip is empty or invalid", invalid: parsed.invalid }, { status: 400 });
    }
    const incomingSettings = body.settings && typeof body.settings === "object" ? { ...body.settings, enabled: true } : { enabled: true };
    const settings = await saveProxyAutoSettings(env, incomingSettings);
    const previousState = await loadProxyAutoState(env);
    const timestamp = (new Date()).toISOString();
    const state = await saveProxyAutoState(env, buildProxyAutoState(previousState, {
      version: 1,
      trigger: String(body.trigger || "manual"),
      startedAt: timestamp,
      status: "success",
      action: "imported",
      reason: "imported selected PROXYIP into auto pool",
      currentProxyip: selectedProxyip.join(","),
      currentFailureCount: 0,
      selectedProxyip
    }));
    return jsonResponse({ success: true, settings, state, invalid: parsed.invalid });
  }
  const result = await runProxyAutoMaintenance(env, {
    trigger: "manual",
    hostname: url.hostname,
    forceEnabled: Boolean(body.forceEnabled),
    forceReplace: Boolean(body.forceReplace),
    settings: body.settings
  });
  return jsonResponse(result);
}
__name(handleProxyIpAutoRun, "handleProxyIpAutoRun");
function isProtectedAdminPath(pathname, adminBasePath) {
  const lowerPath = String(pathname || "").toLowerCase();
  const base = String(adminBasePath || ROUTES.ADMIN_ROOT);
  const lowerBase = base.toLowerCase();
  return lowerPath.startsWith(`${lowerBase}/pg/`) || lowerPath.startsWith(`${lowerBase}/rk/`) || lowerPath.startsWith(`${lowerBase}/fd/`);
}
__name(isProtectedAdminPath, "isProtectedAdminPath");
async function handleAdmin(request, env, url, basePath = ROUTES.ADMIN_ROOT) {
  const adminBasePath = basePath || ROUTES.ADMIN_ROOT;
  const adminRootPath = `${adminBasePath}/`;
  const adminLoginPath = `${adminBasePath}/ht/dl`;
  const adminLogoutPath = `${adminBasePath}/ht/tu`;
  const adminStatePath = `${adminBasePath}/pg/du`;
  const adminSavePath = `${adminBasePath}/pg/xie`;
  const adminEntriesPath = `${adminBasePath}/rk/du`;
  const adminProxyCatalogPath = `${adminBasePath}/fd/jk`;
  const adminProxyTestPath = `${adminBasePath}/fd/jk/ce`;
  const adminEntryCandidatesPath = `${adminBasePath}/fd/jk/rk`;
  const adminProxyAutoPath = `${adminBasePath}/fd/zd/du`;
  const adminProxyRunPath = `${adminBasePath}/fd/zd/ce`;
  const isProtectedPath = isProtectedAdminPath(url.pathname, adminBasePath);
  if (request.method === "OPTIONS" && isProtectedPath) {
    return new Response(null, { status: 204, headers: ADMIN_CORS_HEADERS });
  }
  const authenticated = await isAdminRequest(request, env);
  if (!authenticated) {
    if (isProtectedPath) {
      return withAdminCors(jsonResponse({ success: false, error: "forbidden" }, { status: 403 }));
    }
    if ((request.method === "GET" || request.method === "POST") && (url.pathname === adminBasePath || url.pathname === adminRootPath || url.pathname === adminLoginPath)) {
      return await handleLogin(request, env, adminBasePath);
    }
    return new Response("Redirecting", {
      status: 302,
      headers: { Location: adminBasePath, "Cache-Control": "no-store" }
    });
  }
  if (url.pathname === adminLoginPath) {
    return await handleLogin(request, env, adminBasePath);
  }
  if (url.pathname === adminLogoutPath) {
    const response = jsonResponse({ success: true });
    response.headers.set("Set-Cookie", "auth=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict");
    return withAdminCors(response);
  }
  if (url.pathname === adminBasePath || url.pathname === adminRootPath) {
    if (request.method !== "GET") {
      return new Response("Method Not Allowed", { status: 405 });
    }
    return await renderStaticAdminPage(request, env, adminBasePath);
  }
  if (url.pathname === adminStatePath) {
    if (request.method !== "GET") {
      return withAdminCors(new Response("Method Not Allowed", { status: 405 }));
    }
    const [config, addText, settings, autoState] = await Promise.all([
      loadConfig(env, url.hostname),
      loadEntryEndpointsText(env),
      loadProxyAutoSettings(env),
      loadProxyAutoState(env)
    ]);
    return withAdminCors(jsonResponse({
      success: true,
      config: withRenderedLink(config),
      addText,
      currentProxyip: currentProxyipForAdmin(settings, autoState, config),
      proxyAuto: { settings, state: autoState }
    }));
  }
  if (url.pathname === adminSavePath) {
    if (request.method !== "POST") {
      return withAdminCors(new Response("Method Not Allowed", { status: 405 }));
    }
    let body;
    try {
      body = JSON.parse(await readLimitedText(request));
    } catch (error) {
      return withAdminCors(jsonResponse({ success: false, error: "invalid JSON" }, { status: 400 }));
    }
    let savedConfig = null;
    if (body.config || body.UUID || body.HOST) {
      savedConfig = await saveConfig(env, withRenderedLink(body.config || body), url.hostname);
    }
    if (typeof body.addText === "string" || typeof body.entries === "string") {
      await saveEntryEndpointsText(env, typeof body.addText === "string" ? body.addText : body.entries);
    }
    let savedSettings = null;
    const incomingSettings = body.proxyAuto?.settings || body.autoSettings || body.settings;
    if (incomingSettings && typeof incomingSettings === "object") {
      savedSettings = await saveProxyAutoSettings(env, incomingSettings);
    }
    const [config, addText, settings, autoState] = await Promise.all([
      savedConfig ? Promise.resolve(savedConfig) : loadConfig(env, url.hostname),
      loadEntryEndpointsText(env),
      savedSettings ? Promise.resolve(savedSettings) : loadProxyAutoSettings(env),
      loadProxyAutoState(env)
    ]);
    return withAdminCors(jsonResponse({
      success: true,
      config: withRenderedLink(config),
      addText,
      currentProxyip: currentProxyipForAdmin(settings, autoState, config),
      proxyAuto: { settings, state: autoState }
    }));
  }
  if (url.pathname === adminEntriesPath) {
    if (request.method === "GET") {
      return withAdminCors(jsonResponse({ success: true, addText: await loadEntryEndpointsText(env) }));
    }
    if (request.method === "POST") {
      const body = await readLimitedText(request);
      try {
        const parsed = JSON.parse(body);
        await saveEntryEndpointsText(env, String(parsed.addText ?? parsed.entries ?? ""));
      } catch {
        await saveEntryEndpointsText(env, body);
      }
      return withAdminCors(jsonResponse({ success: true, addText: await loadEntryEndpointsText(env) }));
    }
    return withAdminCors(new Response("Method Not Allowed", { status: 405 }));
  }
  if (url.pathname === adminProxyTestPath) {
    return withAdminCors(await handleProxyIpProbe(request, env, url));
  }
  if (url.pathname === adminEntryCandidatesPath) {
    return withAdminCors(await handleEntryCandidates(request, env));
  }
  if (url.pathname === adminProxyCatalogPath || url.pathname.startsWith(`${adminProxyCatalogPath}/`)) {
    return withAdminCors(await handleProxyIpCatalog(request, env, url, adminProxyCatalogPath));
  }
  if (url.pathname === adminProxyAutoPath) {
    return withAdminCors(await handleProxyIpAuto(request, env, url));
  }
  if (url.pathname === adminProxyRunPath) {
    return withAdminCors(await handleProxyIpAutoRun(request, env, url));
  }
  return new Response("Not Found", { status: 404 });
}
__name(handleAdmin, "handleAdmin");
async function handleSubscription(request, env, url, ctx) {
  if (request.method !== "GET") {
    return new Response("Method Not Allowed", { status: 405 });
  }
  const outputKind = subscriptionOutputKind(request, url);
  const cached = await matchSubscriptionCache(request, url, outputKind);
  if (cached) {
    return cached;
  }
  const limited = enforceSubscriptionRateLimit(request);
  if (limited) {
    return limited;
  }
  const config = await loadConfig(env, url.hostname, { allowDefaultFallback: false });
  const token = getSubscriptionConfig(config).TOKEN;
  if (!token || !equalSubscriptionToken(url.searchParams.get("token"), token)) {
    return new Response("Forbidden", { status: 403 });
  }
  if (url.searchParams.has("clash")) {
    const response = await fetchConvertedSubscriptionResponse(config, url, env, "clash", token, request);
    return await cacheSubscriptionResponse(request, url, outputKind, response, ctx);
  }
  if (url.searchParams.has("sb") || url.searchParams.has("singbox")) {
    const response = await fetchConvertedSubscriptionResponse(config, url, env, "singbox", token, request);
    return await cacheSubscriptionResponse(request, url, outputKind, response, ctx);
  }
  const addText = await loadEntryEndpointsText(env);
  const records = buildNodeRecords(config, addText);
  let response;
  if (wantsBase64Subscription(request, url)) {
    response = new Response(renderBase64Subscription(records), {
      headers: subscriptionResponseHeaders(config, url, env, TEXT_HEADERS["Content-Type"], request)
    });
    return await cacheSubscriptionResponse(request, url, outputKind, response, ctx);
  }
  response = new Response(renderMixedSubscription(records), {
    headers: subscriptionResponseHeaders(config, url, env, TEXT_HEADERS["Content-Type"], request)
  });
  return await cacheSubscriptionResponse(request, url, outputKind, response, ctx);
}
__name(handleSubscription, "handleSubscription");
var worker_ip168_proxy_mode_default = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    try {
      if (url.protocol === "http:") {
        url.protocol = "https:";
        return Response.redirect(url.href, 301);
      }
      const adminBasePath = getAdminBasePath(env);
      const adminEntryBasePath = getAdminEntryBasePath(url.pathname, adminBasePath);
      if (request.method === "GET" && url.pathname === VENDOR_QRCODE_PATH) {
        return await renderQrCodeVendorAsset(env);
      }
      if (url.pathname === ROUTES.SUBSCRIPTION) {
        return await handleSubscription(request, env, url, ctx);
      }
      if (adminEntryBasePath) {
        return await handleAdmin(request, env, url, adminEntryBasePath);
      }
      if (isWebSocketUpgrade(request)) {
        return await handleWebSocket(request, env, await loadConfig(env, url.hostname, { allowDefaultFallback: false }), url);
      }
      if (request.method === "GET" && url.pathname === ROUTES.PUBLIC_ROOT) {
        return new Response("This website is under construction.", {
          headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" }
        });
      }
      return new Response("Not Found", { status: 404 });
    } catch (error) {
      console.error("[fetch] request failed", error);
      return jsonResponse({ success: false, error: error.message || "internal error" }, { status: 500 });
    }
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      runProxyAutoMaintenance(env, { trigger: "scheduled" }).catch((error) => {
        console.error("[scheduled] proxy auto maintenance failed", error);
      })
    );
  }
};
export {
  worker_ip168_proxy_mode_default as default
};


