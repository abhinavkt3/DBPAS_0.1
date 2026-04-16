/**
 * DBPAS Crypto Utilities
 * 
 * ECDSA key management, signing, and hashing utilities using ethers.js.
 * Implements the cryptographic primitives required by the DPGA protocol.
 */

const { ethers } = require('ethers');

/**
 * Generate a new ECDSA keypair (secp256k1).
 * @returns {{ privateKey: string, publicKey: string, address: string }}
 */
function generateKeyPair() {
  const wallet = ethers.Wallet.createRandom();
  return {
    privateKey: wallet.privateKey,
    publicKey: wallet.publicKey,
    address: wallet.address,
  };
}

/**
 * Create an ethers.js Wallet from a private key.
 * @param {string} privateKey - Hex-encoded private key.
 * @returns {ethers.Wallet}
 */
function walletFromKey(privateKey) {
  return new ethers.Wallet(privateKey);
}

/**
 * Compute keccak256 hash of packed data.
 * @param {string[]} types  - Solidity ABI types (e.g., ['bytes32', 'uint256']).
 * @param {any[]}    values - Corresponding values.
 * @returns {string} Hex-encoded keccak256 hash.
 */
function keccak256Packed(types, values) {
  const packed = ethers.solidityPacked(types, values);
  return ethers.keccak256(packed);
}

/**
 * Compute keccak256 hash of raw bytes.
 * @param {string|Uint8Array} data - Input data.
 * @returns {string} Hex-encoded keccak256 hash.
 */
function keccak256(data) {
  if (typeof data === 'string' && !data.startsWith('0x')) {
    data = ethers.toUtf8Bytes(data);
  }
  return ethers.keccak256(data);
}

/**
 * Sign a message hash using ECDSA (secp256k1).
 * Produces a 65-byte signature (r + s + v) compatible with ecrecover.
 * 
 * @param {string} privateKey   - Hex-encoded private key.
 * @param {string} messageHash  - 32-byte hex hash to sign.
 * @returns {Promise<string>} 65-byte hex-encoded signature.
 */
async function signMessage(privateKey, messageHash) {
  const wallet = new ethers.Wallet(privateKey);
  // ethers.js signMessage auto-prefixes with "\x19Ethereum Signed Message:\n32"
  // We use wallet.signingKey.sign for raw hash signing that matches ecrecover on-chain
  const sig = wallet.signingKey.sign(messageHash);
  return sig.serialized;
}

/**
 * Sign a message with Ethereum prefix (for ecrecover compatibility).
 * @param {string} privateKey   - Hex-encoded private key.
 * @param {string} messageHash  - 32-byte hex hash.
 * @returns {Promise<string>} 65-byte hex signature.
 */
async function signMessagePrefixed(privateKey, messageHash) {
  const wallet = new ethers.Wallet(privateKey);
  // This produces a signature over the Ethereum-prefixed hash
  const messageBytes = ethers.getBytes(messageHash);
  return wallet.signMessage(messageBytes);
}

/**
 * Recover signer address from a signature.
 * @param {string} messageHash - Original message hash (32 bytes, hex).
 * @param {string} signature   - 65-byte hex signature.
 * @returns {string} Recovered Ethereum address.
 */
function recoverAddress(messageHash, signature) {
  const messageBytes = ethers.getBytes(messageHash);
  return ethers.verifyMessage(messageBytes, signature);
}

/**
 * Recover signer from raw (non-prefixed) signature.
 * @param {string} messageHash - 32-byte hex hash.
 * @param {string} signature   - 65-byte hex signature.
 * @returns {string} Recovered address.
 */
function recoverAddressRaw(messageHash, signature) {
  return ethers.recoverAddress(messageHash, signature);
}

/**
 * Verify that a signature was produced by the claimed address.
 * @param {string} messageHash - Original message hash.
 * @param {string} signature   - 65-byte hex signature.
 * @param {string} expectedAddress - Expected signer address.
 * @returns {boolean} True if signature is valid and matches address.
 */
function verifySignature(messageHash, signature, expectedAddress) {
  try {
    const recovered = recoverAddress(messageHash, signature);
    return recovered.toLowerCase() === expectedAddress.toLowerCase();
  } catch {
    return false;
  }
}

/**
 * Generate a UUID v4 as a bytes32 product ID.
 * @returns {string} Hex-encoded bytes32 PID.
 */
function generatePID() {
  const { v4: uuidv4 } = require('uuid');
  const uuid = uuidv4().replace(/-/g, '');
  return ethers.zeroPadValue('0x' + uuid, 32);
}

/**
 * Encode GPS coordinates as int256 (scaled by 1e6).
 * @param {number} lat - Latitude in degrees.
 * @param {number} lon - Longitude in degrees.
 * @returns {{ lat: bigint, lon: bigint }}
 */
function encodeGPS(lat, lon) {
  return {
    lat: BigInt(Math.round(lat * 1e6)),
    lon: BigInt(Math.round(lon * 1e6)),
  };
}

/**
 * Decode GPS coordinates from int256 (scaled by 1e6).
 * @param {bigint|number} lat - Encoded latitude.
 * @param {bigint|number} lon - Encoded longitude.
 * @returns {{ lat: number, lon: number }}
 */
function decodeGPS(lat, lon) {
  return {
    lat: Number(lat) / 1e6,
    lon: Number(lon) / 1e6,
  };
}

module.exports = {
  generateKeyPair,
  walletFromKey,
  keccak256Packed,
  keccak256,
  signMessage,
  signMessagePrefixed,
  recoverAddress,
  recoverAddressRaw,
  verifySignature,
  generatePID,
  encodeGPS,
  decodeGPS,
};
