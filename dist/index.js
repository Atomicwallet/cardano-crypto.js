"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

var _regenerator = _interopRequireDefault(require("@babel/runtime/regenerator"));

var _asyncToGenerator2 = _interopRequireDefault(require("@babel/runtime/helpers/asyncToGenerator"));

var _typeof2 = _interopRequireDefault(require("@babel/runtime/helpers/typeof"));

var bip39 = require('bip39-light');

var cbor = require('borc');

var Module = require('../lib.js');

var crc32 = require('./utils/crc32');

var base58 = require('./utils/base58');

var scrypt = require('./utils/scrypt-async');

var pbkdf2 = require('./utils/pbkdf2');

var CborIndefiniteLengthArray = require('./utils/CborIndefiniteLengthArray');

var HARDENED_THRESHOLD = 0x80000000;

function validateDerivationScheme(input) {
  if (input !== 1 && input !== 2) {
    throw new Error('invalid derivation scheme!');
  }
}

function validateBuffer(input, expectedLength) {
  if (!Buffer.isBuffer(input)) {
    throw new Error('not buffer!');
  }

  if (expectedLength && input.length !== expectedLength) {
    throw new Error('Invalid buffer length');
  }
}

function validateArray(input) {
  if ((0, _typeof2["default"])(input) !== (0, _typeof2["default"])([])) {
    throw new Error('not an array!');
  }
}

function validateDerivationIndex(input) {
  if (!Number.isInteger(input)) {
    throw new Error('invalid derivation index!');
  }
}

function validateString(input) {
  if ((0, _typeof2["default"])(input) !== (0, _typeof2["default"])('aa')) {
    throw new Error('not a string!');
  }
}

function validateMnemonic(input) {
  if (!bip39.validateMnemonic(input)) {
    var e = new Error('Invalid or unsupported mnemonic format:');
    e.name = 'InvalidArgumentException';
    throw e;
  }
}

function validateMnemonicWords(input) {
  var wordlist = bip39.wordlists.EN;
  var words = input.split(' ');
  var valid = words.reduce(function (result, word) {
    return result && wordlist.indexOf(word) !== -1;
  }, true);

  if (!valid) {
    throw new Error('Invalid mnemonic words');
  }
}

function validatePaperWalletMnemonic(input) {
  validateMnemonicWords(input);
  var mnemonicLength = input.split(' ').length;

  if (mnemonicLength !== 27) {
    throw Error("Paper Wallet Mnemonic must be 27 words, got ".concat(mnemonicLength, " instead"));
  }
}

function cborEncodeBuffer(input) {
  validateBuffer(input);
  var len = input.length;
  var cborPrefix = [];

  if (len < 24) {
    cborPrefix = [0x40 + len];
  } else if (len < 256) {
    cborPrefix = [0x58, len];
  } else {
    throw Error('CBOR encode for more than 256 bytes not yet implemented');
  }

  return Buffer.concat([Buffer.from(cborPrefix), input]);
}

function sign(msg, keypair) {
  validateBuffer(msg);
  validateBuffer(keypair, 128);
  var msgLen = msg.length;

  var msgArrPtr = Module._malloc(msgLen);

  var msgArr = new Uint8Array(Module.HEAPU8.buffer, msgArrPtr, msgLen);

  var keypairArrPtr = Module._malloc(128);

  var keypairArr = new Uint8Array(Module.HEAPU8.buffer, keypairArrPtr, 128);

  var sigPtr = Module._malloc(64);

  var sigArr = new Uint8Array(Module.HEAPU8.buffer, sigPtr, 64);
  msgArr.set(msg);
  keypairArr.set(keypair);

  Module._emscripten_sign(keypairArrPtr, msgArrPtr, msgLen, sigPtr);

  Module._free(msgArrPtr);

  Module._free(keypairArrPtr);

  Module._free(sigPtr);

  return Buffer.from(sigArr);
}

function verify(msg, publicKey, sig) {
  validateBuffer(msg);
  validateBuffer(publicKey, 32);
  validateBuffer(sig, 64);
  var msgLen = msg.length;

  var msgArrPtr = Module._malloc(msgLen);

  var msgArr = new Uint8Array(Module.HEAPU8.buffer, msgArrPtr, msgLen);

  var publicKeyArrPtr = Module._malloc(32);

  var publicKeyArr = new Uint8Array(Module.HEAPU8.buffer, publicKeyArrPtr, 32);

  var sigPtr = Module._malloc(64);

  var sigArr = new Uint8Array(Module.HEAPU8.buffer, sigPtr, 64);
  msgArr.set(msg);
  publicKeyArr.set(publicKey);
  sigArr.set(sig);
  var result = Module._emscripten_verify(msgArrPtr, msgLen, publicKeyArrPtr, sigPtr) === 0;

  Module._free(msgArrPtr);

  Module._free(publicKeyArrPtr);

  Module._free(sigPtr);

  return result;
}

function mnemonicToRootKeypair(_x, _x2) {
  return _mnemonicToRootKeypair.apply(this, arguments);
}

function _mnemonicToRootKeypair() {
  _mnemonicToRootKeypair = (0, _asyncToGenerator2["default"])(
  /*#__PURE__*/
  _regenerator["default"].mark(function _callee(mnemonic, derivationScheme) {
    return _regenerator["default"].wrap(function _callee$(_context) {
      while (1) {
        switch (_context.prev = _context.next) {
          case 0:
            validateDerivationScheme(derivationScheme);

            if (!(derivationScheme === 1)) {
              _context.next = 5;
              break;
            }

            return _context.abrupt("return", mnemonicToRootKeypairV1(mnemonic));

          case 5:
            if (!(derivationScheme === 2)) {
              _context.next = 9;
              break;
            }

            return _context.abrupt("return", mnemonicToRootKeypairV2(mnemonic, ''));

          case 9:
            throw Error("Derivation scheme ".concat(derivationScheme, " not implemented"));

          case 10:
          case "end":
            return _context.stop();
        }
      }
    }, _callee);
  }));
  return _mnemonicToRootKeypair.apply(this, arguments);
}

function mnemonicToRootKeypairV1(mnemonic) {
  var seed = mnemonicToSeedV1(mnemonic);
  return seedToKeypairV1(seed);
}

function mnemonicToSeedV1(mnemonic) {
  validateMnemonic(mnemonic);
  var entropy = Buffer.from(bip39.mnemonicToEntropy(mnemonic), 'hex');
  return cborEncodeBuffer(blake2b(cborEncodeBuffer(entropy), 32));
}

function seedToKeypairV1(seed) {
  var result;

  for (var i = 1; result === undefined && i <= 1000; i++) {
    try {
      var digest = hmac_sha512(seed, [Buffer.from("Root Seed Chain ".concat(i), 'ascii')]);
      var tempSeed = digest.slice(0, 32);
      var chainCode = digest.slice(32, 64);
      result = trySeedChainCodeToKeypairV1(tempSeed, chainCode);
    } catch (e) {
      if (e.name === 'InvalidKeypair') {
        continue;
      }

      throw e;
    }
  }

  if (result === undefined) {
    var e = new Error('Secret key generation from mnemonic is looping forever');
    e.name = 'RuntimeException';
    throw e;
  }

  return result;
}

function trySeedChainCodeToKeypairV1(seed, chainCode) {
  validateBuffer(seed, 32);
  validateBuffer(chainCode, 32);

  var seedArrPtr = Module._malloc(32);

  var seedArr = new Uint8Array(Module.HEAPU8.buffer, seedArrPtr, 32);

  var chainCodeArrPtr = Module._malloc(32);

  var chainCodeArr = new Uint8Array(Module.HEAPU8.buffer, chainCodeArrPtr, 32);

  var keypairArrPtr = Module._malloc(128);

  var keypairArr = new Uint8Array(Module.HEAPU8.buffer, keypairArrPtr, 128);
  seedArr.set(seed);
  chainCodeArr.set(chainCode);

  var returnCode = Module._emscripten_wallet_secret_from_seed(seedArrPtr, chainCodeArrPtr, keypairArrPtr);

  Module._free(seedArrPtr);

  Module._free(chainCodeArrPtr);

  Module._free(keypairArrPtr);

  if (returnCode === 1) {
    var e = new Error('Invalid keypair');
    e.name = 'InvalidKeypair';
    throw e;
  }

  return Buffer.from(keypairArr);
}

function mnemonicToRootKeypairV2(_x3, _x4) {
  return _mnemonicToRootKeypairV.apply(this, arguments);
}

function _mnemonicToRootKeypairV() {
  _mnemonicToRootKeypairV = (0, _asyncToGenerator2["default"])(
  /*#__PURE__*/
  _regenerator["default"].mark(function _callee2(mnemonic, password) {
    var seed, rootSecret;
    return _regenerator["default"].wrap(function _callee2$(_context2) {
      while (1) {
        switch (_context2.prev = _context2.next) {
          case 0:
            seed = mnemonicToSeedV2(mnemonic);
            _context2.next = 3;
            return seedToKeypairV2(seed, password);

          case 3:
            rootSecret = _context2.sent;
            return _context2.abrupt("return", seedToKeypairV2(seed, password));

          case 5:
          case "end":
            return _context2.stop();
        }
      }
    }, _callee2);
  }));
  return _mnemonicToRootKeypairV.apply(this, arguments);
}

function mnemonicToSeedV2(mnemonic) {
  validateMnemonic(mnemonic);
  return Buffer.from(bip39.mnemonicToEntropy(mnemonic), 'hex');
}

function seedToKeypairV2(_x5, _x6) {
  return _seedToKeypairV.apply(this, arguments);
}

function _seedToKeypairV() {
  _seedToKeypairV = (0, _asyncToGenerator2["default"])(
  /*#__PURE__*/
  _regenerator["default"].mark(function _callee3(seed, password) {
    var xprv, publicKey;
    return _regenerator["default"].wrap(function _callee3$(_context3) {
      while (1) {
        switch (_context3.prev = _context3.next) {
          case 0:
            _context3.next = 2;
            return pbkdf2(password, seed, 4096, 96, 'sha512');

          case 2:
            xprv = _context3.sent;
            xprv[0] &= 248;
            xprv[31] &= 31;
            xprv[31] |= 64;
            publicKey = toPublic(xprv.slice(0, 64));
            return _context3.abrupt("return", Buffer.concat([xprv.slice(0, 64), publicKey, xprv.slice(64)]));

          case 8:
          case "end":
            return _context3.stop();
        }
      }
    }, _callee3);
  }));
  return _seedToKeypairV.apply(this, arguments);
}

function toPublic(privateKey) {
  validateBuffer(privateKey, 64);

  var privateKeyArrPtr = Module._malloc(64);

  var privateKeyArr = new Uint8Array(Module.HEAPU8.buffer, privateKeyArrPtr, 64);

  var publicKeyArrPtr = Module._malloc(32);

  var publicKeyArr = new Uint8Array(Module.HEAPU8.buffer, publicKeyArrPtr, 32);
  privateKeyArr.set(privateKey);

  Module._emscripten_to_public(privateKeyArrPtr, publicKeyArrPtr);

  Module._free(privateKeyArrPtr);

  Module._free(publicKeyArrPtr);

  return Buffer.from(publicKeyArr);
}

function derivePrivate(parentKey, index, derivationScheme) {
  validateBuffer(parentKey, 128);
  validateDerivationIndex(index);
  validateDerivationScheme(derivationScheme);

  var parentKeyArrPtr = Module._malloc(128);

  var parentKeyArr = new Uint8Array(Module.HEAPU8.buffer, parentKeyArrPtr, 128);

  var childKeyArrPtr = Module._malloc(128);

  var childKeyArr = new Uint8Array(Module.HEAPU8.buffer, childKeyArrPtr, 128);
  parentKeyArr.set(parentKey);

  Module._emscripten_derive_private(parentKeyArrPtr, index, childKeyArrPtr, derivationScheme);

  Module._free(parentKeyArrPtr);

  Module._free(childKeyArrPtr);

  return Buffer.from(childKeyArr);
}

function derivePublic(parentExtPubKey, index, derivationScheme) {
  validateBuffer(parentExtPubKey, 64);
  validateDerivationIndex(index);
  validateDerivationScheme(derivationScheme);
  var parentPubKey = parentExtPubKey.slice(0, 32);
  var parentChainCode = parentExtPubKey.slice(32, 64);

  var parentPubKeyArrPtr = Module._malloc(32);

  var parentPubKeyArr = new Uint8Array(Module.HEAPU8.buffer, parentPubKeyArrPtr, 32);

  var parentChainCodeArrPtr = Module._malloc(32);

  var parentChainCodeArr = new Uint8Array(Module.HEAPU8.buffer, parentChainCodeArrPtr, 32);

  var childPubKeyArrPtr = Module._malloc(32);

  var childPubKeyArr = new Uint8Array(Module.HEAPU8.buffer, childPubKeyArrPtr, 32);

  var childChainCodeArrPtr = Module._malloc(32);

  var childChainCodeArr = new Uint8Array(Module.HEAPU8.buffer, childChainCodeArrPtr, 32);
  parentPubKeyArr.set(parentPubKey);
  parentChainCodeArr.set(parentChainCode);

  var resultCode = Module._emscripten_derive_public(parentPubKeyArrPtr, parentChainCodeArrPtr, index, childPubKeyArrPtr, childChainCodeArrPtr, derivationScheme);

  Module._free(parentPubKeyArrPtr);

  Module._free(parentChainCodeArrPtr);

  Module._free(parentPubKeyArrPtr);

  Module._free(parentChainCodeArrPtr);

  if (resultCode !== 0) {
    throw Error("derivePublic has exited with code ".concat(resultCode));
  }

  return Buffer.concat([Buffer.from(childPubKeyArr), Buffer.from(childChainCodeArr)]);
}

function blake2b(input, outputLen) {
  validateBuffer(input);
  var inputLen = input.length;

  var inputArrPtr = Module._malloc(inputLen);

  var inputArr = new Uint8Array(Module.HEAPU8.buffer, inputArrPtr, inputLen);

  var outputArrPtr = Module._malloc(outputLen);

  var outputArr = new Uint8Array(Module.HEAPU8.buffer, outputArrPtr, outputLen);
  inputArr.set(input);

  Module._emscripten_blake2b(inputArrPtr, inputLen, outputArrPtr, outputLen);

  Module._free(inputArrPtr);

  Module._free(outputArrPtr);

  return Buffer.from(outputArr);
}

function sha3_256(input) {
  validateBuffer(input);
  var inputLen = input.length;

  var inputArrPtr = Module._malloc(inputLen);

  var inputArr = new Uint8Array(Module.HEAPU8.buffer, inputArrPtr, inputLen);
  var outputLen = 32;

  var outputArrPtr = Module._malloc(outputLen);

  var outputArr = new Uint8Array(Module.HEAPU8.buffer, outputArrPtr, outputLen);
  inputArr.set(input);

  Module._emscripten_sha3_256(inputArrPtr, inputLen, outputArrPtr);

  Module._free(inputArrPtr);

  Module._free(outputArrPtr);

  return Buffer.from(outputArr);
}

function hmac_sha512(initKey, inputs) {
  validateBuffer(initKey);
  validateArray(inputs);
  inputs.map(validateBuffer);

  var ctxLen = Module._emscripten_size_of_hmac_sha512_ctx();

  var ctxArrPtr = Module._malloc(ctxLen);

  var ctxArr = new Uint8Array(Module.HEAPU8.buffer, ctxArrPtr, ctxLen);
  var initKeyLen = initKey.length;

  var initKeyArrPtr = Module._malloc(initKeyLen);

  var initKeyArr = new Uint8Array(Module.HEAPU8.buffer, initKeyArrPtr, initKeyLen);
  var outputLen = 64;

  var outputArrPtr = Module._malloc(outputLen);

  var outputArr = new Uint8Array(Module.HEAPU8.buffer, outputArrPtr, outputLen);
  initKeyArr.set(initKey);

  Module._emscripten_hmac_sha512_init(ctxArrPtr, initKeyArrPtr, initKeyLen);

  for (var i = 0; i < inputs.length; i++) {
    var inputLen = inputs[i].length;

    var inputArrPtr = Module._malloc(inputLen);

    var inputArr = new Uint8Array(Module.HEAPU8.buffer, inputArrPtr, inputLen);
    inputArr.set(inputs[i]);

    Module._emscripten_hmac_sha512_update(ctxArrPtr, inputArrPtr, inputLen);

    Module._free(inputArrPtr);
  }

  Module._emscripten_hmac_sha512_final(ctxArrPtr, outputArrPtr);

  Module._free(initKeyArrPtr);

  Module._free(ctxArrPtr);

  Module._free(outputArrPtr);

  return Buffer.from(outputArr);
}

function cardanoMemoryCombine(input, password) {
  validateString(password);
  validateBuffer(input);

  if (password === '') {
    return input;
  }

  var transformedPassword = blake2b(Buffer.from(password, 'utf-8'), 32);
  var transformedPasswordLen = transformedPassword.length;

  var transformedPasswordArrPtr = Module._malloc(transformedPasswordLen);

  var transformedPasswordArr = new Uint8Array(Module.HEAPU8.buffer, transformedPasswordArrPtr, transformedPasswordLen);
  var inputLen = input.length;

  var inputArrPtr = Module._malloc(inputLen);

  var inputArr = new Uint8Array(Module.HEAPU8.buffer, inputArrPtr, inputLen);

  var outputArrPtr = Module._malloc(inputLen);

  var outputArr = new Uint8Array(Module.HEAPU8.buffer, outputArrPtr, inputLen);
  inputArr.set(input);
  transformedPasswordArr.set(transformedPassword);

  Module._emscripten_cardano_memory_combine(transformedPasswordArrPtr, transformedPasswordLen, inputArrPtr, outputArrPtr, inputLen);

  Module._free(inputArrPtr);

  Module._free(outputArrPtr);

  Module._free(transformedPasswordArrPtr);

  return Buffer.from(outputArr);
}

function chacha20poly1305Encrypt(input, key, nonce) {
  validateBuffer(input);
  validateBuffer(key, 32);
  validateBuffer(nonce, 12);
  var inputLen = input.length;

  var inputArrPtr = Module._malloc(inputLen);

  var inputArr = new Uint8Array(Module.HEAPU8.buffer, inputArrPtr, inputLen);
  var keyLen = key.length;

  var keyArrPtr = Module._malloc(keyLen);

  var keyArr = new Uint8Array(Module.HEAPU8.buffer, keyArrPtr, keyLen);
  var nonceLen = nonce.length;

  var nonceArrPtr = Module._malloc(nonceLen);

  var nonceArr = new Uint8Array(Module.HEAPU8.buffer, nonceArrPtr, nonceLen);
  var tagLen = 16;
  var outputLen = inputLen + tagLen;

  var outputArrPtr = Module._malloc(outputLen);

  var outputArr = new Uint8Array(Module.HEAPU8.buffer, outputArrPtr, outputLen);
  inputArr.set(input);
  keyArr.set(key);
  nonceArr.set(nonce);

  var resultCode = Module._emscripten_chacha20poly1305_enc(keyArrPtr, nonceArrPtr, inputArrPtr, inputLen, outputArrPtr, outputArrPtr + inputLen, tagLen, 1);

  Module._free(inputArrPtr);

  Module._free(keyArrPtr);

  Module._free(nonceArrPtr);

  Module._free(outputArrPtr);

  if (resultCode !== 0) {
    throw Error('chacha20poly1305 encryption has failed!');
  }

  return Buffer.from(outputArr);
}

function chacha20poly1305Decrypt(input, key, nonce) {
  validateBuffer(input);
  validateBuffer(key, 32);
  validateBuffer(nonce, 12); // extract tag from input

  var tagLen = 16;
  var tag = input.slice(input.length - tagLen, input.length);
  input = input.slice(0, input.length - tagLen);
  var inputLen = input.length;

  var inputArrPtr = Module._malloc(inputLen);

  var inputArr = new Uint8Array(Module.HEAPU8.buffer, inputArrPtr, inputLen);

  var tagArrPtr = Module._malloc(tagLen);

  var tagArr = new Uint8Array(Module.HEAPU8.buffer, tagArrPtr, tagLen);
  var keyLen = key.length;

  var keyArrPtr = Module._malloc(keyLen);

  var keyArr = new Uint8Array(Module.HEAPU8.buffer, keyArrPtr, keyLen);
  var nonceLen = nonce.length;

  var nonceArrPtr = Module._malloc(nonceLen);

  var nonceArr = new Uint8Array(Module.HEAPU8.buffer, nonceArrPtr, nonceLen);
  var outputLen = inputLen;

  var outputArrPtr = Module._malloc(outputLen);

  var outputArr = new Uint8Array(Module.HEAPU8.buffer, outputArrPtr, outputLen);
  inputArr.set(input);
  tagArr.set(tag);
  keyArr.set(key);
  nonceArr.set(nonce);

  var resultCode = Module._emscripten_chacha20poly1305_enc(keyArrPtr, nonceArrPtr, inputArrPtr, inputLen, outputArrPtr, tagArrPtr, tagLen, 0);

  Module._free(inputArrPtr);

  Module._free(keyArrPtr);

  Module._free(nonceArrPtr);

  Module._free(outputArrPtr);

  Module._free(tagArrPtr);

  if (resultCode !== 0) {
    throw Error('chacha20poly1305 decryption has failed!');
  }

  return Buffer.from(outputArr);
}

function decodePaperWalletMnemonic(_x7) {
  return _decodePaperWalletMnemonic.apply(this, arguments);
}

function _decodePaperWalletMnemonic() {
  _decodePaperWalletMnemonic = (0, _asyncToGenerator2["default"])(
  /*#__PURE__*/
  _regenerator["default"].mark(function _callee4(paperWalletMnemonic) {
    var paperWalletMnemonicAsList, mnemonicScrambledPart, mnemonicPassphrasePart, passphrase, unscrambledMnemonic;
    return _regenerator["default"].wrap(function _callee4$(_context4) {
      while (1) {
        switch (_context4.prev = _context4.next) {
          case 0:
            validatePaperWalletMnemonic(paperWalletMnemonic);
            paperWalletMnemonicAsList = paperWalletMnemonic.split(' ');
            mnemonicScrambledPart = paperWalletMnemonicAsList.slice(0, 18).join(' ');
            mnemonicPassphrasePart = paperWalletMnemonicAsList.slice(18, 27).join(' ');
            _context4.next = 6;
            return mnemonicToPaperWalletPassphrase(mnemonicPassphrasePart);

          case 6:
            passphrase = _context4.sent;
            _context4.next = 9;
            return paperWalletUnscrambleStrings(passphrase, mnemonicScrambledPart);

          case 9:
            unscrambledMnemonic = _context4.sent;
            return _context4.abrupt("return", unscrambledMnemonic);

          case 11:
          case "end":
            return _context4.stop();
        }
      }
    }, _callee4);
  }));
  return _decodePaperWalletMnemonic.apply(this, arguments);
}

function mnemonicToPaperWalletPassphrase(_x8, _x9) {
  return _mnemonicToPaperWalletPassphrase.apply(this, arguments);
}
/* taken from https://github.com/input-output-hk/rust-cardano/blob/08796d9f100f417ff30549b297bd20b249f87809/cardano/src/paperwallet.rs */


function _mnemonicToPaperWalletPassphrase() {
  _mnemonicToPaperWalletPassphrase = (0, _asyncToGenerator2["default"])(
  /*#__PURE__*/
  _regenerator["default"].mark(function _callee5(mnemonic, password) {
    var mnemonicBuffer, salt, saltBuffer;
    return _regenerator["default"].wrap(function _callee5$(_context5) {
      while (1) {
        switch (_context5.prev = _context5.next) {
          case 0:
            mnemonicBuffer = Buffer.from(mnemonic, 'utf8');
            salt = "mnemonic".concat(password || '');
            saltBuffer = Buffer.from(salt, 'utf8');
            _context5.next = 5;
            return pbkdf2(mnemonicBuffer, saltBuffer, 2048, 32, 'sha512');

          case 5:
            return _context5.abrupt("return", _context5.sent.toString('hex'));

          case 6:
          case "end":
            return _context5.stop();
        }
      }
    }, _callee5);
  }));
  return _mnemonicToPaperWalletPassphrase.apply(this, arguments);
}

function paperWalletUnscrambleStrings(_x10, _x11) {
  return _paperWalletUnscrambleStrings.apply(this, arguments);
}

function _paperWalletUnscrambleStrings() {
  _paperWalletUnscrambleStrings = (0, _asyncToGenerator2["default"])(
  /*#__PURE__*/
  _regenerator["default"].mark(function _callee6(passphrase, mnemonic) {
    var input, saltLength, outputLength, output, i;
    return _regenerator["default"].wrap(function _callee6$(_context6) {
      while (1) {
        switch (_context6.prev = _context6.next) {
          case 0:
            input = Buffer.from(bip39.mnemonicToEntropy(mnemonic), 'hex');
            saltLength = 8;

            if (!(saltLength >= input.length)) {
              _context6.next = 4;
              break;
            }

            throw Error('unscrambleStrings: Input is too short');

          case 4:
            outputLength = input.length - saltLength;
            _context6.next = 7;
            return pbkdf2(passphrase, input.slice(0, saltLength), 10000, outputLength, 'sha512');

          case 7:
            output = _context6.sent;

            for (i = 0; i < outputLength; i++) {
              output[i] = output[i] ^ input[saltLength + i];
            }

            return _context6.abrupt("return", bip39.entropyToMnemonic(output));

          case 10:
          case "end":
            return _context6.stop();
        }
      }
    }, _callee6);
  }));
  return _paperWalletUnscrambleStrings.apply(this, arguments);
}

function xpubToHdPassphrase(_x12) {
  return _xpubToHdPassphrase.apply(this, arguments);
}

function _xpubToHdPassphrase() {
  _xpubToHdPassphrase = (0, _asyncToGenerator2["default"])(
  /*#__PURE__*/
  _regenerator["default"].mark(function _callee7(xpub) {
    return _regenerator["default"].wrap(function _callee7$(_context7) {
      while (1) {
        switch (_context7.prev = _context7.next) {
          case 0:
            validateBuffer(xpub, 64);
            return _context7.abrupt("return", pbkdf2(xpub, 'address-hashing', 500, 32, 'sha512'));

          case 2:
          case "end":
            return _context7.stop();
        }
      }
    }, _callee7);
  }));
  return _xpubToHdPassphrase.apply(this, arguments);
}

function packAddress(derivationPath, xpub, hdPassphrase, derivationScheme) {
  validateBuffer(xpub, 64);
  validateDerivationScheme(derivationScheme);

  if (derivationScheme === 1) {
    validateArray(derivationPath);
    validateBuffer(hdPassphrase, 32);
  }

  var addressPayload, addressAttributes;

  if (derivationScheme === 1 && derivationPath.length > 0) {
    addressPayload = encryptDerivationPath(derivationPath, hdPassphrase);
    addressAttributes = new Map([[1, cbor.encode(addressPayload)]]);
  } else {
    addressPayload = Buffer.from([]);
    addressAttributes = new Map();
  }

  var addressRoot = getAddressHash([0, [0, xpub], addressPayload.length > 0 ? new Map([[1, cbor.encode(addressPayload)]]) : new Map()]);
  var addressType = 0; // Public key address

  var addressData = [addressRoot, addressAttributes, addressType];
  var addressDataEncoded = cbor.encode(addressData);
  return base58.encode(cbor.encode([new cbor.Tagged(24, addressDataEncoded), crc32(addressDataEncoded)]));
}

function unpackAddress(address, hdPassphrase) {
  // we decode the address from the base58 string
  // and then we strip the 24 CBOR data tags (the "[0].value" part)
  var addressAsBuffer = cbor.decode(base58.decode(address))[0].value;
  var addressData = cbor.decode(addressAsBuffer);
  var attributes = addressData[1];
  var payload = cbor.decode(attributes.get(1));
  var derivationPath;

  try {
    derivationPath = decryptDerivationPath(payload, hdPassphrase);
  } catch (e) {
    throw new Error('Unable to get derivation path from address');
  }

  if (derivationPath && derivationPath.length > 2) {
    throw Error('Invalid derivation path length, should be at most 2');
  }

  return {
    derivationPath: derivationPath
  };
}

function isValidAddress(address) {
  try {
    // we decode the address from the base58 string
    var addressAsArray = cbor.decode(base58.decode(address)); // we strip the 24 CBOR data taga by taking the "value" attribute from the "Tagged" object

    var addressDataEncoded = addressAsArray[0].value;
    var crc32Checksum = addressAsArray[1];

    if (crc32Checksum !== crc32(addressDataEncoded)) {
      return false;
    }
  } catch (e) {
    return false;
  }

  return true;
}

function getAddressHash(input) {
  // eslint-disable-next-line camelcase
  var firstHash = sha3_256(cbor.encode(input));
  return blake2b(firstHash, 28);
}

function encryptDerivationPath(derivationPath, hdPassphrase) {
  var serializedDerivationPath = cbor.encode(new CborIndefiniteLengthArray(derivationPath));
  return chacha20poly1305Encrypt(serializedDerivationPath, hdPassphrase, Buffer.from('serokellfore'));
}

function decryptDerivationPath(addressPayload, hdPassphrase) {
  var decipheredDerivationPath = chacha20poly1305Decrypt(addressPayload, hdPassphrase, Buffer.from('serokellfore'));

  try {
    return cbor.decode(Buffer.from(decipheredDerivationPath));
  } catch (err) {
    throw new Error('incorrect address or passphrase');
  }
}

module.exports = {
  derivePublic: derivePublic,
  derivePrivate: derivePrivate,
  sign: sign,
  verify: verify,
  mnemonicToRootKeypair: mnemonicToRootKeypair,
  decodePaperWalletMnemonic: decodePaperWalletMnemonic,
  xpubToHdPassphrase: xpubToHdPassphrase,
  packAddress: packAddress,
  unpackAddress: unpackAddress,
  isValidAddress: isValidAddress,
  cardanoMemoryCombine: cardanoMemoryCombine,
  blake2b: blake2b,
  base58: base58,
  scrypt: scrypt,
  toPublic: toPublic,
  _mnemonicToSeedV1: mnemonicToSeedV1,
  _seedToKeypairV1: seedToKeypairV1,
  _mnemonicToSeedV2: mnemonicToSeedV2,
  _seedToKeypairV2: seedToKeypairV2,
  _sha3_256: sha3_256,
  _chacha20poly1305Decrypt: chacha20poly1305Decrypt,
  _chacha20poly1305Encrypt: chacha20poly1305Encrypt
};