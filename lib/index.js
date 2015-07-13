'use strict';

var ppcryptutils = require('cryptutils-paypal');

function encrypt(encryptionKey, macKey, text) {
    var result;

    var ppcrypto = new ppcryptutils({ // eslint-disable-line new-cap
        encryptionAlgorithm: 'desx',
        macAlgorithm: 'sha1',
        encryptionKey: encryptionKey,
        macKey: macKey
    });

    ppcrypto.sealAndEncode(new Buffer(text), function(encrypted_text) {
        result = encrypted_text;
    });

    return result;
}

function decrypt(encryptionKey, macKey, encrypted_text) {
    var result;

    var ppcrypto = new ppcryptutils({ // eslint-disable-line new-cap
        encryptionAlgorithm: 'desx',
        macAlgorithm: 'sha1',
        encryptionKey: encryptionKey,
        macKey: macKey
    });

    ppcrypto.decodeAndUnseal(encrypted_text, function(text) {
        result = text.toString();
    });

    return result;
}

module.exports = {
    encrypt: encrypt,
    decrypt: decrypt
};
