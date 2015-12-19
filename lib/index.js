'use strict';

var ppcryptutils = require('cryptutils-paypal');

function encrypt(encryptionKey, macKey, text) {
    var ppcrypto = new ppcryptutils({ // eslint-disable-line new-cap
        encryptionAlgorithm: 'desx',
        macAlgorithm: 'sha1',
        encryptionKey: encryptionKey,
        macKey: macKey
    });

    return ppcrypto.sealAndEncode(new Buffer(text)).toString();
}

function decrypt(encryptionKey, macKey, encrypted_text) {
    var ppcrypto = new ppcryptutils({ // eslint-disable-line new-cap
        encryptionAlgorithm: 'desx',
        macAlgorithm: 'sha1',
        encryptionKey: encryptionKey,
        macKey: macKey
    });

    return ppcrypto.decodeAndUnseal(encrypted_text).toString();
}

module.exports = {
    encrypt: encrypt,
    decrypt: decrypt
};
