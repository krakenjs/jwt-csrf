"use strict";

var crypto = require("crypto");

// https://nodejs.org/api/crypto.html#crypto_crypto_createcipher_algorithm_password_options
var defaultAlgorithm = "aes-256-ctr";
var defaultIV = crypto.randomBytes(16);

function encrypt(key, text, algorithm, iv) {
  var cipher;
  if (crypto.createCipheriv) {
    cipher = crypto.createCipheriv(
      algorithm ? algorithm : defaultAlgorithm,
      key,
      iv ? iv : defaultIV
    );
  } else {
    crypto = crypto.createCipher(defaultAlgorithm, key);
  }
  var crypted = cipher.update(text, "utf8", "hex");
  crypted += cipher.final("hex");
  return crypted;
}

function decrypt(key, text, algorithm, iv) {
  var decipher;
  if (crypto.createDecipheriv) {
    decipher = crypto.createDecipheriv(
      algorithm ? algorithm : defaultAlgorithm,
      key,
      iv ? iv : defaultIV
    );
  } else {
    crypto.createDecipher(defaultAlgorithm, key);
  }
  var dec = decipher.update(text, "hex", "utf8");
  dec += decipher.final("utf8");
  return dec;
}

module.exports = {
  encrypt: encrypt,
  decrypt: decrypt
};
