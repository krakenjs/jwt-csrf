'use strict';

var crypto = require('crypto');

function encrypt(key, text){
  var cipher = crypto.createCipher('aes-256-ctr', key)
  var crypted = cipher.update(text,'utf8','hex')
  crypted += cipher.final('hex');
  return crypted;
}

function decrypt(key, text){
  var decipher = crypto.createDecipher('aes-256-ctr', key)
  var dec = decipher.update(text,'hex','utf8')
  dec += decipher.final('utf8');
  return dec;
}

module.exports = {
    encrypt: encrypt,
    decrypt: decrypt
};