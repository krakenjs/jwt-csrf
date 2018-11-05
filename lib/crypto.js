'use strict';

var crypto = require('crypto');

function encrypt(key, text){
  var IV = new Buffer(crypto.randomBytes(16));
  var cipher = crypto.createCipheriv('aes-256-ctr', key, IV)
  var crypted = cipher.update(text,'utf8','hex')
  crypted += cipher.final('hex');
  return crypted;
}

function decrypt(key, text){
  var IV = new Buffer(crypto.randomBytes(16));
  var decipher = crypto.createDecipher('aes-256-ctr', key, IV)
  var dec = decipher.update(text,'hex','utf8')
  dec += decipher.final('utf8');
  return dec;
}

module.exports = {
    encrypt: encrypt,
    decrypt: decrypt
};