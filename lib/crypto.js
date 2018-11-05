'use strict';

var crypto = require('crypto');

function encrypt(key, text) {
  const hashedAccessKey = crypto.createHash('sha256').update(key).digest('hex');
  const keyBuffer = Buffer.from(hashedAccessKey, 'hex');
  const iv = new Buffer(crypto.randomBytes(16));
  var cipher = crypto.createCipheriv('aes-256-ctr', keyBuffer, iv)
  var crypted = cipher.update(text, 'utf8', 'hex')
  crypted += cipher.final('hex');
  return `${iv.toString('hex')}:${crypted.toString()}`;
}

function decrypt(key, text) {
  const hashedAccessKey = crypto.createHash('sha256').update(key).digest('hex');
  const keyBuffer = Buffer.from(hashedAccessKey, 'hex');
  const textParts = text.split(':');
  const iv = new Buffer(textParts.shift(), 'hex');
  const encryptedText = new Buffer(textParts.join(':'), 'hex');
  var decipher = crypto.createDecipheriv('aes-256-ctr', keyBuffer, iv)
  var dec = decipher.update(text, 'hex', 'utf8')
  dec += decipher.final('utf8');
  return dec;
}

module.exports = {
  encrypt: encrypt,
  decrypt: decrypt
};
