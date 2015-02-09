'use strict';

var jsonwebtoken = require('jsonwebtoken');
var encrypt = require('./lib').encrypt;
var decrypt = require('./lib').decrypt;
var onHeaders = require('on-headers');

var errCodes = {
    INVALID_TOKEN: "EINVALIDCSRF"
};

function isLoggedIn(req) {
    return req.user ? true : false;
}

function toString(x) {
    return x === undefined ? 'undefined' : ( typeof x === 'string' ? x : JSON.stringify(x) );
}

/**
 * Constructs a jwt which would be dropped in res headers on every outgoing response.
 *
 * 1. Construct the token.
 *      Format (for logged in cases): userAgent:payerId
 *      Format (for non logged in cases): userAgent
 *
 * 2. Encrypt the token using ppcryptutils module, with a secret, mackey provided in options
 *
 * 3. Take encrypted value from step #2 and use jsonwebtoken.encode.
 *    If options does not have expiresInMinutes, its defaulted to 20mins.
 *
 *
 * 4. Set it in req.headers['x-csrf-jwt']
 *
 * 5. return result from from step #3.
 *
 *
 *
 *
 * @param options   {secret:*, macKey: *, expiresInMinutes: number}
 * @returns {Function}
 */
function create(options, req) {
    var payload;
    var expiry;

    if (options.expiresInMinutes) {
        expiry = options.expiresInMinutes;
    } else {
        //Set expiry to 20 mins from current time.
        expiry = 20;
    }

    var data = {
        uid: isLoggedIn(req) ? toString(req.user.encryptedAccountNumber) : 'not_logged_in'
    };

    payload = JSON.stringify(data);

    var encryptedPayload = {
        token: encrypt(options.secret, options.macKey, payload)
    };

    var jwtOptions = {
        expiresInMinutes: expiry
    };

    var jwtCsrf = jsonwebtoken.sign(encryptedPayload, options.secret, jwtOptions);

    return jwtCsrf;
}

/**
 * Verifies JWT token in req headers
 * ----------------------------------------
 *
 * 1. If the request is POST, then get the jwt from headers['x-csrf-jwt]. If token is not present
 *    then send a 401 response.
 *
 * 2. Try decoding JWT. JWT decoding logic will throw error if the payload does not match the encrypted value.
 *    JWT is a self verifying token. If decoding throws error then send a 401.
 *
 * 3. If this is a logged in user, decrypt the payload. For logged in case decrypted payload will be of the form
 *    user-agent:payerId.
 *
 *    Verify payerId from above decrypted value with the user's encrypted payerid.
 *
 * 4. Additionally for both logged in and not authenticated user, match user agent as a additional level of security.
 *
 * Takes a callback. callback will be called with err if there is any error in decryption. Or else it will be called
 * with callback(null, result). result could be true or false depending on whether validation succeeds or fails.
 *
 * @param options {secret:*, macKey: *}
 *
 */


function validate(options, req, callback) {

    var token = req.headers && req.headers['x-csrf-jwt'];

    function makeError(code, msg) {
        var e = new Error(msg);
        e.code = code;
        return e;
    }

    //If the jwtToken is not send in header, then send a 401.
    if (!token) {
        return callback(makeError('MISSING_TOKEN', 'missing token header'), false);
    }

    var secret = options.secret;

    //If token is invalid this would throw error. We catch it and send 401 response.
    jsonwebtoken.verify(token, secret, function (err, payload) {
        if (err) {
            err.code = 'VERIFY_FAILED';
            return callback(err);
        }
        var data;

        try {
            var decryptedPayload = decrypt(secret, options.macKey, payload.token);
            data = JSON.parse(decryptedPayload);
        } catch (err) {
            err.code = 'DECRYPT_EXCEPTION';
            return callback(err);
        }

        if (!data) {
            return callback(makeError('DECRYPT_FAILED', 'decrypt token failed'), false);
        }

        //If this is a authenticated user, then verify the payerId in jwtToken with payerId in req.user.
        if (isLoggedIn(req)) {
            //Check payerId in token
            var inputPayerId = data.uid;
            var userPayerId = toString(req.user.encryptedAccountNumber);
            if (inputPayerId === 'not_logged_in') {
                return callback(makeError('NOT_LOGGED_IN_TOKEN',
                    'not logged in token vs user [' + userPayerId + ']'), false);
            }
            else if (inputPayerId !== userPayerId) {
                return callback(makeError('DIFF_PAYERID',
                    'diff payerId [' + inputPayerId + '] vs [' + userPayerId + ']'), false);
            }
        }

        return callback(null, true);
    });
}

module.exports = {

    errCodes: errCodes,
    create: create,
    validate: validate,

    middleware: function (options) {
        return function (req, res, next) {
            //Set jwt in request headers on response out.
            onHeaders(res, function () {
                var jwtCsrf = create(options, req);
                res.setHeader('x-csrf-jwt', jwtCsrf);
            });

            //Validate JWT on incoming request.
            if (req.method !== 'GET' && req.method !== 'HEAD') {
                validate(options, req, function (err, result) {
                    if (err || !result) {
                        res.status(401);
                        var invalidErr = new Error('Invalid CSRF token: ' + err.message);
                        invalidErr.code = errCodes.INVALID_TOKEN + '_' + err.code;
                        invalidErr.details = err.message;
                        return next(invalidErr);
                    }
                    next();
                });
            }
            else {
                next();
            }
        };
    }

};
