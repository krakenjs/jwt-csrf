'use strict';

var jsonwebtoken = require('jsonwebtoken');
var onHeaders = require('on-headers');
var bb = require('bluebird');
var uuid = require('node-uuid');

var encrypt = require('./lib').encrypt;
var decrypt = require('./lib').decrypt;

var DEFAULT_EXPIRATION_IN_MINUTES = 20;

// --- OLD CODE START ---
function toString(x) {
    return x === undefined ? 'undefined' : ( typeof x === 'string' ? x : JSON.stringify(x) );
}
// --- OLD CODE END ---

/**
 * For normalizing errors by adding a code and message
 *
 * @param {String} code - An error code (Ex: "TOKEN_EXPIRED")
 * @param {String} message - An error message (Ex: "Token was expired on 1/1/2015")
 * @returns {Error} - Returns a normalized error
 */
function createError(code, message) {
    var error = new Error(message);
    error.code = code;
    return error;
}

/**
 * Resolves a cookie's domain based on environment variables, localhost, etc.
 *
 * @param {Object} req - Express request object
 * @returns {String} - A resolved domain for a cookie (Ex: '.paypal.com')
 */
function resolveDomain(req) {
    var host, domain;

    if (process.env.DEPLOY_ENV) {
        return '.paypal.com';
    }

    host = req.get('host');
    domain = host.substr(0, host.indexOf(':') || host.length);

    return domain !== 'localhost' && domain !== '127.0.0.1' ? '.paypal.com' : domain;
}

/**
 * Creates a token using a provided payload, secret, and macKey
 *
 * @param {Object} options - Must contain "secret", "macKey"
 * @param {Object} payload - Must contain something. Ideally, a cryptographically-strong key.
 * @returns {String} - A sealed token (JWT)
 */
function create(options, payload) {
    var encryptedPayload = {
        token: encrypt(options.secret, options.macKey, JSON.stringify(payload))
    };

    var jwtOptions = {
        expiresInMinutes: options.expiresInMinutes ? options.expiresInMinutes : DEFAULT_EXPIRATION_IN_MINUTES
    };

    return jsonwebtoken.sign(encryptedPayload, options.secret, jwtOptions);
}

/**
 * Creates a cookie and header token using the same uuid, but different types
 *
 * @param {Object} options - Must contain "secret" and "macKey"
 * @param {Object} res - Express response object
 * @returns {Object} - Has signed cookie and header tokens
 */
function createTokens(options, res) {
    var tokens = {};
    var id = res.locals.jwtuuid = res.locals.jwtuuid || uuid.v4();

    ['cookie', 'header'].forEach(function (type) {
        tokens[type] = create(options, {
            id: id,
            type: type
        });
    });

    return tokens;
}

/**
 * Checks that a JWT is valid, not expired, and is able to be decrypted.
 *
 * @param {String} token - A sealed token (JWT)
 * @param {Object} options - Must contain "secret" and "macKey"
 * @returns {Promise} - Returns a promise
 */
function verifyJWT(token, options) {
    return new bb.Promise(function (resolve, reject) {
        jsonwebtoken.verify(token, options.secret, function (err, payload) {
            var data;

            if (err) {
                // Normalizing error code
                err.code = err.message ? err.message.substring(0, 25).replace(/ /, '_').toUpperCase() : 'VERIFY_FAILED';

                // Re-writing JWT_EXPIRED error to include time it expired
                if (err.code === 'JWT_EXPIRED') {
                    err.message = 'token expired at ' + err.expiredAt;
                    err.code = 'TOKEN_EXPIRED';
                }

                return reject(err);
            }

            // Attempting to decrypt payload (JSON.parse throws errors willy nilly :|)
            try {
                var decryptedPayload = decrypt(options.secret, options.macKey, payload.token);
                data = JSON.parse(decryptedPayload);
            } catch (err) {
                err.code = 'DECRYPT_EXCEPTION';
                return reject(err);
            }

            return resolve(data);
        });
    });
}

/**
 * Checks that a token exists and has the correct type
 *
 * @param {String} token - A sealed token (JWT)
 * @param {String} type - A token type (Ex: "header", "cookie")
 * @returns {Boolean} - Returns true if valid, false if invalid
 */
function isValidTokenType(token, type) {
    return token && token.type === type;
}

/**
 * Checks if an old JWT token is valid using these checks:
 * 1. If the header token exists
 * 2. If the token is a valid JWT
 * 3. If the token has not expired
 * 4. If the user is logged in and does not have a "not_logged_in" token.
 * 5. If the user is logged in and their encrypted account number matches the token
 *
 * If all of those checks pass, the JWT token is valid.
 *
 * @param {Object} options - Must contain "secret" and "macKey"
 * @param {Object} req - Express request object
 * @returns {Promise}
 */
function validateOldToken(options, req) {
    var token = req.headers && req.headers['x-csrf-jwt'];
    var isLoggedIn = req && req.user;

    return verifyJWT(token, options).then(function (headerToken) {

        // If this is a authenticated user, then verify the payerId in jwtToken with payerId in req.user.
        if (isLoggedIn) {

            // Check payerId in token
            var inputPayerId = headerToken.uid;
            var userPayerId = toString(req.user.encryptedAccountNumber);

            if (inputPayerId === 'not_logged_in') {
                throw createError('NOT_LOGGED_IN_TOKEN', 'not logged in token vs user [' + userPayerId + ']');
            } else if (inputPayerId !== userPayerId) {
                throw createError('DIFF_PAYERID', 'diff payerId [' + inputPayerId + '] vs [' + userPayerId + ']');
            }
        }

        return true;
    });
}

/**
 * Checks if a JWT is valid by using these checks:
 * 1. If the header and cookie tokens exist
 * 2. If the tokens are valid JWTs
 * 3. If the tokens have not expired
 * 4. If the decrypted tokens match
 * 5. If the tokens have the correct type (Ex: Header token with a type of "header")
 *
 * If all of those checks pass, the JWT tokens are valid.
 *
 * @param {Object} options - Must contain "secret" and "macKey"
 * @param {Object} req - Express request object
 * @returns {Promise}
 */
function validate(options, req) {

    var header = req.headers && req.headers['x-csrf-jwt'];
    var cookie = req.cookies && req.cookies['csrf-jwt'];

    return bb.try(function () {

        // Being extra granular with our errors here (sorry)
        if (!header && !cookie) {
            throw createError('MISSING_TOKENS', 'missing both tokens');
        }

        if (!header) {
            throw createError('MISSING_HEADER', 'missing header token');
        }

        if (!cookie) {
            throw createError('MISSING_COOKIE', 'missing cookie token');
        }

        return bb.all([
            verifyJWT(header, options),
            verifyJWT(cookie, options)
        ]).spread(function (headerToken, cookieToken) {

            // Fail fast if the header and cookie tokens could not be decrypted
            if (!headerToken || !cookieToken) {
                throw createError('DECRYPT_FAILED', 'failed to decrypt token');
            }

            // Check that the tokens are equivalent
            if (headerToken.id !== cookieToken.id) {
                throw createError('TOKEN_MISMATCH', 'tokens did not match');
            }

            // Check that the token types are correct
            if (!isValidTokenType(headerToken, 'header') || !isValidTokenType(cookieToken, 'cookie')) {
                throw createError('INCORRECT_TOKEN_TYPE', 'incorrect token type');
            }

            return true;
        });
    });
}

module.exports = {

    create: create,
    createTokens: createTokens,
    validate: validate,
    validateOldToken: validateOldToken,

    middleware: function (options) {

        var excludeUrls = options.excludeUrls || [];

        if (options.baseUrl) {
            excludeUrls = excludeUrls.map(function (route) {
                return options.baseUrl + route;
            });
        }

        return function (req, res, next) {

            // Set JWT in header and cookie before response goes out
            onHeaders(res, function () {
                var tokens = createTokens(options, res);

                // Set CSRF as a custom response header
                res.setHeader('x-csrf-jwt', tokens.header);

                // Set an encrypted cookie (the name "csrf-jwt" is encrypted, same with the value)
                res.encryptedCookie('csrf-jwt', tokens.cookie, {
                    secure: process.env.DEPLOY_ENV ? true : (req.protocol === 'https' ? true : false),
                    httpOnly: true,
                    domain: resolveDomain(req),
                    expires: new Date(Date.now() + DEFAULT_EXPIRATION_IN_MINUTES * 60 * 1000),
                    encryptName: true,
                    encryptValue: false
                });
            });

            function handleError(err) {
                res.status(401);

                var invalidErr = new Error('Invalid CSRF token: ' + err.message);
                invalidErr.code = 'EINVALIDCSRF_' + err.code;
                invalidErr.details = err.message;

                return next(invalidErr);
            }

            // Validate JWT on incoming request.
            if (req.method !== 'GET' && req.method !== 'HEAD' && excludeUrls.indexOf(req.originalUrl) === -1) {
                return bb.any([
                    validate(options, req),
                    validateOldToken(options, req)
                ]).then(function () {
                    next();
                }).catch(function (err) {
                    // lol
                    if (err instanceof Array) {
                        err = err[0];
                    }

                    res.status(401);

                    err.code = err.code || 'DECRYPT_FAILED';
                    err.message = err.message || 'decrypt token failed';

                    var invalidErr = new Error('Invalid CSRF token: ' + err.message);
                    invalidErr.code = 'EINVALIDCSRF_' + err.code;
                    invalidErr.details = err.message;

                    return next(invalidErr);
                });
            }

            next();
        };
    }

};
