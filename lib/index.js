'use strict';

var jsonwebtoken = require('jsonwebtoken');
var onHeaders = require('on-headers');
var uuid = require('node-uuid');
var encrypt = require('./crypto').encrypt;
var decrypt = require('./crypto').decrypt;
var util = require('util');
var _ = require('underscore');
var crypto = require('crypto');

var DEFAULT_EXPIRATION_IN_MINUTES = 60;
var DEFAULT_HEADER_NAME = 'x-csrf-jwt';
var DEFAULT_CSRF_DRIVER = 'DOUBLE_SUBMIT';

// Some quick type testing methods
var toString = Object.prototype.toString;
var isRegExp = function(obj) { return !!/object RegExp/.exec(toString.apply(obj)); }
var isString = function(obj) { return !!/object String/.exec(toString.apply(obj)); }
var isArray = function(obj) { return !!/object Array/.exec(toString.apply(obj)); }

/*
    CSRF Error
    ----------

    A custom CSRF Error specifically for cases when we want to throw a 301 to the user's browser.
    Everything else is considered an unhandled error.
 */

function CSRFError(message) {
    this.message = this.code = 'EINVALIDCSRF_' + message;
}

util.inherits(CSRFError, Error);

/*
    Hash
    ----

    Hash a string using sha256
 */

function hash(secret, text) {
    return crypto.createHmac('sha256', secret).update(text).digest('hex');
}

/*
    Resolve Domain
    --------------

    Determine the current domain
 */

function resolveDomain(req) {
    var host = req.get('host'); // Ex: "mysite.com:8000"
    var truncateAt = host.indexOf(':');
    var domain = host.substr(0, truncateAt > -1 ? truncateAt : host.length); // Ex: "mysite.com"

    return '.' + domain;
}


/*
    JWT
    ---

    An abstraction on top of JWT which also handles serialization/deserialization and encryption/decryption

    The final token looks something like:

    [JWT-SIGNED [ENCRYPTED [JSON SERIALIZED [JS OBJECT]]]]

    These methods just handle creating and unpacking this object.

    * pack: serialize, encrypt and sign a javascript object token

    * unpack: verify, decrypt and deserialize an jwt token
 */

var JWT = {

    pack: function(token, options) {

        // Attempt to serialize and encrypt the token
        var encryptedToken = {
            token: encrypt(options.secret, JSON.stringify(token))
        };

        // Then sign it using jsonwebtoken
        return jsonwebtoken.sign(encryptedToken, options.secret, {
            expiresInMinutes: options.expiresInMinutes || DEFAULT_EXPIRATION_IN_MINUTES
        });
    },

    unpack: function(token, options) {

        var encryptedPayload;

        try {

            // Verify the json token
            encryptedPayload = jsonwebtoken.verify(token, options.secret);
        }
        catch (err) {

            // If there's no message, it's probably some weird unhandled error
            if (!err.message) {
                throw err;
            }

            // Normalize 'some error message' to 'SOME_ERROR_MESSAGE'
            throw new CSRFError(err.message.substring(0, 25).replace(/ /, '_').toUpperCase());
        }

        // Attempt to decrypt and deserialize the token
        return JSON.parse(decrypt(options.secret, encryptedPayload.token));
    }
};



/*
    PERSISTENCE DRIVERS
    -------------------

    Drivers for writing and reading to 'persistence' layers, e.g. headers or cookies

    * drop: a user defined method which drops the encrypted jwt token to the persistence layer of choice

    * retrieve: a user defined method which reads the encrypted jwt token from the persistence layer of choice
 */

var PERSISTENCE_DRIVERS = {

    header: {
        drop: function(req, res, options, jwtToken) {
            var headerName = options.headerName || DEFAULT_HEADER_NAME;

            res.setHeader(headerName, jwtToken);
            res.setHeader(headerName + '-hash', hash(options.secret, jwtToken));
        },

        retrieve: function(req, res, options) {
            var headerName = options.headerName || DEFAULT_HEADER_NAME;

            var jwtToken = req.headers[headerName];
            var jwtTokenBody = req.body && req.body.meta && req.body.meta[headerName];

            if (!jwtToken && jwtTokenBody) {

                var jwtTokenHash = req.headers[headerName + '-hash'];

                if (!jwtTokenHash) {
                    throw new CSRFError('BODY_CSRF_HASH_HEADER_MISSING');
                }

                if (jwtTokenHash !== hash(options.secret, jwtTokenBody)) {
                    throw new CSRFError('BODY_CSRF_HASH_MISMATCH');
                }

                jwtToken = jwtTokenBody;
            }

            return jwtToken;
        }
    },

    cookie: {
        drop: function(req, res, options, jwtToken) {

            var secure = Boolean(process.env.DEPLOY_ENV || req.protocol === 'https');
            var expires = Date.now() + (1000 * 60 * 60 * 24 * 7); // 1 week

            res.cookie(options.headerName || DEFAULT_HEADER_NAME, jwtToken, {
                secure: secure,
                httpOnly: true,
                domain: options.getCookieDomain ? options.getCookieDomain(req) : resolveDomain(req),
                expires: new Date(expires),
                encryptName: true,
                encryptValue: false
            });
        },

        retrieve: function(req, res, options) {
            return req.cookies[options.headerName || DEFAULT_HEADER_NAME];
        }
    }
};


/*
    CSRF DRIVERS
    ------------

    Drivers for generating and verifying jwt tokens.

    The process of retrieving, decrypting and dropping the tokens is abstracted, so
    we can just deal with simple javascript objects.

    * persist: a mapping of persistence layers we want to enable for the given csrf mode

    * generate: a user defined method which generates and returns the token (a javascript object)
                with everything needed to verify later

    * verify: a user defined method which recieves the token(s) on inbound requests, and throws a CSRFError if there
              is a verification problem. This later manifests as a 401 response to the browser.
 */

var CSRF_DRIVERS = {

    AUTHED_TOKEN: {

        persist: {
            cookie: false,
            header: true
        },

        generate: function(req, res, options) {

            return {
                uid: options.getUserToken(req)
            };
        },

        verify: function(req, res, options, tokens) {

            // tokens.header will always be an object
            if (Object.keys(tokens.header).length === 0) {
                throw new CSRFError('TOKEN_NOT_IN_HEADER');
            }

            if (options.getUserToken(req)) {

                if (!tokens.header.uid) {
                    throw new CSRFError('TOKEN_PAYERID_MISSING');
                }

                if (tokens.header.uid !== options.getUserToken(req)) {
                    throw new CSRFError('TOKEN_PAYERID_MISMATCH');
                }
            }
        }
    },

    DOUBLE_SUBMIT: {

        persist: {
            cookie: true,
            header: true
        },

        generate: function(req, res, options) {

            return {
                id: uuid.v4()
            }
        },

        verify: function(req, res, options, tokens) {

            if (!Object.keys(tokens.header).length) {
                throw new CSRFError('TOKEN_NOT_IN_HEADER');
            }

            if (!tokens.header.id) {
                throw new CSRFError('ID_NOT_IN_HEADER');
            }

            if (!tokens.cookie.id) {
                throw new CSRFError('ID_NOT_IN_COOKIE');
            }

            if (tokens.header.id !== tokens.cookie.id) {
                throw new CSRFError('HEADER_COOKIE_ID_MISMATCH');
            }
        }
    },

    AUTHED_DOUBLE_SUBMIT: {

        persist: {
            cookie: true,
            header: true
        },

        generate: function(req, res, options) {

            return {
                uid: options.getUserToken(req),
                id: uuid.v4()
            }
        },

        verify: function(req, res, options, tokens) {

            if (!Object.keys(tokens.header).length) {
                throw new CSRFError('TOKEN_NOT_IN_HEADER');
            }

            try {

                // First do the cookie check

                if (!Object.keys(tokens.cookie).length) {
                    throw new CSRFError('TOKEN_NOT_IN_COOKIE');
                }

                if (!tokens.header.id) {
                    throw new CSRFError('ID_NOT_IN_HEADER');
                }

                if (!tokens.cookie.id) {
                    throw new CSRFError('ID_NOT_IN_COOKIE');
                }

                if (tokens.header.id !== tokens.cookie.id) {
                    throw new CSRFError('HEADER_COOKIE_MISMATCH');
                }

            } catch(err) {

                // Then if this fails, fall back to payerid

                if (err instanceof CSRFError) {

                    if (options.getUserToken(req)) {

                        if (!tokens.header.uid) {
                            throw new CSRFError('TOKEN_PAYERID_MISSING');
                        }

                        if (tokens.header.uid !== options.getUserToken(req)) {
                            throw new CSRFError('TOKEN_PAYERID_MISMATCH');
                        }
                    }

                } else {
                    throw err;
                }
            };
        }
    }
};


/*
    Generate
    --------

    Generate an object containing packed jwt tokens for each persistence layer:

    {
        header: 'xxxxxxxxx',
        cookie: 'yyyyyyyyy'
    }
 */


function generate(req, res, options) {

    // Determine which driver to use to generate the token
    var csrfDriver = options.csrfDriver || DEFAULT_CSRF_DRIVER;
    var driver = CSRF_DRIVERS[csrfDriver];

    // Generate the token from our chosen driver
    var token = driver.generate(req, res, options);

    // Build a collection of jwt tokens
    var jwtTokens = {};

    // Loop through each persistance type for the current csrfDriver
    Object.keys(driver.persist).forEach(function(persistenceDriver) {

        // Check if this persistence type is enabled for the current csrfDriver
        if (driver.persist[persistenceDriver]) {

            // Add the csrfDriver and persistenceDriver into the token so we can verify them on inbound requests
            var payload = _.extend({
                csrfDriver: csrfDriver,
                persistenceDriver: persistenceDriver
            }, token);

            // Pack and save our token
            jwtTokens[persistenceDriver] = JWT.pack(payload, options);
        }
    });

    return jwtTokens;
}


/*
    Drop
    ----

    Generate new jwt tokens and drop them to the persistence layers (response headers/cookies).

    The persistence layers used will be those valid for the passed csrfType.
 */

function drop(req, res, options) {

    // Generate the jwt tokens we need to drop
    var jwtTokens = generate(req, res, options);

    // Add them to res.locals for other middlewares to consume
    res.locals.csrfJwtTokens = jwtTokens;

    // Loop through each persistence type for the current csrf driver
    Object.keys(jwtTokens).forEach(function(persistenceDriver) {

        // Get the individual token
        var jwtToken = jwtTokens[persistenceDriver];

        // Drop the token to the persistence layer
        PERSISTENCE_DRIVERS[persistenceDriver].drop(req, res, options, jwtToken);
    });
}


/*
    Read
    ----

    Read and unpack a token, given a persistence driver name.

    e.g. giving 'header' would read the encrypted cookie from req.headers, then decrypt/unpack it.

    Returns an unpacked token, e.g.

    {
        uid: XXXX
    }
 */

function read(req, res, options, persistenceDriver) {

    var jwtToken = PERSISTENCE_DRIVERS[persistenceDriver].retrieve(req, res, options);

    if (!jwtToken) {
        return {};
    }

    var token = JWT.unpack(jwtToken, options);

    // Default the persistenceDriver to 'header' (for legacy tokens -- can remove this later)
    token.persistenceDriver = token.persistenceDriver || 'header';

    // Validate that it has the correct persistenceDriver
    if (token.persistenceDriver !== persistenceDriver) {
        throw new CSRFError('GOT_' + token.persistenceDriver.toUpperCase() + '_EXPECTED_' + persistenceDriver.toUpperCase());
    }

    return token;
}


/*
    Retrieve
    --------

    Retrieve and unpack all tokens from the persistence layer for our driver.

    Returns a mapping of unpacked tokens, e.g.

    {
        header: {
            uid: XXX
        },
        cookie: {
            uid: YYY
        }
    }
 */

function retrieve(req, res, options, csrfDriver) {

    var driver = CSRF_DRIVERS[csrfDriver];

    // Build an object of tokens
    var tokens = {};

    // Loop over each persistence mechanism and build an object of decrypted tokens
    Object.keys(driver.persist).forEach(function(persistenceDriver) {

        // We only want tokens which are valid for the current csrf driver
        if (driver.persist[persistenceDriver]) {
            tokens[persistenceDriver] = read(req, res, options, persistenceDriver);
        }
    });

    return tokens
}


/*
    Verify
    ------

    Verify all tokens from the relevant persistence layers.

    Throw a CSRFError on any verification failures.
 */

function verify(req, res, options) {

    // First we need to get the header first to figure out which csrfDriver we need to verify
    var headerToken = read(req, res, options, 'header');

    var csrfDriver = (headerToken.csrfDriver && CSRF_DRIVERS[headerToken.csrfDriver]) ? headerToken.csrfDriver : DEFAULT_CSRF_DRIVER;

    // Now we know the mode, we can retrieve the tokens from all persistence types for this mode
    var tokens = retrieve(req, res, options, csrfDriver);

    // Now we have all of the tokens, pass to the driver to verify them
    return CSRF_DRIVERS[csrfDriver].verify(req, res, options, tokens);
}


module.exports = {

    CSRFError: CSRFError,

    getHeaderToken: function(req, res, options) {

        var csrfDriver = options.csrfDriver || DEFAULT_CSRF_DRIVER;
        var token = CSRF_DRIVERS[csrfDriver].generate(req, res, options);

        var payload = _.extend({
            csrfDriver: csrfDriver,
            persistenceDriver: 'header'
        }, token);

        return JWT.pack(payload, options);
    },

    middleware: function (options) {

        var csrfDriver = options.csrfDriver || DEFAULT_CSRF_DRIVER;

        if (/AUTHED_TOKEN|AUTHED_DOUBLE_SUBMIT/.test(csrfDriver)) {
            if (!options.getUserToken) {
                throw new Error('csrf-jwt - getUserToken option required for AUTHED_TOKEN and AUTHED_DOUBLE_SUBMIT drivers');
            }
        }

        var excludeUrls = options.excludeUrls || [];

        if (options.baseUrl) {
            excludeUrls = excludeUrls.map(function (route) {
                return options.baseUrl + route;
            });
        }

        return function (req, res, next) {

            // An array to show us the matching excluded urls. If this array
            // contains any values, we should skip out and allow.
            var urlToTest;
            var excludeTheseUrls;

            // Set JWT in header and cookie before response goes out
            // This is done in onHeaders since we need to wait for any service
            // calls (e.g. auth) which may otherwise change the state of
            // our token
            onHeaders(res, function () {
                drop(req, res, options);
            });

            // Skip out on non mutable REST methods
            if (/GET|HEAD|OPTIONS|TRACE/i.test(req.method)) {
                return next();
            }

            if (excludeUrls.length) {

                // We only want to verify certain requests
                urlToTest = req.originalUrl;
                excludeTheseUrls = excludeUrls.filter(function (excludeUrl) {

                    if (isArray(excludeUrl)) {

                        var expression = excludeUrl[0];
                        var options = excludeUrl[1] || '';

                        return new RegExp(expression, options).test(urlToTest);
                    }
                    else if (isRegExp(excludeUrl)) {

                        return excludeUrl.test(urlToTest);
                    }
                    else if (isString(excludeUrl)) {

                        // Setup some variables: regExp for regExp testing and
                        // some bits to use in the indexOf comparison
                        var regExp = new RegExp(excludeUrl);
                        var bits = ((urlToTest || '').split(/[?#]/, 1))[0];

                        // Test regular expression strings first
                        if (regExp.exec(urlToTest)) {
                            return true;
                        }

                        // If we are still here, test the legacy indexOf case
                        return excludeUrls.indexOf(bits) !== -1;
                    }
                });

                // If the filter above actually found anything, that means
                // we matched on the possible exclusions. In this case, var's
                // just pop out and var the next piece of middleware have a
                // shot.
                if (excludeTheseUrls.length) {
                    return next();
                }
            }

            try {
                verify(req, res, options);
            }
            catch (err) {

                // If we get a CSRFError, we can send a 401 to trigger a retry,
                // otherwise the error will be unhandled
                if (err instanceof CSRFError) {
                    res.status(401);
                }

                return next(err);
            }

            return next();
        };
    }
};
