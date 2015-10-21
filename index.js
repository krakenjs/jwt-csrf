'use strict';

var jsonwebtoken = require('jsonwebtoken');
var onHeaders = require('on-headers');
var uuid = require('node-uuid');
var encrypt = require('./lib').encrypt;
var decrypt = require('./lib').decrypt;
var util = require('util');
var _ = require('underscore');

var DEFAULT_EXPIRATION_IN_MINUTES = 60;
var DEFAULT_HEADER_NAME = 'x-csrf-jwt';
var DEFAULT_CSRF_DRIVER = 'AUTHED_TOKEN';


/*
    CSRF Error
    ----------

    A custom CSRF Error specifically for cases when we want to throw a 301 to the user's browser.
    Everything else is considered an unhandled error.
 */

function CSRFError(message) {
    this.message = 'EINVALIDCSRF_' + message;
}

util.inherits(CSRFError, Error);



/*
    Resolve Domain
    --------------

    Determine the current domain
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
            token: encrypt(options.secret, options.macKey, JSON.stringify(token))
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
        return JSON.parse(decrypt(options.secret, options.macKey, encryptedPayload.token));
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
            res.setHeader(options.headerName || DEFAULT_HEADER_NAME, jwtToken);
        },

        retrieve: function(req, res, options) {
            return req.headers[options.headerName || DEFAULT_HEADER_NAME];
        }
    },

    cookie: {
        drop: function(req, res, options, jwtToken) {

            var secure = Boolean(process.env.DEPLOY_ENV || req.protocol === 'https');
            var expires = Date.now() + (1000 * 60 * 60 * 24 * 7); // 1 week

            res.cookie(options.headerName || DEFAULT_HEADER_NAME, jwtToken, {
                secure: secure,
                httpOnly: true,
                domain: resolveDomain(req),
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
                uid: req.user && req.user.encryptedAccountNumber
            };
        },

        verify: function(req, res, options, tokens) {

            // tokens.header will always be an object
            if (Object.keys(tokens.header).length === 0) {
                throw new CSRFError('TOKEN_NOT_IN_HEADER');
            }

            if (req.user && req.user.encryptedAccountNumber) {

                if (!tokens.header.uid) {
                    throw new CSRFError('TOKEN_PAYERID_MISSING');
                }

                if (tokens.header.uid !== req.user.encryptedAccountNumber) {
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

            if (!tokens.header.id) {
                throw new CSRFError('ID_NOT_IN_HEADER');
            }

            if (!tokens.cookie.id) {
                throw new CSRFError('ID_NOT_IN_COOKIE');
            }

            if (tokens.header.id !== tokens.cookie.id) {
                throw new CSRFError('HEADER_COOKIE_TOKEN_MISMATCH');
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
                uid: req.user && req.user.encryptedAccountNumber,
                id: uuid.v4()
            }
        },

        verify: function(req, res, options, tokens) {

            if (!Object.keys(tokens.header).length) {
                throw new CSRFError('TOKEN_NOT_IN_HEADER');
            }

            try {

                // First do the payerid check

                if (req.user && req.user.encryptedAccountNumber) {

                    if (!tokens.header.uid) {
                        throw new CSRFError('TOKEN_PAYERID_MISSING');
                    }

                    if (tokens.header.uid !== req.user.encryptedAccountNumber) {
                        throw new CSRFError('TOKEN_PAYERID_MISMATCH');
                    }
                }

            } catch(err) {

                // Then if this fails, fall back to cookie check

                if (err instanceof CSRFError) {

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
    var token = driver.generate(req, res);

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

    middleware: function (options) {

        var excludeUrls = options.excludeUrls || [];

        if (options.baseUrl) {
            excludeUrls = excludeUrls.map(function (route) {
                return options.baseUrl + route;
            });
        }

        return function (req, res, next) {

            // Set JWT in header and cookie before response goes out
            // This is done in onHeaders since we need to wait for any service calls (e.g. auth) which may
            // otherwise change the state of our token
            onHeaders(res, function () {
                drop(req, res, options);
            });

            // We only want to verify certain requests
            if (req.method === 'GET' || req.method === 'HEAD' || excludeUrls.indexOf(req.originalUrl) !== -1) {
                return next();
            }

            try {
                verify(req, res, options);
            }
            catch (err) {

                // If we get a CSRFError, we can send a 401 to trigger a retry, otherwise the error will be unhandled
                if (err instanceof CSRFError) {
                    res.status(401);
                }

                return next(err);
            }

            return next();
        };
    }
};
