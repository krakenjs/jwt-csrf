'use strict';

var lib = require('../lib/index');
var assert = require('chai').assert;
var jsonwebtoken = require('jsonwebtoken');
var uuid = require('node-uuid');
var jwtCsrf = require('../index');

function getTokens() {
    return {
        header: JSON.stringify({
            uuid: uuid.v4(),
            type: 'header'
        }),
        cookie: JSON.stringify({
            uuid: uuid.v4(),
            type: 'cookie'
        })
    };
}

function getSignedTokens() {
    var tokens = getTokens();

    return {
        header: jsonwebtoken.sign({
            token: lib.encrypt(SECRET, MACKEY, tokens.header)
        }, SECRET),
        cookie: jsonwebtoken.sign({
            token: lib.encrypt(SECRET, MACKEY, tokens.cookie)
        }, SECRET)
    };
}

describe('middleware', function () {

    var SECRET = 'somerandomsecret';
    var MACKEY = 'somerandommac';
    var userAgent = 'Mozilla';
    var options;
    var tokens;
    var res;

    beforeEach(function () {
        options = {
            secret: SECRET,
            macKey: MACKEY
        };
        res = {
            locals: {}
        }
        tokens = jwtCsrf.createTokens(options, res);
    });

    describe('Happy', function () {

        it('Should not validate GET requests', function (done) {

            var req = {
                method: 'GET'
            };

            var middleware = jwtCsrf.middleware(options);

            middleware(req, {}, function(err, result){
                assert(!err, 'Expect next() to be called without error');
                done();
            });
        });

        it('Should not validate HEAD requests', function (done) {

            var req = {
                method: 'HEAD'
            };

            var middleware = jwtCsrf.middleware(options);

            middleware(req, {}, function(err, result){
                assert(!err, 'Expect next() to be called without error');
                done();
            });
        });

        it('Should call next if token is verified and valid', function (done) {

            var tokens = jwtCsrf.createTokens(options, {
                locals: {}
            });

            var req = {
                headers: {
                    'x-csrf-jwt': tokens.header,
                    'user-agent': userAgent
                },
                cookies: {
                    'csrf-jwt': tokens.cookie
                }
            };

            var res = {
                status: function (statusCode) {
                    assert(!statusCode, 'Ensure there is no status code set, defaults to 200');
                }
            };

            var middleware = jwtCsrf.middleware(options);

            middleware(req, res, function(err, result){
                assert(!err, 'Expect next() to be called without error');
                done();
            });
        });

        it('Should set header and token on response out', function () {

            var res = {
                locals: {},
                status: function (statusCode) {
                    assert(!statusCode, 'Ensure there is no status code set, defaults to 200');
                },
                writeHead: function () {
                    // noop
                },
                setHeader: function (key, value) {
                    assert.equal(key, 'x-csrf-jwt', 'x-csrf-jwt header has been set');
                    assert(value, 'x-csrf-jwt header value exists');
                },
                encryptedCookie: function (key, value, options) {
                    assert.equal(key, 'csrf-jwt', 'csrf-jwt cookie has been set');
                    assert(value, 'csrf-jwt cookie value exists');
                    assert(options, 'csrf-jwt cookie options exists');
                    assert(options.httpOnly, 'csrf-jwt cookie options exists');
                }
            };

            var tokens = jwtCsrf.createTokens(options, res);

            var req = {
                headers: {
                    'x-csrf-jwt': tokens.header,
                    'user-agent': userAgent
                },
                cookies: {
                    'csrf-jwt': tokens.cookie
                },
                get: function () {
                    return 'https://www.paypal.com';
                }
            };

            var middleware = jwtCsrf.middleware(options);

            middleware(req, res, function(err, result){
                res.writeHead();
                assert(!err, 'Expect next() to be called without error');
            });
        });

    });

    describe('Unhappy', function () {

        it('Should throw a 401 if there are no tokens', function (done) {

            var tokens = jwtCsrf.createTokens(options, {
                locals: {}
            });

            var req = {
                headers: {
                    'user-agent': userAgent
                }
            };

            var res = {
                status: function (statusCode) {
                    assert.equal(statusCode, 401, 'Ensure a 401 status code was set');
                }
            };

            var middleware = jwtCsrf.middleware(options);

            middleware(req, res, function(err, result){
                assert(err, 'Expect an error to be thrown');
                assert(!result, 'Expect an error to be thrown');
                done();
            });
        });

        it('Should throw a 401 if there is only a header token', function (done) {

            var tokens = jwtCsrf.createTokens(options, {
                locals: {}
            });

            var req = {
                headers: {
                    'x-csrf-jwt': tokens.header,
                    'user-agent': userAgent
                }
            };

            var res = {
                status: function (statusCode) {
                    assert.equal(statusCode, 401, 'Ensure a 401 status code was set');
                }
            };

            var middleware = jwtCsrf.middleware(options);

            middleware(req, res, function(err, result){
                assert(err, 'Expect an error to be thrown');
                assert(!result, 'Expect an error to be thrown');
                done();
            });
        });

        it('Should throw a 401 if there is only a cookie token', function (done) {

            var tokens = jwtCsrf.createTokens(options, {
                locals: {}
            });

            var req = {
                headers: {
                    'user-agent': userAgent
                },
                cookies: {
                    'csrf-jwt': tokens.cookie
                }
            };

            var res = {
                status: function (statusCode) {
                    assert.equal(statusCode, 401, 'Ensure a 401 status code was set');
                }
            };

            var middleware = jwtCsrf.middleware(options);

            middleware(req, res, function(err, result){
                assert(err, 'Expect an error to be thrown');
                assert(!result, 'Expect an error to be thrown');
                done();
            });
        });

        it('Should throw a 401 if the header could not be decrypted', function (done) {

            var tokens = jwtCsrf.createTokens(options, {
                locals: {}
            });

            var req = {
                headers: {
                    'x-csrf-jwt': 'sometoken',
                    'user-agent': userAgent
                },
                cookies: {
                    'csrf-jwt': tokens.cookie
                }
            };

            var res = {
                status: function (statusCode) {
                    assert.equal(statusCode, 401, 'Ensure a 401 status code was set');
                }
            };

            var middleware = jwtCsrf.middleware(options);

            middleware(req, res, function(err, result){
                assert(err, 'Expect an error to be thrown');
                assert(!result, 'Expect an error to be thrown');
                done();
            });
        });

        it('Should throw a 401 if the cookie could not be decrypted', function (done) {

            var tokens = jwtCsrf.createTokens(options, {
                locals: {}
            });

            var req = {
                headers: {
                    'x-csrf-jwt': tokens.header,
                    'user-agent': userAgent
                },
                cookies: {
                    'csrf-jwt': 'sometoken'
                }
            };

            var res = {
                status: function (statusCode) {
                    assert.equal(statusCode, 401, 'Ensure a 401 status code was set');
                }
            };

            var middleware = jwtCsrf.middleware(options);

            middleware(req, res, function(err, result){
                assert(err, 'Expect an error to be thrown');
                assert(!result, 'Expect an error to be thrown');
                done();
            });
        });

        it('Should throw a 401 if the header token has a type of cookie', function (done) {

            var tokens = jwtCsrf.createTokens(options, {
                locals: {}
            });

            var req = {
                headers: {
                    'x-csrf-jwt': tokens.cookie,
                    'user-agent': userAgent
                },
                cookies: {
                    'csrf-jwt': tokens.cookie
                }
            };

            var res = {
                status: function (statusCode) {
                    assert.equal(statusCode, 401, 'Ensure a 401 status code was set');
                }
            };

            var middleware = jwtCsrf.middleware(options);

            middleware(req, res, function(err, result){
                assert(err, 'Expect an error to be thrown');
                assert(!result, 'Expect an error to be thrown');
                done();
            });
        });

        it('Should throw a 401 if the cookie token has a type of header', function (done) {

            var tokens = jwtCsrf.createTokens(options, {
                locals: {}
            });

            var req = {
                headers: {
                    'x-csrf-jwt': tokens.header,
                    'user-agent': userAgent
                },
                cookies: {
                    'csrf-jwt': tokens.header
                }
            };

            var res = {
                status: function (statusCode) {
                    assert.equal(statusCode, 401, 'Ensure a 401 status code was set');
                }
            };

            var middleware = jwtCsrf.middleware(options);

            middleware(req, res, function(err, result){
                assert(err, 'Expect an error to be thrown');
                assert(!result, 'Expect an error to be thrown');
                done();
            });
        });
    });
});

describe('create/createTokens', function () {

    var SECRET = 'somerandomsecret';
    var MACKEY = 'somerandommac';
    var userAgent = 'Mozilla';
    var req;
    var res;
    var options;

    beforeEach(function () {
        req = {
            headers: {
                'user-agent': userAgent
            }
        };
        res = {
            locals: {}
        };
        options = {
            secret: SECRET,
            macKey: MACKEY,
            expiresInMinutes: 20
        };
    });

    it('Should create a sealed header token', function (done) {

        var data = jwtCsrf.create(options, {
            type: 'header',
            id: uuid.v4()
        });

        jsonwebtoken.verify(data, SECRET, function (err, decoded) {
            var verifiedToken = JSON.parse(lib.decrypt(SECRET, MACKEY, decoded.token));
            assert.equal(verifiedToken.type, 'header', 'Must have token type of header');
            assert(verifiedToken.id, 'Should have an id');
            done();
        });
    });

    it('Should create a sealed cookie token', function (done) {

        var data = jwtCsrf.create(options, {
            type: 'cookie',
            id: uuid.v4()
        });

        jsonwebtoken.verify(data, SECRET, function (err, decoded) {
            var verifiedToken = JSON.parse(lib.decrypt(SECRET, MACKEY, decoded.token));
            assert.equal(verifiedToken.type, 'cookie', 'Must have token type of cookie');
            assert(verifiedToken.id, 'Should have an id');
            done();
        });
    });

    it('Should create a sealed header and cookie token', function (done) {

        var tokens = jwtCsrf.createTokens(options, res);

        // fuggit
        jsonwebtoken.verify(tokens.header, SECRET, function (err, decoded) {
            var verifiedToken = JSON.parse(lib.decrypt(SECRET, MACKEY, decoded.token));

            assert.equal(verifiedToken.type, 'header', 'Must have token type of header');
            assert(verifiedToken.id, 'Should have an id');

            jsonwebtoken.verify(tokens.cookie, SECRET, function (err, decoded) {
                var verifiedToken = JSON.parse(lib.decrypt(SECRET, MACKEY, decoded.token));

                assert.equal(verifiedToken.type, 'cookie', 'Must have token type of cookie');
                assert(verifiedToken.id, 'Should have an id');

                done();
            });
        });
    });
});

describe('validate', function () {

    var SECRET = 'somerandomsecret';
    var MACKEY = 'somerandommac';
    var userAgent = 'Mozilla';
    var token = {
        id: uuid.v4()
    };
    var res = {
        locals: {}
    };

    var options;
    var tokens;

    beforeEach(function () {
        options = {
            secret: SECRET,
            macKey: MACKEY
        };
        tokens = jwtCsrf.createTokens(options, res);
    });

    describe('Happy', function () {
        it('Should pass validation rules', function (done) {
            var req = {
                headers: {
                    'x-csrf-jwt': tokens.header,
                    'user-agent': userAgent
                },
                cookies: {
                    'csrf-jwt': tokens.cookie
                }
            };

            return jwtCsrf.validate(options, req).then(function (data) {
                assert(data, 'Expect verification to pass');
                done();
            });
        });
    });

    describe('Unhappy', function () {
        it('Should fail if no tokens are provided', function (done) {
            var req = {
                headers: {
                    'user-agent': userAgent
                },
                cookies: {}
            };

            return jwtCsrf.validate(options, req)
                .catch(function (err) {
                    assert(err, 'Expect verification to fail');
                    assert.equal(err.code, 'MISSING_TOKENS', 'Error code is MISSING_HEADER');
                    done();
                });
        });

        it('Should fail if a header token is not provided', function (done) {
            var req = {
                headers: {
                    'user-agent': userAgent
                },
                cookies: {
                    'csrf-jwt': tokens.cookie
                }
            };

            return jwtCsrf.validate(options, req)
                .catch(function (err) {
                    assert(err, 'Expect verification to fail');
                    assert.equal(err.code, 'MISSING_HEADER', 'Error code is INVALID_TOKEN');
                    done();
                });
        });

        it('Should fail if a cookie token is not provided', function (done) {
            var req = {
                headers: {
                    'x-csrf-jwt': tokens.header,
                    'user-agent': userAgent
                },
                cookies: {}
            };

            return jwtCsrf.validate(options, req)
                .catch(function (err) {
                    assert(err, 'Expect verification to fail');
                    assert.equal(err.code, 'MISSING_COOKIE', 'Error code is INVALID_TOKEN');
                    done();
                });
        });

        it('Should fail for expired token', function (done) {

            var id = uuid.v4();

            var headerToken = jwtCsrf.create({
                secret: SECRET,
                macKey: MACKEY,
                expiresInMinutes: -1
            }, {
                id: id,
                type: 'header'
            });

            var cookieToken = jwtCsrf.create({
                secret: SECRET,
                macKey: MACKEY,
                expiresInMinutes: -1
            }, {
                id: id,
                type: 'cookie'
            });

            var req = {
                headers: {
                    'x-csrf-jwt': headerToken,
                    'user-agent': userAgent
                },
                cookies: {
                    'csrf-jwt': cookieToken
                }
            };

            return jwtCsrf.validate(options, req)
                .catch(function (err) {
                    assert.equal(err.code, 'TOKEN_EXPIRED', 'Error code is TOKEN_EXPIRED');
                    assert.ok(err.message.indexOf('token expired at') > -1, 'Error contains time token expired');
                    done();
                });
        });
    });
});