'use strict';


var assert = require('chai').assert;
var underscore = require('underscore');
var jwtCsrf = require('../index');

var SECRET = 'somerandomsecret';
var MACKEY = 'somerandommackey';

var HEADER_NAME = 'csrf';


function merge(obj, props) {
    obj = obj || {};
    props = props || {};
    underscore.extend(props, obj);
    underscore.extend(obj, props);
    return obj;
}


function getOptions(obj) {
    return merge(obj, {
        headerName: HEADER_NAME,
        secret: SECRET,
        macKey: MACKEY,
        getUserToken: getUserToken
    });
}

function getReq(obj) {
    return merge(obj, {
        get: function(key) {
            return 'mysite.com:8000';
        },
        protocol: 'https',
        headers: {},
        cookies: {}
    });
}

function getRes(obj) {
    return merge(obj, {
        locals: {},
        cookies: {},
        headers: {},
        status: function (statusCode) {

        },
        writeHead: function () {

        },
        setHeader: function (key, value) {
            assert(value, 'header value exists');
            this.headers[key] = value;
        },
        cookie: function (key, value, options) {
            assert.equal(key, HEADER_NAME, 'cookie has been set');
            assert(value, 'cookie value exists');
            assert(options, 'cookie options exists');
            assert(options.httpOnly, 'cookie options exists');
            assert.equal(options.domain, '.mysite.com', 'cookie domain has been set');
            this.cookies[key] = value;
        }
    });
}

function assertError(err, message) {
    assert(err, 'Expected ' + message);
    assert.equal(err.message, message);
}

function assertNotError(err) {
    if (err) {
        throw err;
    }
}

function handleCSRFError(err) {
    if (err && !(err instanceof jwtCsrf.CSRFError)) {
        throw err;
    }
}

function getUserToken(req) {
    return req.userId;
}

function runMiddleware(req, res, options, callback) {

    options = getOptions(options);
    console.log(options);
    req = getReq(req);
    res = getRes(res);

    jwtCsrf.middleware(options)(req, res, function(err) {

        if (err) {
            handleCSRFError(err)
        }

        try {
            res.writeHead(200);
        }
        catch (err) {
            handleCSRFError(err);
            return callback(err);
        }

        return callback(err);
    });

}




describe('middleware', function() {

    it('should return and validate tokens for GET and POST in AUTHED_TOKEN mode', function() {

        var req = {method: 'GET'};
        var res = {};
        var options = {csrfDriver: 'AUTHED_TOKEN'};

        runMiddleware(req, res, options, function(err) {

            assertNotError(err);
            assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
            assert(!res.cookies[HEADER_NAME], 'Expected JWT cookie to be absent');

            req.method = 'POST';
            req.headers[HEADER_NAME] = res.headers[HEADER_NAME];

            runMiddleware(req, res, options, function(err) {

                assertNotError(err);
                assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
                assert(!res.cookies[HEADER_NAME], 'Expected JWT cookie to be absent');
            });
        });
    });

    it('should return and validate tokens for GET and POST in AUTHED_TOKEN mode with an authenticated buyer', function() {

        var req = {
            method: 'GET',
            userId: 'XYZ'
        };
        var res = {};
        var options = {csrfDriver: 'AUTHED_TOKEN'};

        runMiddleware(req, res, options, function(err) {

            assertNotError(err);
            assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
            assert(!res.cookies[HEADER_NAME], 'Expected JWT cookie to be absent');

            req.method = 'POST';
            req.headers[HEADER_NAME] = res.headers[HEADER_NAME];

            runMiddleware(req, res, options, function(err) {

                assertNotError(err);
                assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
                assert(!res.cookies[HEADER_NAME], 'Expected JWT cookie to be absent');
            });
        });
    });

    it('should return and validate tokens for GET and POST in DOUBLE_SUBMIT mode', function() {

        var req = {method: 'GET'};
        var res = {};
        var options = {csrfDriver: 'DOUBLE_SUBMIT'};

        runMiddleware(req, res, options, function(err) {

            assertNotError(err);
            assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
            assert(res.cookies[HEADER_NAME], 'Expected JWT cookie to be absent');

            req.method = 'POST';
            req.headers[HEADER_NAME] = res.headers[HEADER_NAME];
            req.cookies[HEADER_NAME] = res.cookies[HEADER_NAME];

            runMiddleware(req, res, options, function(err) {

                assertNotError(err);
                assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
                assert(res.cookies[HEADER_NAME], 'Expected JWT cookie to be absent');
            });
        });
    });

    it('should return and validate tokens for GET in AUTHED_TOKEN and POST in DOUBLE_SUBMIT mode', function() {

        var req = {method: 'GET'};
        var res = {};
        var options = {csrfDriver: 'AUTHED_TOKEN'};

        runMiddleware(req, res, options, function(err) {

            assertNotError(err);
            assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
            assert(!res.cookies[HEADER_NAME], 'Expected JWT cookie to be absent');

            options.csrfDriver = 'DOUBLE_SUBMIT';
            req.method = 'POST';
            req.headers[HEADER_NAME] = res.headers[HEADER_NAME];

            runMiddleware(req, res, options, function(err) {

                assertNotError(err);
                assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
                assert(res.cookies[HEADER_NAME], 'Expected JWT cookie to be present');
            });
        });
    });


    it('should return and validate tokens for GET in DOUBLE_SUBMIT and POST in AUTHED_TOKEN mode', function() {

        var req = {method: 'GET'};
        var res = {};
        var options = {csrfDriver: 'DOUBLE_SUBMIT'};

        runMiddleware(req, res, options, function(err) {

            assertNotError(err);
            assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
            assert(res.cookies[HEADER_NAME], 'Expected JWT cookie to be absent');

            options.csrfDriver = 'AUTHED_TOKEN';
            req.method = 'POST';
            req.headers[HEADER_NAME] = res.headers[HEADER_NAME];
            req.cookies[HEADER_NAME] = res.cookies[HEADER_NAME];

            runMiddleware(req, res, options, function(err) {

                assertNotError(err);
                assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
                assert(res.cookies[HEADER_NAME], 'Expected JWT cookie to be present');
            });
        });
    });

    it('should work when erratically changing between modes', function() {

        var req = {method: 'GET'};
        var res = {};
        var options = {csrfDriver: 'AUTHED_TOKEN'};

        runMiddleware(req, res, options, function(err) {

            assertNotError(err);
            assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
            assert(!res.cookies[HEADER_NAME], 'Expected JWT cookie to be absent');

            options.csrfDriver = 'DOUBLE_SUBMIT';
            req.method = 'POST';
            req.headers[HEADER_NAME] = res.headers[HEADER_NAME];

            runMiddleware(req, res, options, function(err) {

                assertNotError(err);
                assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
                assert(res.cookies[HEADER_NAME], 'Expected JWT cookie to be present');

                options.csrfDriver = 'AUTHED_TOKEN';
                req.method = 'POST';
                req.headers[HEADER_NAME] = res.headers[HEADER_NAME];
                req.cookies[HEADER_NAME] = res.cookies[HEADER_NAME];

                runMiddleware(req, res, options, function(err) {

                    assertNotError(err);
                    assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
                    assert(res.cookies[HEADER_NAME], 'Expected JWT cookie to be present');

                    options.csrfDriver = 'DOUBLE_SUBMIT';
                    req.method = 'POST';
                    req.headers[HEADER_NAME] = res.headers[HEADER_NAME];

                    runMiddleware(req, res, options, function(err) {

                        assertNotError(err);
                        assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
                        assert(res.cookies[HEADER_NAME], 'Expected JWT cookie to be present');
                    });
                });
            });
        });
    });




    it('should fail for POST in AUTHED_TOKEN if no header is passed', function() {

        var req = {method: 'POST'};
        var res = {};
        var options = {csrfDriver: 'AUTHED_TOKEN'};

        runMiddleware(req, res, options, function(err) {

            assertError(err, 'EINVALIDCSRF_TOKEN_NOT_IN_HEADER');
            assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
            assert(!res.cookies[HEADER_NAME], 'Expected JWT cookie to be absent');
        });
    });


    it('should fail for POST in DOUBLE_SUBMIT if no cookie or header is passed', function() {

        var req = {method: 'POST'};
        var res = {};
        var options = {csrfDriver: 'DOUBLE_SUBMIT'};

        runMiddleware(req, res, options, function(err) {

            assertError(err, 'EINVALIDCSRF_TOKEN_NOT_IN_HEADER');
            assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
            assert(res.cookies[HEADER_NAME], 'Expected JWT cookie to be present');
        });
    });

    it('should fail POST in DOUBLE_SUBMIT mode if no header is present', function() {

        var req = {method: 'GET'};
        var res = {};
        var options = {csrfDriver: 'DOUBLE_SUBMIT'};

        runMiddleware(req, res, options, function(err) {

            assertNotError(err);
            assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
            assert(res.cookies[HEADER_NAME], 'Expected JWT cookie to be absent');

            req.method = 'POST';
            req.cookies[HEADER_NAME] = res.cookies[HEADER_NAME];

            runMiddleware(req, res, options, function(err) {

                assertError(err, 'EINVALIDCSRF_TOKEN_NOT_IN_HEADER');
                assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
                assert(res.cookies[HEADER_NAME], 'Expected JWT cookie to be absent');
            });
        });
    });

    it('should fail POST in DOUBLE_SUBMIT mode if no cookie is present', function() {

        var req = {method: 'GET'};
        var res = {};
        var options = {csrfDriver: 'DOUBLE_SUBMIT'};

        runMiddleware(req, res, options, function(err) {

            assertNotError(err);
            assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
            assert(res.cookies[HEADER_NAME], 'Expected JWT cookie to be absent');

            req.method = 'POST';
            req.headers[HEADER_NAME] = res.headers[HEADER_NAME];
            req.userId = 'xyz';

            runMiddleware(req, res, options, function(err) {

                assertError(err, 'EINVALIDCSRF_ID_NOT_IN_COOKIE');
                assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
                assert(res.cookies[HEADER_NAME], 'Expected JWT cookie to be absent');
            });
        });
    });


    it('should fail POST in AUTHED_TOKEN mode with an authenticated buyer but not an authenticated token', function() {

        var req = {
            method: 'GET'
        };
        var res = {};
        var options = {csrfDriver: 'AUTHED_TOKEN'};

        runMiddleware(req, res, options, function(err) {

            assertNotError(err);
            assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
            assert(!res.cookies[HEADER_NAME], 'Expected JWT cookie to be absent');

            req.method = 'POST';
            req.userId = 'XYZ';
            req.headers[HEADER_NAME] = res.headers[HEADER_NAME];

            runMiddleware(req, res, options, function(err) {

                assertError(err, 'EINVALIDCSRF_TOKEN_PAYERID_MISSING');
                assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
                assert(!res.cookies[HEADER_NAME], 'Expected JWT cookie to be absent');
            });
        });
    });


    it('should fail POST in AUTHED_TOKEN mode with an authenticated buyer and an authenticated token for a different buyer', function() {

        var req = {
            method: 'GET',
            userId: 'ABC'
        };
        var res = {};
        var options = {csrfDriver: 'AUTHED_TOKEN'};

        runMiddleware(req, res, options, function(err) {

            assertNotError(err);
            assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
            assert(!res.cookies[HEADER_NAME], 'Expected JWT cookie to be absent');

            req.method = 'POST';
            req.userId = 'XYZ';
            req.headers[HEADER_NAME] = res.headers[HEADER_NAME];

            runMiddleware(req, res, options, function(err) {

                assertError(err, 'EINVALIDCSRF_TOKEN_PAYERID_MISMATCH');
                assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
                assert(!res.cookies[HEADER_NAME], 'Expected JWT cookie to be absent');
            });
        });
    });

    it('should fail POST in DOUBLE_SUBMIT mode when passing a header value as a cookie', function() {

        var req = {method: 'GET'};
        var res = {};
        var options = {csrfDriver: 'DOUBLE_SUBMIT'};

        runMiddleware(req, res, options, function(err) {

            assertNotError(err);
            assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
            assert(res.cookies[HEADER_NAME], 'Expected JWT cookie to be absent');

            req.method = 'POST';
            req.headers[HEADER_NAME] = res.headers[HEADER_NAME];
            req.cookies[HEADER_NAME] = res.headers[HEADER_NAME];

            runMiddleware(req, res, options, function(err) {

                assertError(err, 'EINVALIDCSRF_GOT_HEADER_EXPECTED_COOKIE');
                assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
                assert(res.cookies[HEADER_NAME], 'Expected JWT cookie to be absent');
            });
        });
    });

    it('should fail POST in DOUBLE_SUBMIT mode when passing a cookie value as a header', function() {

        var req = {method: 'GET'};
        var res = {};
        var options = {csrfDriver: 'DOUBLE_SUBMIT'};

        runMiddleware(req, res, options, function(err) {

            assertNotError(err);
            assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
            assert(res.cookies[HEADER_NAME], 'Expected JWT cookie to be absent');

            req.method = 'POST';
            req.headers[HEADER_NAME] = res.cookies[HEADER_NAME];
            req.cookies[HEADER_NAME] = res.cookies[HEADER_NAME];

            runMiddleware(req, res, options, function(err) {

                assertError(err, 'EINVALIDCSRF_GOT_COOKIE_EXPECTED_HEADER');
                assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
                assert(res.cookies[HEADER_NAME], 'Expected JWT cookie to be absent');
            });
        });
    });

    it('should fail POST in DOUBLE_SUBMIT mode when passing a cookie value as a header and vice versa', function() {

        var req = {method: 'GET'};
        var res = {};
        var options = {csrfDriver: 'DOUBLE_SUBMIT'};

        runMiddleware(req, res, options, function(err) {

            assertNotError(err);
            assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
            assert(res.cookies[HEADER_NAME], 'Expected JWT cookie to be absent');

            req.method = 'POST';
            req.headers[HEADER_NAME] = res.cookies[HEADER_NAME];
            req.cookies[HEADER_NAME] = res.headers[HEADER_NAME];

            runMiddleware(req, res, options, function(err) {

                assertError(err, 'EINVALIDCSRF_GOT_COOKIE_EXPECTED_HEADER');
                assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
                assert(res.cookies[HEADER_NAME], 'Expected JWT cookie to be absent');
            });
        });
    });

    it('should fail POST in DOUBLE_SUBMIT mode when the token and header do not match', function() {

        var req = {method: 'GET'};
        var res = {};
        var options = {csrfDriver: 'DOUBLE_SUBMIT'};

        runMiddleware(req, res, options, function(err) {

            assertNotError(err);
            assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
            assert(res.cookies[HEADER_NAME], 'Expected JWT cookie to be absent');

            var oldCookie = res.cookies[HEADER_NAME];

            runMiddleware(req, res, options, function(err) {

                assertNotError(err);
                assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
                assert(res.cookies[HEADER_NAME], 'Expected JWT cookie to be absent');


                req.method = 'POST';
                req.headers[HEADER_NAME] = res.headers[HEADER_NAME];
                req.cookies[HEADER_NAME] = oldCookie;
                req.userId = 'xyz';

                runMiddleware(req, res, options, function(err) {

                    assertError(err, 'EINVALIDCSRF_HEADER_COOKIE_ID_MISMATCH');
                    assert(res.headers[HEADER_NAME], 'Expected JWT header to be present');
                    assert(res.cookies[HEADER_NAME], 'Expected JWT cookie to be absent');
                });
            });
        });
    });
});
