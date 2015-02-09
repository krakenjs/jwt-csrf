'use strict';

var lib = require('../lib/index');
var sinon = require('sinon');
var assert = require('chai').assert;


var jsonwebtoken = require('jsonwebtoken');
var jwtCsrf = require('../index');

describe('create jwt Tests', function () {

    var SECRET = "somerandomsecret";
    var MACKEY = "somerandommac";

    var userAgent = 'Mozilla';

    it('test No login case', function (done) {

        var req = {
            headers: {
                'user-agent': userAgent
            }
        };

        var options = {
            secret: SECRET,
            macKey: MACKEY,
            expiresInMinutes: 20
        };

        var data = jwtCsrf.create(options, req);

        jsonwebtoken.verify(data, SECRET, function (err, decoded) {
            var plainText = lib.decrypt(SECRET, MACKEY, decoded.token);
            var x = JSON.parse(plainText);
            assert(x && x.uid, 'Assert the decrypted jwt to have uid');
            done();
        });
    });

    it('test No encrypted account number case', function (done) {

        var req = {
            headers: {
                'user-agent': userAgent
            },
            user: {
                encryptedAccountNumber: undefined
            }
        };

        var options = {
            secret: SECRET,
            macKey: MACKEY,
            expiresInMinutes: 20
        };

        var data = jwtCsrf.create(options, req);

        jsonwebtoken.verify(data, SECRET, function (err, decoded) {
            var plainText = lib.decrypt(SECRET, MACKEY, decoded.token);
            var x = JSON.parse(plainText);
            assert.equal(x.uid, 'undefined', 'jwt uid should be undefined');
            done();
        });


    });


    it('test Login case', function (done) {

        var req = {
            headers: {
                'user-agent': userAgent
            },
            user: {
                encryptedAccountNumber: 123443223432
            }
        };

        var options = {
            secret: SECRET,
            macKey: MACKEY
        };

        var data = jwtCsrf.create(options, req);

        jsonwebtoken.verify(data, SECRET, function (err, decoded) {
            var plainText = lib.decrypt(SECRET, MACKEY, decoded.token);
            var x = JSON.parse(plainText);
            assert(x && x.uid, 'Assert the decrypted jwt to have uid');
            assert(x.uid === req.user.encryptedAccountNumber.toString(), 'Assert the payerId in the token');
            done();
        });


    });

    function sym_test(user_agent, done) {
        var options = {
            secret: SECRET,
            macKey: MACKEY
        };

        var req = {
            headers: {},
            user: {
                encryptedAccountNumber: 123443223432
            }
        };
        if (user_agent !== undefined) {
            req.headers['user-agent'] = user_agent;
        }

        var data = jwtCsrf.create(options, req);
        req.headers['x-csrf-jwt'] = data;

        jwtCsrf.validate(options, req, function (err, flag) {
            assert(flag, 'validate callback with result: ' + flag);
            done();
        });
    }

    it('test Login case with user-agent as empty string', function (done) {
        sym_test('', done);
    });

    it('test Login case with user-agent as white space string', function (done) {
        sym_test('   ', done);
    });

    it('test Login case with user-agent as null', function (done) {
        sym_test(null, done);
    });

    it('test Login case with user-agent as undefined', function (done) {
        sym_test(undefined, done);
    });

    it('test Login case with user-agent', function (done) {
        sym_test('hello world', done);
    });

    it('should skip if req.method is GET', function (done) {
        var options = {
        };

        var mw = jwtCsrf.middleware(options);
        mw({method: 'GET'}, {}, function (err) {
            assert(!err);
            done();
        });
    });

    it('Should call next for happy case', function (done) {

        var req = {
            headers: {
                'user-agent': userAgent
            },
            user: {
                encryptedAccountNumber: 123443223432
            }
        };

        var options = {
            secret: SECRET,
            macKey: MACKEY,
            expiresInMinutes: 20
        };

        var res = {
            setHeader: sinon.spy(),
            writeHead: function () {},
            status: function () {}
        };

        var next = sinon.spy();

        var middleware = jwtCsrf.middleware(options);

        middleware(req, res, next);
        res.writeHead();
        assert(next.called, 'Expect next() to be called');
        assert(res.setHeader.called, 'Expect jwt to be set in headers');
        done();

    });
});


describe('validate Tests', function () {

    var SECRET = "somerandomsecret";
    var MACKEY = "somerandommac";

    var userAgent = 'Mozilla';

    var options = {
        secret: SECRET,
        macKey: MACKEY
    }

    function constructToken(customAgent, payerId) {
        var data = {
            uid: payerId
        };

        return JSON.stringify(data);
    }

    it('Should fail with no token', function (done) {
        var req = {
            headers: {
                'user-agent': userAgent
            }
        };

        jwtCsrf.validate(options, req, function (err, data) {
            assert(!data, 'Expect verification to fail');
            done();
        })


    });

    it('should fail if token is not object', function (done) {
        var token = "null";
        var encryptedToken = {
            token: lib.encrypt(SECRET, MACKEY, token)
        };

        var jwtData = jsonwebtoken.sign(encryptedToken, SECRET);
        var req = {
            headers: {
                'x-csrf-jwt': jwtData,
                'user-agent': userAgent
            }
        };

        jwtCsrf.validate(options, req, function (err, data) {
            assert(!data);
            assert.equal(err.code, 'DECRYPT_FAILED');
            done();
        });
    });

    it('Should fail if token not valid JSON', function (done) {

        var token = "";
        var ecryptedToken = {
            token: lib.encrypt(SECRET, MACKEY, token)
        };

        var jwtData = jsonwebtoken.sign(ecryptedToken, SECRET);

        var req = {
            headers: {
                'x-csrf-jwt': jwtData,
                'user-agent': userAgent
            }
        };

        jwtCsrf.validate(options, req, function (err, data) {
            assert(!data, 'Expect verification to fail');
            done();
        })

    });

    it('Should fail for expired token', function (done) {

        var token = "testing";
        var ecryptedToken = {
            token: lib.encrypt(SECRET, MACKEY, token)
        };

        var jwtData = jsonwebtoken.sign(ecryptedToken, SECRET, {
            expiresInMinutes: -1
        });

        var req = {
            headers: {
                'x-csrf-jwt': jwtData,
                'user-agent': userAgent
            }
        };


        jwtCsrf.validate(options, req, function (err, data) {
            assert(!data, 'Expect verification to fail');
            done();
        })

    });


    it('Should fail for missing payer Id in loggedin case', function (done) {

        var token = constructToken(userAgent, undefined);
        var ecryptedToken = {
            token: lib.encrypt(SECRET, MACKEY, token)
        };

        var jwtData = jsonwebtoken.sign(ecryptedToken, SECRET);

        var req = {
            headers: {
                'x-csrf-jwt': jwtData,
                'user-agent': userAgent
            },
            user: {
                encryptedAccountNumber: 123443223432
            }
        };

        jwtCsrf.validate(options, req, function (err, data) {
            assert(!data, 'Expect verification to fail');
            done();
        })

    });

    it('Should fail for mismatched payer Id in loggedin case', function (done) {

        var token = constructToken(userAgent, "1234");
        var ecryptedToken = {
            token: lib.encrypt(SECRET, MACKEY, token)
        };

        var jwtData = jsonwebtoken.sign(ecryptedToken, SECRET);

        var req = {
            headers: {
                'x-csrf-jwt': jwtData,
                'user-agent': userAgent
            },
            user: {
                encryptedAccountNumber: "123443223432"
            }
        };

        jwtCsrf.validate(options, req, function (err, data) {
            assert(!data, 'Expect verification to fail');
            assert.equal(err.code, 'DIFF_PAYERID');
            done();
        })


    });

    it('Should work for No login happy case', function (done) {

        var token = constructToken(userAgent, 'x');
        var ecryptedToken = {
            token: lib.encrypt(SECRET, MACKEY, token)
        };

        var jwtData = jsonwebtoken.sign(ecryptedToken, SECRET);

        var req = {
            headers: {
                'x-csrf-jwt': jwtData,
                'user-agent': userAgent
            }
        };

        jwtCsrf.validate(options, req, function (err, data) {
            assert(data, 'Expect verification to succeed');
            done();
        })
    });


    it('Should work for login happy case', function (done) {

        var token = constructToken(userAgent, "1234");
        var ecryptedToken = {
            token: lib.encrypt(SECRET, MACKEY, token)
        };

        var jwtData = jsonwebtoken.sign(ecryptedToken, SECRET);

        var req = {
            headers: {
                'x-csrf-jwt': jwtData,
                'user-agent': userAgent
            },
            user: {
                encryptedAccountNumber: "1234"
            }
        };

        jwtCsrf.validate(options, req, function (err, data) {
            assert(data, 'Expect verification to succeed ');
            done();
        })
    });

    it('Should call next for happy case', function (done) {

        var token = constructToken();
        var ecryptedToken = {
            token: lib.encrypt(SECRET, MACKEY, token)
        };

        var jwtData = jsonwebtoken.sign(ecryptedToken, SECRET);

        var req = {
            headers: {
                'x-csrf-jwt': jwtData,
                'user-agent': userAgent
            }
        };

        var next = sinon.spy();

        var middleware = jwtCsrf.middleware(options);

        middleware(req, {status: function () {}}, next);

        assert(next.called, 'Expect next() to be called');

        done();

    });


    it('Should set 401 status and call next(err) for non happy case', function (done) {

        var token = "";
        var ecryptedToken = {
            token: lib.encrypt(SECRET, MACKEY, token)
        };

        var jwtData = jsonwebtoken.sign(ecryptedToken, SECRET);

        var req = {
            headers: {
                'x-csrf-jwt': jwtData,
                'user-agent': "RandomHeader"
            }
        };

        var next = sinon.spy();
        var res = {
            status: sinon.spy()
        };

        var middleware = jwtCsrf.middleware(options);

        middleware(req, res, next);

        assert(res.status.calledWith(401), 'Expect status 401 to be set');
        assert(next.args.toString(),
            "Expect next() called with err");
        done();

    });

});

