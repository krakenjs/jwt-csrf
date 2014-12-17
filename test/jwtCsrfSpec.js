'use strict';

var lib = require('../lib/index');
var sinon = require('sinon');
var assert = require('chai').assert;


var jsonwebtoken = require('jsonwebtoken');
var jwtCsrf = require('../index');

describe('create jwt Tests', function(){

    var SECRET = "somerandomsecret";
    var userAgent = 'Mozilla';

    it('test No login case', function(done){

        var req = {
            headers : {
                'user-agent': userAgent
            }
        };

        var options = {
            secret : SECRET,
            expiresInMinutes: 20
        }

        var data = jwtCsrf.create(options, req);

        jsonwebtoken.verify(data, SECRET, function(err, decoded) {
            var plainText = lib.decrypt(SECRET, decoded.token);
            var split = plainText.split(":");
            assert(split && split.length === 1 , 'Assert the decrypted jwt to have 1 field');
            assert(split[0] === userAgent, 'Expect payload to have right user agent');
            done();
        });


    });

    it('test Login case', function(done){

        var req = {
            headers : {
                'user-agent': userAgent
            },
            user: {
                encryptedAccountNumber: 123443223432
            }
        };

        var options = {
            secret : SECRET
        }

        var data = jwtCsrf.create(options, req);

        jsonwebtoken.verify(data, SECRET, function(err, decoded) {
            var plainText = lib.decrypt(SECRET, decoded.token);
            var split = plainText.split(":");
            assert(split && split.length === 2 , 'Assert the decrypted jwt to have 1 field');
            assert(split[1] === req.user.encryptedAccountNumber.toString(), 'Assert the payerId in the token');
            done();
        });


    });


    it('Should call next for happy case', function(done){

        var req = {
            headers : {
                'user-agent': userAgent
            },
            user: {
                encryptedAccountNumber: 123443223432
            }
        };

        var options = {
            secret : SECRET,
            expiresInMinutes: 20
        };

        var res = {
            setHeader: sinon.spy(),
            writeHead : function(){}
        };

        var next = sinon.spy();

        var middleware = jwtCsrf.setJwt(options);

        middleware(req, res, next);
        res.writeHead();
        assert(next.called, 'Expect next() to be called');
        assert(res.setHeader.called, 'Expect jwt to be set in headers');
        done();

    });
});


describe('validate Tests', function(){

    var SECRET = "somerandomsecret";

    var userAgent = 'Mozilla';

    var options = {
        secret: SECRET
    }

    function constructToken(customAgent, payerId){
        var data = [
            customAgent || userAgent
        ]

        if(payerId){
            data.push(payerId);
        }
        return data.join(":");
    }

    it('Should fail with no token', function(done){
        var req = {
            headers : {
                'user-agent': userAgent
            }
        };

        jwtCsrf.validate(options, req, function(err, data){
            assert(!data , 'Expect verification to fail');
            done();
        })



    });

    it('Should fail if less than 1 field in token', function(done){

        var token = "";
        var ecryptedToken = {
           token: lib.encrypt(SECRET, token)
        };

        var jwtData = jsonwebtoken.sign(ecryptedToken, SECRET);

        var req = {
            headers : {
                'x-csrf-jwt': jwtData,
                'user-agent': userAgent
            }
        };

        jwtCsrf.validate(options, req, function(err, data){
            assert(!data , 'Expect verification to fail');
            done();
        })

    });

    it('Should fail for mismatch useragent', function(done){

        var token = constructToken('Chrome');
        var ecryptedToken = {
            token: lib.encrypt(SECRET, token)
        };

        var jwtData = jsonwebtoken.sign(ecryptedToken, SECRET);

        var req = {
            headers : {
                'x-csrf-jwt': jwtData,
                'user-agent': userAgent
            }
        };

        jwtCsrf.validate(options, req, function(err, data){
            assert(!data , 'Expect verification to fail');
            done();
        })

    });


    it('Should fail for expired token', function(done){

        var token = "testing";
        var ecryptedToken = {
            token: lib.encrypt(SECRET, token)
        };

        var jwtData = jsonwebtoken.sign(ecryptedToken, SECRET, {
            expiresInMinutes: -1
        });

        var req = {
            headers : {
                'x-csrf-jwt': jwtData,
                'user-agent': userAgent
            }
        };


        jwtCsrf.validate(options, req, function(err, data){
            assert(!data , 'Expect verification to fail');
            done();
        })

    });


    it('Should fail for missing payer Id in loggedin case', function(done){

        var token = constructToken();
        var ecryptedToken = {
            token: lib.encrypt(SECRET, token)
        };

        var jwtData = jsonwebtoken.sign(ecryptedToken, SECRET);

        var req = {
            headers : {
                'x-csrf-jwt': jwtData,
                'user-agent': userAgent
            },
            user: {
                encryptedAccountNumber: 123443223432
            }
        };

        jwtCsrf.validate(options, req, function(err, data){
            assert(!data , 'Expect verification to fail');
            done();
        })

    });

    it('Should fail for mismatched payer Id in loggedin case', function(done){

        var token = constructToken(userAgent, "1234");
        var ecryptedToken = {
            token: lib.encrypt(SECRET, token)
        };

        var jwtData = jsonwebtoken.sign(ecryptedToken, SECRET);

        var req = {
            headers : {
                'x-csrf-jwt': jwtData,
                'user-agent': userAgent
            },
            user: {
                encryptedAccountNumber: "123443223432"
            }
        };

        jwtCsrf.validate(options, req, function(err, data){
            assert(!data , 'Expect verification to fail');
            done();
        })


    });

    it('Should work for No login happy case', function(done){

        var token = constructToken();
        var ecryptedToken = {
            token: lib.encrypt(SECRET, token)
        };

        var jwtData = jsonwebtoken.sign(ecryptedToken, SECRET);

        var req = {
            headers : {
                'x-csrf-jwt': jwtData,
                'user-agent': userAgent
            }
        };

        jwtCsrf.validate(options, req, function(err, data){
            assert(data , 'Expect verification to succeed');
            done();
        })
    });


    it('Should work for login happy case', function(done){

        var token = constructToken(userAgent, "1234");
        var ecryptedToken = {
            token: lib.encrypt(SECRET, token)
        };

        var jwtData = jsonwebtoken.sign(ecryptedToken, SECRET);

        var req = {
            headers : {
                'x-csrf-jwt': jwtData,
                'user-agent': userAgent
            },
            user: {
                encryptedAccountNumber: "1234"
            }
        };

        jwtCsrf.validate(options, req, function(err, data){
            assert(data , 'Expect verification to succeed');
            done();
        })
    });

    it('Should call next for happy case', function(done){

        var token = constructToken();
        var ecryptedToken = {
            token: lib.encrypt(SECRET, token)
        };

        var jwtData = jsonwebtoken.sign(ecryptedToken, SECRET);

        var req = {
            headers : {
                'x-csrf-jwt': jwtData,
                'user-agent': userAgent
            }
        };

        var next = sinon.spy();

        var middleware = jwtCsrf.checkJwt(options);

        middleware(req, {}, next);

        assert(next.called, 'Expect next() to be called');

        done();

    });


    it('Should send 401 for non happy case', function(done){

        var token = constructToken();
        var ecryptedToken = {
            token: lib.encrypt(SECRET, token)
        };

        var jwtData = jsonwebtoken.sign(ecryptedToken, SECRET);

        var req = {
            headers : {
                'x-csrf-jwt': jwtData,
                'user-agent': "RandomHeader"
            }
        };

        var next = sinon.spy();
        var res = {
            send: sinon.spy()
        }

        var middleware = jwtCsrf.checkJwt(options);

        middleware(req, res, next);

        assert(res.send.calledWith(401), 'Expect next() to be called');

        done();

    });

});

