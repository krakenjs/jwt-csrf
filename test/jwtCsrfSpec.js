'use strict';

var lib = require('../lib/index');
var sinon = require('sinon');
var assert = require('chai').assert;


var jwtCsrf = require('../index');
var jwt = require('jwt-simple');

describe('create jwt Tests', function(){

    var SECRET = "somerandomsecret";


    it('test No login case', function(done){

        var req = {
            headers : {
                'user-agent': 'Mozilla'
            }
        };
        var token = jwtCsrf.create(SECRET, req);
        var decodedToken = jwt.decode(token, SECRET);
        var plainText = lib.decrypt(SECRET, decodedToken);

        var split = plainText.split(":");
        assert(split && split.length === 3 , 'Assert the decrypted jwt to have 3 fields');
        assert(req.headers['X-CSRF-JWT'], 'Expect jwt to be set in headers');
        done();

    });

    it('test Login case', function(done){

        var req = {
            headers : {
                'user-agent': 'Mozilla'
            },
            user: {
                encryptedAccountNumber: 123443223432
            }
        };
        var token = jwtCsrf.create(SECRET, req);
        var decodedToken = jwt.decode(token, SECRET);
        var plainText = lib.decrypt(SECRET, decodedToken);

        var split = plainText.split(":");
        assert(split && split.length === 4 , 'Assert the decrypted jwt to have 3 fields');
        assert(split[3] === req.user.encryptedAccountNumber.toString(), 'Assert the payerId in the token');
        assert(req.headers['X-CSRF-JWT'], 'Expect jwt to be set in headers');
        done();

    });

    it('Should call next for happy case', function(done){

        var req = {
            headers : {
                'user-agent': 'Mozilla'
            },
            user: {
                encryptedAccountNumber: 123443223432
            }
        };

        var next = sinon.spy();

        var middleware = jwtCsrf.setJwt(SECRET);

        middleware(req, {}, next);

        assert(next.called, 'Expect next() to be called');
        assert(req.headers['X-CSRF-JWT'], 'Expect jwt to be set in headers');
        done();

    });
});


describe('validate Tests', function(){

    var SECRET = "somerandomsecret";

    var userAgent = 'Mozilla';

    function constructToken(expired, customAgent, payerId){
        var d = new Date();
        var time = d.getTime();

        var data = [
            expired ? time : time + (20 * 60 * 1000),
            3252466252,
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
        assert(!jwtCsrf.validate(SECRET, req) , 'Expect verification to fail');
        done();

    });

    it('Should fail if less than 3 fields in token', function(done){

        var token = "213:sdfdasfsadfas";
        var ecryptedToken = lib.encrypt(SECRET, token);
        var jwtString = jwt.encode(ecryptedToken, SECRET);

        var req = {
            headers : {
                'X-CSRF-JWT': jwtString,
                'user-agent': userAgent
            }
        };

        assert(!jwtCsrf.validate(SECRET, req) , 'Expect verification to fail');

        done();

    });

    it('Should fail for mismatch useragent', function(done){

        var token = constructToken(false, 'Chrome');
        var ecryptedToken = lib.encrypt(SECRET, token);
        var jwtString = jwt.encode(ecryptedToken, SECRET);

        var req = {
            headers : {
                'X-CSRF-JWT': jwtString,
                'user-agent': userAgent
            }
        };

        assert(!jwtCsrf.validate(SECRET, req) , 'Assert verification to fail');

        done();

    });

    it('Should fail for expired token', function(done){

        var token = constructToken(true);
        var ecryptedToken = lib.encrypt(SECRET, token);
        var jwtString = jwt.encode(ecryptedToken, SECRET);

        var req = {
            headers : {
                'X-CSRF-JWT': jwtString,
                'user-agent': userAgent
            }
        };

        assert(!jwtCsrf.validate(SECRET, req) , 'Assert verification to fail');

        done();

    });

    it('Should fail for missing payer Id in loggedin case', function(done){

        var token = constructToken();
        var ecryptedToken = lib.encrypt(SECRET, token);
        var jwtString = jwt.encode(ecryptedToken, SECRET);

        var req = {
            headers : {
                'X-CSRF-JWT': jwtString,
                'user-agent': userAgent
            },
            user: {
                encryptedAccountNumber: 123443223432
            }
        };

        assert(!jwtCsrf.validate(SECRET, req) , 'Assert verification to fail');

        done();

    });

    it('Should fail for mismatched payer Id in loggedin case', function(done){

        var token = constructToken(false, userAgent, 1234);
        var ecryptedToken = lib.encrypt(SECRET, token);
        var jwtString = jwt.encode(ecryptedToken, SECRET);

        var req = {
            headers : {
                'X-CSRF-JWT': jwtString,
                'user-agent': userAgent
            },
            user: {
                encryptedAccountNumber: 123443223432
            }
        };

        assert(!jwtCsrf.validate(SECRET, req) , 'Assert verification to fail');

        done();

    });

    it('Should work for No login happy case', function(done){

        var token = constructToken();
        var ecryptedToken = lib.encrypt(SECRET, token);
        var jwtString = jwt.encode(ecryptedToken, SECRET);

        var req = {
            headers : {
                'X-CSRF-JWT': jwtString,
                'user-agent': userAgent
            }
        };

        assert(jwtCsrf.validate(SECRET, req) , 'Assert verification to succeed');

        done();

    });

    it('Should work for login happy case', function(done){

        var token = constructToken(false, userAgent, "1234");
        var ecryptedToken = lib.encrypt(SECRET, token);
        var jwtString = jwt.encode(ecryptedToken, SECRET);

        var req = {
            headers : {
                'X-CSRF-JWT': jwtString,
                'user-agent': userAgent
            },
            user: {
                encryptedAccountNumber: "1234"
            }
        };

        assert(jwtCsrf.validate(SECRET, req) , 'Assert verification to succeed');

        done();

    });

    it('Should call next for happy case', function(done){

        var token = constructToken();
        var ecryptedToken = lib.encrypt(SECRET, token);
        var jwtString = jwt.encode(ecryptedToken, SECRET);

        var req = {
            headers : {
                'X-CSRF-JWT': jwtString,
                'user-agent': userAgent
            }
        };

        var next = sinon.spy();

        var middleware = jwtCsrf.checkJwt(SECRET);

        middleware(req, {}, next);

        assert(next.called, 'Expect next() to be called');

        done();

    });

    it('Should send 401 for non happy case', function(done){

        var token = constructToken();
        var ecryptedToken = lib.encrypt(SECRET, token);
        var jwtString = jwt.encode(ecryptedToken, SECRET);

        var req = {
            headers : {
                'X-CSRF-JWT': jwtString,
                'user-agent': "RandomHeader"
            }
        };

        var next = sinon.spy();
        var res = {
            send: sinon.spy()
        }

        var middleware = jwtCsrf.checkJwt(SECRET);

        middleware(req, res, next);

        assert(res.send.calledWith(401), 'Expect next() to be called');

        done();

    });

    it('Should send 401 for invlid token', function(done){

        var token = constructToken();
        var ecryptedToken = lib.encrypt(SECRET, token);


        var req = {
            headers : {
                'X-CSRF-JWT': ecryptedToken,
                'user-agent': "RandomHeader"
            }
        };

        var next = sinon.spy();
        var res = {
            send: sinon.spy()
        }

        var middleware = jwtCsrf.checkJwt(SECRET);

        middleware(req, res, next);

        assert(res.send.calledWith(401), 'Expect next() to be called');

        done();

    });

});

