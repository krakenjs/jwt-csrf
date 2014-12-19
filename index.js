var jsonwebtoken = require('jsonwebtoken');
var encrypt = require('./lib').encrypt;
var decrypt = require('./lib').decrypt;
var onHeaders = require('on-headers');

var errCodes = {
    INVALID_TOKEN: "EINVALIDCSRF"
}

function isLoggedIn(req){
    return req.user ? true: false;
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
function create(options, req){
    var payload;
    var expiry;

    if(options.expiresInMinutes){
        expiry = options.expiresInMinutes;
    } else{
        //Set expiry to 20 mins from current time.
        expiry = 20;
    }


    var userAgent = req.headers && req.headers['user-agent'];

    var data = [userAgent];

    if(isLoggedIn(req)){
        var payerId =  req.user.encryptedAccountNumber;
        data.push(payerId);
    }

    payload = data.join("::");

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
 * 1. If the request is POST, then get the jwt from headers['x-csrf-jwt]. If token is not present then send a 401 response.
 *
 * 2. Try decoding JWT. JWT decoding logic will throw error if the payload does not match the encrypted value.
 *  JWT is a self verifying token. If decoding throws error then send a 401.
 *
 * 3. If this is a logged in user, decrypt the payload. For logged in case decrypted payload will be of the form
 *    user-agent:payerId.
 *
 *    Verify payerId from above decrypted value with the user's encrypted payerid.
 *
 * 4. Additionally for both logged in and not authenticated user, match user agent as a additional level of security.
 *
 * Takes a callback. callback will be called with err if there is any error in decryption. Or else it will be called with
 * callback(null, result). result could be true or false depending on whether validation succeeds or fails.
 *
 * @param options {secret:*, macKey: *}
 *
 */

function validate(options, req, callback) {

    var token = req.headers && req.headers['x-csrf-jwt'];

    //If the jwtToken is not send in header, then send a 401.
    if (!token) {
        return callback(null, false);
    }

    var secret = options.secret;


    //If token is invalid this would throw error. We catch it and send 401 response.
    jsonwebtoken.verify(token, secret, function (err, payload) {
        if(err){
            return callback(err);
        }
        var decryptedPayload;

        try{
            decryptedPayload = decrypt(secret, options.macKey, payload.token);
        } catch (err){
            return callback(err);
        }
        var userAgent = req.headers['user-agent'];

        //Expected format for decryptedPayLoad is randomToken:payerId:user-agent
        var split = decryptedPayload.split("::");

        if (!split || split.length < 1) {
            return callback(null, false);
        }

        var userAgentInToken = split[0];
        if (userAgentInToken !== userAgent) {
            return callback(null, false);
        }

        //If this is a authenticated user, then verify the payerId in jwtToken with payerId in req.user.
        if (isLoggedIn(req)) {
            if (split.length !== 2) {
                return callback(null, false);
            }
            //Check payerId in token
            var inputPayerId = split[1];
            var userPayerId = req.user.encryptedAccountNumber;
            if (inputPayerId !== userPayerId) {
                return callback(null, false);
            }
        }
        return callback(null, true);

    });

}
module.exports = {

    errCodes: errCodes,
    create: create,
    validate: validate,

    //Returns a jwt middleware
    setJwt: function(options){
        return function (req, res, next){
            onHeaders(res, function() {
                var jwtCsrf = create(options, req);
                res.setHeader('x-csrf-jwt', jwtCsrf);
            });

            next();
        }
    },

    checkJwt: function(options){
        return function(req, res, next){

            if(req.method !== 'GET') {
                validate(options, req, function(err, result){
                    if(err || !result){
                        res.status(401);
                        var err = new Error('Invalid CSRF token');
                        err.code = errCodes.INVALID_TOKEN;
                        next(err);
                    }
                });
            }
            next();

        }
    }

}