var jwt = require('jwt-simple');
var encrypt = require('./lib').encrypt;
var decrypt = require('./lib').decrypt;


function isLoggedIn(req){
    return req.user ? true: false;
}

/**
 * Constructs a jwt which would be dropped in res headers on every outgoing response.
 *
 * 1. Construct the token.
 *      Format (for logged in cases): expiry:randomNum:userAgent:payerId
 *      Format (for non logged in cases): expiry:randomNum:userAgent
 *
 * 2. Encrypt the token using crypto module, with key from vault:encrypted_csrftoken_crypt_key
 *
 * 3. Take encrypted value from step #2 and use jwt.encode
 *
 * 4. return result from from step #3.
 *
 *
 *
 *
 * @param secret
 * @returns {Function}
 */
function create(secret, req){
    var payload;
    var d = new Date();

    //Set expiry to 20 mins from current time.
    var expiry = d.getTime() + (20 * 60 * 1000);
    var randomNum = Math.floor(Math.random()*1000001);
    var userAgent = req.headers && req.headers['user-agent'];

    var data = [expiry, randomNum, userAgent];

    if(isLoggedIn(req)){
        var payerId =  req.user.encryptedAccountNumber;
        data.push(payerId);
    }

    payload = data.join(":");

    var encryptedPayload = encrypt(secret, payload);


    var jwtCsrf = jwt.encode(encryptedPayload, secret);
    req.headers['X-CSRF-JWT'] = jwtCsrf;

    return jwtCsrf;
}

/**
 * Verifies JWT token in req headers
 * ----------------------------------------
 *
 * 1. If the request is POST, then get the jwt from headers['X-CSRF-JWT]. If token is not present then send a 401 response.
 *
 * 2. Try decoding JWT. JWT decoding logic will throw error if the payload does not match the encrypted value.
 * JWT is a self verifying token. If decoding throws error then send a 401.
 *
 * 3. If this is a logged in user, decrypt the payload. For logged in case descrypted payload will be of the form
 *    expiry:randomToken:user-agent:payerId.
 *
 *    Verify payerId from above decrypted value with the payerId from user's payerId.
 *
 *
 *
 * @param options
 * @returns {Function}
 */

function validate(secret, req){

    var token = req.headers && req.headers['X-CSRF-JWT'];

    //If the jwtToken is not send in header, then send a 401.
    if(!token){
        return false;
    };

    var payload;
    var userAgent = req.headers['user-agent'];

    //If token is invalid this would throw error. We catch it and send 401 response.
    payload = jwt.decode(token, secret);

    var decryptedPayload = decrypt(secret, payload);

    //Expected format for decryptedPayLoad is randomToken:payerId:user-agent
    var split = decryptedPayload.split(":");

    if(!split && split.length < 3){
        return false;
    }

    var userAgentInToken  = split[2];

    if(userAgentInToken !== userAgent){
        return false;
    }

    //Check token expiry
    var expiry = parseInt(split[0]);
    var currentDate = new Date();

    if(expiry <= currentDate.getTime() ){
        return false;
    }

    //If this is a authenticated user, then verify the payerId in jwtToken with payerId in req.user.
    if(isLoggedIn(req)){
        if(split.length !== 4){
            return false;
        }
        //Check payerId in token
        var inputPayerId = split[3];
        var userPayerId = req.user.encryptedAccountNumber;
        if(inputPayerId !== userPayerId) {
            return false;
        }
    }

    return true;
}

module.exports = {

    create: create,
    validate: validate,

    //Returns a jwt middleware
    setJwt: function(secret){
        return function (req, res, next){
            create(secret, req);
            next();
        }
    },

    checkJwt: function(secret){
        return function(req, res, next){
            try {
                (req.method !== 'GET') && !validate(secret, req) ? res.send(401, 'Invalid token') : next()
            } catch(err){
                res.send(401, 'Invalid token');
            }

        }
    }

}