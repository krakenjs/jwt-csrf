jwt-csrf
========

Jwt middleware provider for hermes

Can be used as simple API or a middleware. Internally uses `jsonwebtoken` ([Here](https://github.com/auth0/node-jsonwebtoken))
and `crypto-paypal` modules.

## As API:

### Create JWT:

Usage:

```
 var token = create(options, req);

```

`options` is json which must contain `secret` and optional `expiresInMinutes`

  1. Construct the token.

       Format (for logged in cases): userAgent:payerId

       Format (for non logged in cases): userAgent

  2. Encrypt the token using `crypto-paypal` module, with `options.secret`

  3. Take encrypted value from step #2 and use `jsonwebtoken.sign`

  4. return result from from step #3.


### Validate JWT:

Will return `true` if the token validation succeeds, else returns false.

```
 var validate = validate(options, req, callback);

```

`options` is json which must contain `secret`.


Checks for JWT in `req.headers['X-CSRF-JWT']`

 1. If the request is POST, then get the jwt from headers['X-CSRF-JWT]. If token is not present then send a 401   response.
 
 2. Try decoding JWT. JWT decoding logic will throw error if the payload does not match the encrypted value.
 JWT is a self verifying token. If decoding throws error then send a 401.

 3. If this is a logged in user, decrypt the payload. For logged in case decrypted payload will be of the form
 user-agent:payerId.

 Verify payerId from above decrypted value with the user's encrypted payerid.

 4. Additionally for both logged in and not authenticated user, match user agent as a additional level of security.

`callback` will be called with err if there is any error in decryption. Or else it will be called with
callback(null, result). result could be true or false depending on whether validation succeeds or fails.

## As Middlware:

### setJwt:

 Usage

 ```
   var middleware = setJwt(options);

 ```

`options` is json which must contain `secret` and optional `expiresInMinutes`


Returns a middlware function which takes `req`, `res`, `next`. Sets the JWT in req headers under `'X-CSRF-JWT'`


### validateJWT:

 Usage

 ```
   var middleware = validateJWT(options);

 ```

`options` is json which must contain `secret`.

Returns a middlware function which takes `req`, `res`, `next`. Internally calls validate api (above).

If validation succeeds calls `next`. Else, does `res.status(401)` calls `next` with a error.


## Testing
`$ npm test`

`$ npm run cover`
