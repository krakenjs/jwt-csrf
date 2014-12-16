jwt-csrf
========

Jwt middleware provider for hermes

Can be used as simple API or a middleware. Internally uses `jwt-simple` and `crypto-paypal` modules.

## As API:

### Create JWT:

Usage:

```
 var token = create(SECRET, req);

```

  1. Construct the token.
       Format (for logged in cases): expiry:randomNum:userAgent:payerId
       Format (for non logged in cases): expiry:randomNum:userAgent

  2. Encrypt the token using crypto module, with key from vault:encrypted_csrftoken_crypt_key

  3. Take encrypted value from step #2 and use jwt.encode

  4. Set it in `req.headers['X-CSRF-JWT']`

  5. return result from from step #3.


### Validate JWT:

Will return `true` if the token validation succeeds, else returns false.

```
 var validate = validate(SECRET, req);

```

Checks for JWT in `req.headers['X-CSRF-JWT']`

 1. If the request is POST, then get the jwt from headers['X-CSRF-JWT]. If token is not present then send a 401   response.
 
 2. Try decoding JWT. JWT decoding logic will throw error if the payload does not match the encrypted value.
 JWT is a self verifying token. If decoding throws error then send a 401.

 3. If this is a logged in user, decrypt the payload. For logged in case descrypted payload will be of the form
 expiry:randomToken:user-agent:payerId.

 Verify payerId from above decrypted value with the payerId from user's payerId.


## As Middlware:

### setJwt:

 Usage

 ```
   var middleware = setJwt(SECRET);

 ```

Returns a middlware function which takes `req`, `res`, `next`. Sets the JWT in req headers under `req.headers['X-CSRF-JWT']`


### validateJWT:

 Usage

 ```
   var middleware = validateJWT(SECRET);

 ```

Returns a middlware function which takes `req`, `res`, `next`. Internally calls validate api (above).

If validation succeeds calls `next`. Else, sends 401: `res.send(401`


## Testing
`$ npm test`

`$ npm run cover`
