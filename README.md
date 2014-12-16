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

  4. return result from from step #3.


### Validate JWT:

Will return `true` if the token validation succeeds, else returns false.

```
 var validate = validate(SECRET, req);

```

Checks for JWT in `req.headers['X-CSRF-JWT']`

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