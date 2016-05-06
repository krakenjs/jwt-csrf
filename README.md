# jwt-csrf

[![Dependency Status](http://tooling.paypalcorp.com/badges/npm/version/jwt-csrf.svg?style=flat-square)](http://tooling.paypalcorp.com/badges/npm/version/jwt-csrf.svg?style=flat-square)
[![Dependency Status](http://tooling.paypalcorp.com/badges/david/NodeXOShared/jwt-csrf.svg?style=flat-square)](http://tooling.paypalcorp.com/badges/david/NodeXOShared/jwt-csrf.svg?style=flat-square)
[![devDependency Status](http://tooling.paypalcorp.com:/badges/david/dev/NodeXOShared/jwt-csrf.svg?style=flat-square)](http://tooling.paypalcorp.com/badges/david/NodeXOShared/jwt-csrf.svg?style=flat-square)

CSRF protection using the power of JWTs. Provides a number of stateless methods of csrf protection, if you don't want to keep a session.

Defaults to the [double submit](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#Double_Submit_Cookies) method of csrf protection, but supports a number of different strategies.

## Middleware

#### Example

 ```javascript
var express = require('express');
var app = express();

var jwtCSRF = require('jwt-csrf');
var jwtMiddleware = jwtCSRF.middleware(options); // This can be used like any other Express middleware

app.use(jwtMiddleware); // Executed on all requests
 ```

The middleware must be included before others to be effective.

#### Handling errors

On errors, jwt-csrf will call `next(err)` with a `jwtCSRF.CSRFError`. If you want to handle this specifically, you can do so in a middleware:

```javascript
function(err, req, res, next) {
    if (err instanceof jwtCSRF.CSRFError) {
        explode();
    }
}
```

## Options

`options` is an Object with the following format:
* **secret** : String (Required) - Your application's secret, must be cryptographically complex.
* **macKey** : String (Required) - Your application's mac key, must be cryptographically complex.
* **csrfDriver** : String (Optional) - CSRF driver/strategy to use. Defaults to `DOUBLE_SUBMIT`.
* **expiresInMinutes** : Number (Optional) - A token's expiration time.  Defaults to `60`.
* **headerName** : String (Optional) - The name of the response header that will contain the csrf token. Defaults to `x-csrf-jwt`.
* **excludeUrls** : Array (Optional) - An array of urls to exclude from csrf protection. Not recommended unless you know what you're doing
* **getUserToken** : Function (Optional) - A custom method to call to get a user specific token for the `AUTHED_TOKEN` and `AUTHED_DOUBLE_SUBMIT`. Must accept `req` and return a user-specific token (like a user id) for a known user.

## CSRF Drivers

### DOUBLE_SUBMIT

Persist two linked tokens on the client side, one via an http header, another via a cookie. On incoming requests, match the tokens.

### AUTHED_TOKEN

Persist a token via an http header linked to the currently authenticated user. Validate agains the user for incoming requests.

Requires `getUserToken` to be set in options

### AUTHED_DOUBLE_SUBMIT

A combination of `DOUBLE_SUBMIT` and `AUTHED_TOKEN`, either strategy passing will allow the request to go through.