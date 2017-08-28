# jwt-csrf

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
* **csrfDriver** : String (Optional) - CSRF driver/strategy to use. Defaults to `DOUBLE_SUBMIT`.
* **expiresInMinutes** : Number (Optional) - A token's expiration time.  Defaults to `60`.
* **headerName** : String (Optional) - The name of the response header that will contain the csrf token. Defaults to `x-csrf-jwt`.
* **excludeUrls** : Array (Optional) - An array of elements that can be comprised of any of the following
 * A **regular expression object**. The request url will be compared using RegExp.test() using the regular expression supplied here
 * A **two element array** with the first being a string based regular expression and the second being the regular expression options such as "i" or "g". A regular expression will be created and tested against the request url. This is the ideal way to create a regular expression if the excludUrls are defined in a JSON file.
 * **A string**. This string will be tested as a regular expression with no regexp options. If this doesn't match the `request.originalUrl`, then it will be tested against the url as a direct string match.
* **getUserToken** : Function (Optional) - Get a user specific token for the `AUTHED_TOKEN` and `AUTHED_DOUBLE_SUBMIT` strategies. Must accept `req` and return a user-specific token (like a user id) for a known user.
* **getCookieDomain** : Function (Optional) - Must accept `req` and return a domain that the cookie will be scoped for (Ex: ".mysite.com").  Otherwise, defaults to the domain inside of the request.

## CSRF Drivers

##### DOUBLE_SUBMIT

Persist two linked tokens on the client side, one via an http header, another via a cookie. On incoming requests, match the tokens.

##### AUTHED_TOKEN

Persist a token via an http header linked to the currently authenticated user. Validate against the user for incoming requests.

Requires `getUserToken` to be set in options

##### AUTHED_DOUBLE_SUBMIT

A combination of `DOUBLE_SUBMIT` and `AUTHED_TOKEN`, either strategy passing will allow the request to go through.


## Client side

Note that jwt-csrf **only** works for ajax calls, not full-page posts, since it relies on being able to set and read http headers.

### Persisting the csrf token

Firstly, you will need to pass the token down in your initial page render. You can get the value as follows on the server-side, to insert into your initial html:

```javascript
var jwtCsrf = require('jwt-csrf');
var token = jwtCsrf.getHeaderToken(req, res, { secret: mySecret });
```

You have two options for persisting the csrf token on the client side:

#### 1. Manually

- On every ajax response, persist the `x-csrf-jwt` header
- On every ajax request, send the persisted `x-csrf-jwt` header

For example:

```javascript
var csrfJwt;

jQuery.ajax({
    type: 'POST',
    url: '/api/some/action',
    headers: {
        'x-csrf-jwt': csrfJwt
    },
    success: function(data, textStatus, request){
        csrfJwt = request.getResponseHeader('x-csrf-jwt');
    }
});
```

#### 2. Automatically, by patching XMLHttpRequest

```javascript
var jwtCsrf = require('jwt-csrf/client');
jwtCsrf.setToken(initialToken);
jwtCsrf.patchXhr();
```

This will hook into each request and response and automatically persist the token on the client side for you.
