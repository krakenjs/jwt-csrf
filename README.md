jwt-csrf
========
[![Dependency Status](http://daviddm-5042.ccg21.dev.paypalcorp.com:1337/NodeXOShared/jwt-csrf.svg)](http://daviddm-5042.ccg21.dev.paypalcorp.com:1337/NodeXOShared/jwt-csrf)
[![devDependency Status](http://daviddm-5042.ccg21.dev.paypalcorp.com:1337/NodeXOShared/jwt-csrf/dev-status.svg)](http://daviddm-5042.ccg21.dev.paypalcorp.com:1337/NodeXOShared/jwt-csrf#info=devDependencies)

For creating and validating JWTs.  Can be used as an API or Express middleware.

## Middleware (recommended)

#### Example

 ```javascript
var express = require('express');
var app = express();

var jwtCSRF = require('jwt-csrf');
var jwtMiddleware = jwtCSRF.middleware(options); // This can be used like any other Express middleware

app.use(jwtMiddleware); // Executed on all requests

app.post('/payment', someOtherMiddleware);
 ```

`options` is an Object with the following format:
* **expiresInMinutes** : Number (Optional) - A token's expiration time.  Defaults to 20 minutes.
* **secret** : String (Required) - Your application's secret, must be cryptographically complex :)
* **macKey** : String (Required) - Your application's mac key, must be cryptographically complex :)

## API

### Create multiple JWTs (for a Double Submit CSRF implementation)

#### Example
```javascript
var jwtcsrf = require('jwt-csrf');
var tokens = jwtcsrf.createTokens(options); // options contains "secret" and "macKey"

res.setHeader('x-csrf-jwt', tokens.header);
res.setCookie('csrf-jwt', tokens.cookie);
```

`options` is an Object with the following format:
* **expiresInMinutes** : Number (Optional) - A token's expiration time.  Defaults to 20 minutes.
* **secret** : String (Required) - Your application's secret, must be cryptographically complex :)
* **macKey** : String (Required) - Your application's mac key, must be cryptographically complex :)

### Create a single JWT

#### Example
```javascript
var jwtcsrf = require('jwt-csrf');
var token = jwtcsrf.create(options, payload);

res.header('x-csrf-jwt', token);
```

`options` is an Object with the following format:
* **expiresInMinutes** : Number (Optional) - A token's expiration time.  Defaults to 20 minutes.
* **secret** : String (Required) - Your application's secret, must be cryptographically complex :)
* **macKey** : String (Required) - Your application's mac key, must be cryptographically complex :)

`payload` is an Object that contains a cryptographically strong key (identical to each user, or at random)


### Validate JWT

Returns a promise (Sorry, we're evil.  Submit a PR if you want!)

#### Example
```javascript
var jwtcsrf = require('jwt-csrf');

// "req" contains a "x-csrf-jwt" header and "csrf-jwt" cookie
return jwtcsrf.validate(options, req).then(function (isValid) {
  next();
}).catch(function (err) {
  res.status(401);
  return next(new Error(err));
});
```

`options` is an Object with the following format:
* **secret** : String (Required) - Your application's secret, must be cryptographically complex :)
* **macKey** : String (Required) - Your application's mac key, must be cryptographically complex :)
