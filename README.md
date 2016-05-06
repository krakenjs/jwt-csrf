# jwt-csrf

[![Dependency Status](http://tooling.paypalcorp.com/badges/npm/version/jwt-csrf.svg?style=flat-square)](http://tooling.paypalcorp.com/badges/npm/version/jwt-csrf.svg?style=flat-square)
[![Dependency Status](http://tooling.paypalcorp.com/badges/david/NodeXOShared/jwt-csrf.svg?style=flat-square)](http://tooling.paypalcorp.com/badges/david/NodeXOShared/jwt-csrf.svg?style=flat-square)
[![devDependency Status](http://tooling.paypalcorp.com:/badges/david/dev/NodeXOShared/jwt-csrf.svg?style=flat-square)](http://tooling.paypalcorp.com/badges/david/NodeXOShared/jwt-csrf.svg?style=flat-square)

For creating and validating JWTs.  Can be used as an API or Express middleware.

## Middleware

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

#### Handling errors

On errors, jwt-csrf will call `next(err)` with a `jwtCSRF.CSRFError`. If you want to handle this specifically, you can do so in a middleware:

```javascript
function(err, req, res, next) {
    if (err instanceof jwtCSRF.CSRFError) {
        explode();
    }
}
```
