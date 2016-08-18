// Type definitions for jwt-csrf 4.0.5
// Project: https://github.com/krakenjs/jwt-csrf
// Definitions by: Paul Lucas <https://github.com/pauljlucas>
// Definitions: https://github.com/DefinitelyTyped/DefinitelyTyped


declare module "jwt-csrf" {
    import * as express from "express";

    function middleware(options?: {
        /**
         * Your application's secret, must be cryptographically complex
         */
        secret: string;
        /**
         * CSRF driver/strategy to use. Defaults to DOUBLE_SUBMIT
         */
        csrfDriver?: string;
        /**
         *  A token's expiration time. Defaults to 60.
         */
        expiresInMinutes?: number;
        /**
         * The name of the response header that will contain the csrf token. Defaults to x-csrf-jwt
         */
        headerName?: string;
        /**
         * An array of urls to exclude from csrf protection. Not recommended unless you know what you're doing
         */
        excludeUrls?: [string];
        /**
         * Get a user specific token for the AUTHED_TOKEN and AUTHED_DOUBLE_SUBMIT strategies. Must accept req and return a user-specific token (like a user id) for a known user.
         */
        getUserToken?: Function;
        /**
         * Must accept req and return a domain that the cookie will be scoped for (Ex: ".mysite.com"). Otherwise, defaults to the domain inside of the request.
         */
        getCookieDomain?: Function;
    }): express.RequestHandler;

    function getHeaderToken(req: express.Request, res: express.Response, secret: {
        /**
         * Your application's secret, must be cryptographically complex
         */
        secret: string;
    }): string;

}