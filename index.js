const {promisify} = require('util');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const verifyAsync = promisify(jwt.verify);
const algorithms = ['RS256', 'HS256'];
const createFailureResponse = (status, message) => ({status, body: {message}});

module.exports.createMiddleware = (domain, audience, key) => {
    const issuer = `https://${domain}/`;

    // If no key is provided, use a function that looks for a public key hosted on the Auth0 tenant
    if (!key) {
        const client = jwksClient({jwksUri: `https://${domain}/.well-known/jwks.json`});
        key = (header, callback) => {
            const getSigningKeyAsync = promisify(client.getSigningKey).bind(client);
            getSigningKeyAsync(header.kid).then(key => {
                const signingKey = key.publicKey || key.rsaPublicKey;
                callback(null, signingKey);
            }).catch(err => {
                callback(err);
            });
        };
    }

    return (scopes, httpTrigger) => {
        return async (context, ...args) => {
            const {method, headers, originalUrl: url} = context.req;
            try {
                // Strip out the "Bearer " text from the beginning of the Authorization header
                const token = headers.authorization.slice(7);

                // Verify the JSON web token. If no exception is thrown, the token is valid.
                const options = {algorithms, audience, issuer};
                const payload = await verifyAsync(token, key, options);

                // Verify scopes, if defined.
                if (scopes) {
                    const authorizedScopes = payload.scope.split(' ');
                    const httpTriggerScopes = [].concat(scopes);   // scopes can be a single value or an array

                    // Ensure that all scopes defined by the authenticated Azure Function
                    // are included in the list of authorized scopes.
                    if (!httpTriggerScopes.every(scope => authorizedScopes.includes(scope))) {
                        context.log.error(`azure-functions-auth0: One or more missing scopes in ${method} request from ${url}.`);
                        context.res = createFailureResponse(403, 'Forbidden');
                        return;
                    }
                }

                context.log(`azure-functions-auth0: Successfully authorized a ${method} request from ${url}.`);
                return httpTrigger(context, ...args);
            }
            catch (err) {
                if (err instanceof jwt.JsonWebTokenError ||
                    err instanceof jwt.TokenExpiredError ||
                    err instanceof jwt.NotBeforeError) {
                    // Authentication failed; log the error and return HTTP 401 Unauthorized
                    context.log.error(`azure-functions-auth0: Unauthorized ${method} request from ${url}: ${err.message}`);
                    context.res = createFailureResponse(401, 'Unauthorized');
                }
                else {
                    context.log.error(`azure-functions-auth0: An unexpected error has occurred.\n${err.stack}`);
                    context.res = createFailureResponse(500, 'Internal Server Error');
                }
            }
        };
    };
}

module.exports.unauthenticatedResponse = {res: {status: 401, body: {err: "Unauthenticated"}}};
