const {promisify} = require('util');
const {JsonWebTokenError, TokenExpiredError, NotBeforeError} = require('jsonwebtoken');
const verifyJwtAsync = promisify(require('jsonwebtoken').verify);
const jwksClient = require('jwks-rsa');

const createFailureResponse = (status, message) => ({status, body: {message}});
const RES_401_UNAUTHORIZED = createFailureResponse(401, 'Unauthorized');
const RES_403_FORBIDDEN = createFailureResponse(403, 'Forbidden');
const RES_500_INTERNAL_SERVER_ERROR = createFailureResponse(500, 'Internal Server Error');

// Auth0 only supports RS256 and HS256
const ALLOWED_SIGNING_ALGORITHMS = ['RS256', 'HS256'];



module.exports.createMiddleware = (appDomain, apiIdentifier, key) => {
    const issuer = `https://${appDomain}/`;

    // If no key is provided, use a function that looks for a public key hosted on the Auth0 tenant
    if (!key) {
        const client = jwksClient({jwksUri: `https://${appDomain}/.well-known/jwks.json`});
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

    return (scopes, func) => {
        return async (context, ...args) => {
            const {method, headers, originalUrl: url} = context.req;
            try {
                if (!headers.authorization) {
                    // Returning the response in addition to assigning to context.res ensures
                    // that $return HTTP output bindings will work in addition to named bindings.
                    return context.res = RES_401_UNAUTHORIZED;
                }
                // The actual token begins after the "Bearer " string.
                const token = headers.authorization.slice(7);

                const options = {
                    algorithms: ALLOWED_SIGNING_ALGORITHMS,
                    audience: apiIdentifier,
                    issuer
                };
                // Verify the JSON web token. If no exception is thrown, the token is valid.
                const payload = await verifyJwtAsync(token, key, options);

                if (scopes) {
                    const tokenScopes = payload.scope.split(' ');
                    const funcScopes = scopes.split(' ');

                    // Ensure that all scopes required by the Azure Function
                    // are included in the list of authorized scopes.
                    if (!funcScopes.every(scope => tokenScopes.includes(scope))) {
                        context.log.error(`azure-functions-auth0: One or more missing scopes in ${method} request from ${url}.`);
                        return context.res = RES_403_FORBIDDEN;
                    }
                }

                context.log(`azure-functions-auth0: Successfully authorized a ${method} request from ${url}.`);
                return func(context, ...args);
            }
            catch (err) {
                if (err instanceof JsonWebTokenError || err instanceof TokenExpiredError || err instanceof NotBeforeError) {
                    context.log.error(`azure-functions-auth0: Unauthorized ${method} request from ${url}: ${err.message}`);
                    return context.res = RES_401_UNAUTHORIZED;
                }
                else {
                    context.log.error(`azure-functions-auth0: An unexpected error has occurred.\n${err.stack}`);
                    return context.res = RES_500_INTERNAL_SERVER_ERROR;
                }
            }
        };
    };
}
