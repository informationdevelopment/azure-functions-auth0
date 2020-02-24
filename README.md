# azure-functions-auth0
Auth0 authentication middleware for Azure Functions.

**This package has been deprecated and is no longer maintained. Please use [@informationdevelopment/auth0-serverless](https://github.com/informationdevelopment/auth0-serverless) instead.**

### Installation
azure-functions-auth0 can be installed with NPM:

```bash
npm install @informationdevelopment/azure-functions-auth0
```

### Usage
```javascript
const azureFunctionsAuth0 = require('@informationdevelopment/azure-functions-auth0');

const auth = azureFunctionsAuth0.createMiddleware(
    'example.auth0.com',                    // App domain
    'https://example.azurewebsites.net/api' // API identifier (audience)
);

module.exports = auth('read:movies', async (context, req) => {
    return db.getMovies();
});
```
