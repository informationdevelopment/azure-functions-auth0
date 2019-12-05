# azure-functions-auth0
Auth0 authentication middleware for Azure Functions.

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
