# Overview

tus-server provides an implementation of the [TUS protocol](https://tus.io) for resumable uploads built on [cloudflare workers](https://www.cloudflare.com/products/workers/) and [R2](https://www.cloudflare.com/products/r2/). 

# Building
You'll need [Node.js](https://nodejs.org/). If you use [nvm](https://github.com/creationix/nvm) run
```
nvm use
```

To install dependencies,
```
npm install
```

In order to deploy to cloudflare or use non-local dev mode, use the [`wrangler`](https://developers.cloudflare.com/workers/wrangler/install-and-update/) utility. Follow those instructions to authenticate with your cloudflare account.

# Testing

The server assumes an authentication is provided via a signature using a shared secret. You can provide one for development by setting `SHARED_AUTH_SECRET` in `.dev.vars`, e.g.
```
> cat .dev.vars
SHARED_AUTH_SECRET = "test"
```

To run a dev server you can interact with over localhost
```
wrangler dev
```

To run unit tests,
```
npm test
```

# Deploying

## One time setup
1. Create an R2 bucket and update the binding in `wrangler.toml`
2. Add a base64 encoded shared auth secret with `wrangler secret put SHARED_AUTH_SECRET`

```
wrangler deploy -e <staging|production>
```

# License

Copyright 2023 Signal Messenger, LLC

Licensed under the [AGPLv3](LICENSE)

