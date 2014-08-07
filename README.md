# Sample Merchant Server

The easiest way to get started with a client SDK without a server implementation.

If you'd like to try things out without a server of your own, you can use this server, which is based on the `taproot` gem.

## Getting Started

```
export GITHUB_OAUTH=YOUR_GITHUB_OAUTH_TOKEN # See heroku config or curl -u 'GITHUB_USERNAME' -d '{"scopes":["repo"],"note":"Braintree Sample Merchant"}' https://api.github.com/authorizations
cd braintree-ios/Sample\ Merchant\ Server
bundle
$EDITOR taproot.yml # Modify this file with your sandbox credentials.
taprootd
```

Now you'll be able to obtain a client token with `curl localhost:3132/client_token`. 

For a full listing of available endpoints, `curl localhost:3132`.

## Deployment

This app is deployed to heroku at http://braintree-sample-merchant.herokuapp.com/ and http://executive-sample-merchant.herokuapp.com/. 

To deploy a new instance:

1. Create a new heroku app: `heroku create`
2. Setup the enviornment variables `MERCHANT_ID`, `ENVIRONMENT`, `PUBLIC_KEY` and `PRIVATE_KEY`
3. Deploy `git push heroku`

### Dependencies

This app is referenced in braintree-{ios,android} and the docs. If you make changes, make sure those are also up to date.
