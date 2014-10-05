# Sample Merchant Server

The easiest way to get started with a client SDK without a server implementation.

If you'd like to try things out without a server of your own, you can use this server, which is based on the `taproot` gem.

## Running Locally

```
export GITHUB_OAUTH=YOUR_GITHUB_OAUTH_TOKEN # https://github.com/settings/applications#personal-access-tokens OR curl -u 'GITHUB_USERNAME' -d '{"scopes":["repo"],"note":"Braintree Sample Merchant"}' https://api.github.com/authorizations
cd braintree-ios/Sample\ Merchant\ Server
bundle
$EDITOR taproot.yml # Modify this file with your sandbox credentials.
taprootd
```

Now you'll be able to obtain a client token with `curl localhost:3132/client_token`. 

For a full listing of available endpoints, `curl localhost:3132`.

## Deployment

This app is deployed to a number of heroku instances:

* http://braintree-sample-merchant.herokuapp.com/
* http://executive-sample-merchant.herokuapp.com/
* http://braintree-qa-merchant.herokuapp.com/

A number of our demo apps for iOS and Android rely on these instances.

It's easy to spin up a new instance of your own:

1. Create a new heroku app: `heroku create [NAME]`
2. Setup the enviornment variables `MERCHANT_ID`, `ENVIRONMENT`, `PUBLIC_KEY` and `PRIVATE_KEY` using `heroku config:set`
3. Since the `Gemfile` relies on a private repository (https:/github.com/benmills/taproot.git), you will need to give Github access to your heroku instance via the `GITHUB_OAUTH` environment variable.
  * `heroku config:set GITHUB_OAUTH=YOUR_GITHUB_OAUTH_TOKEN # https://github.com/settings/applications#personal-access-tokens OR curl -u 'GITHUB_USERNAME' -d '{"scopes":["repo"],"note":"Braintree Sample Merchant"}' https://api.github.com/authorizations
4. Deploy with `git push heroku`

## API Examples

* `GET /client_token` - retrieve a client token embedded in JSON under the key `client_token`
* `GET /client_token?decode=1` - retrieve a client token decoded client token
* `GET /client_token?version=1` - retrieve a `v1` client token
* `GET /config/current` - see which Braintree environment is being used
* `GET /` - retrieve an API listing

### Dependencies

This app is referenced in braintree-{ios,android} and the docs. If you make changes, make sure they are compatible before deploying changes.
