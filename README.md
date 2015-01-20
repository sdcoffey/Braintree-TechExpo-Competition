# Sample Merchant Server

A dumb merchant server that makes it easy to work on client SDKs and switch between Braintree environments easily.

## Running Locally

```
bundle
cp config_example.yml config.yml
$EDITOR config.yml # Modify this file with your development/sandbox/production credentials.
./bin/start_server
```

Now you'll be able to obtain a client token with `curl localhost:3132/client_token`.

For a full listing of available endpoints, `curl localhost:3132`.

## Deployment

This app is deployed to a number of heroku instances:

* http://braintree-sample-merchant.herokuapp.com/
* http://executive-sample-merchant.herokuapp.com/
* http://braintree-qa-merchant.herokuapp.com/

You can access these instances via the Braintree organizational heroku account. Deploying is as simple as `git push`.

A number of our demo apps for iOS and Android rely on these instances.

It's easy to spin up a new instance of your own:

1. Create a new heroku app: `heroku create [NAME]`
2. Setup the enviornment variables `MERCHANT_ID`, `ENVIRONMENT`, `PUBLIC_KEY` and `PRIVATE_KEY` using `heroku config:set`
3. Deploy with `git push heroku`

You can also use `heroku clone --app braintree-sample-merchant`.

## API Examples

* `GET /client_token` - retrieve a client token embedded in JSON under the key `client_token`
* `GET /client_token?decode=1` - retrieve a client token decoded client token
* `GET /client_token?version=1` - retrieve a `v1` client token
* `GET /config/current` - see which Braintree environment is being used
* `GET /` - retrieve an API listing

### Dependencies

This app is referenced in braintree-{ios,android} and the docs. If you make changes, make sure they are compatible before deploying changes.
