# Braintree TechExpo Competition

Welcome to the Braintree Tech Expo integration challenge! 

We've built Braintree's SDKs to be flexible and easy to integrate, and we'd like to show you. Your challenge is to create a simple web or mobile app that integrates with Braintree. You can find basic docs for integrating Braintree [here](https://developers.braintreepayments.com/start/overview).

Braintree integrations have two components: the server side, and the client side. We've taken care of the server side for you (see below).

Your challenge is to complete the integration in a client side app. You can use any platform you like: Web, iOS, and Android.

We'll be giving away sweet Braintree sweatshirts to the first individuals who are able to do any of the following on each of our platforms, along with a few other randomly chosen successful integrations:

 - Create a transasction
 - Create a customer
 - Vault a payment method

## The Server

To keep your integration simple, we've already implemented a merchant server in Sandbox that you should use. There a just a few endpoints you'll need to know:

 - `GET /client_token` - retrieve a client token embedded in JSON under the key `client_token`. You use this client token to initalize your [set up your client](https://developers.braintreepayments.com/start/hello-client/). 

 - `POST /nonce/transaction` - create a $1 transaction with a nonce. The nonce should be included as a query param, e.g., `/nonce/transaction?nonce=your-nonce-from-braintree`.

 - `PUT /customers/:customer_id` - creates a customer with the given customer ID. You can then use this customer id to vault a payment method.

 - `POST /customers/:customer_id/vault` - vaults a payment method associated with a nonce. Again, the nonce should be included as a query param on the url, e.g, `/customers/your-customer-id/vault?nonce=your-nonce-from-braintree`.

For more context on these actions, check out our [server-side guides](https://developers.braintreepayments.com/guides/overview).

Our sample merchant server is deployed in Heroku, and can be found at 
```
https://samplemerchant-techexpo.herokuapp.com
```

## Docs

Everything you need to get through the integration should be available on the Braintree developer docs site. We recommend checking out the [Overview](https://developers.braintreepayments.com/start/overview) and then [Set Up Your Client](https://developers.braintreepayments.com/start/hello-client/javascript/v2).

Note that you can change the client language you'll see across our documentation from a dropdown near the top of each page. 

### Sample Payment Method numbers

You can find a list of sample Credit Card numbers enabled in Sandbox [here](https://developers.braintreepayments.com/reference/general/testing/ruby#credit-card-numbers).

## Prize Mechanics

We expect the integration wil take about 45 minutes to do if you're working on a platform that you're comfortable with. If you find it to be much harder than that, let us know – we'd love your feedback.

We'll send a sweatshirt to the first person to complete one of the challenge tasks on each of our three platforms (iOS, Android, and Web). We'll also send several more sweatshirts to randomly-chosen successful integrations that we receive by the end of the day on Friday (August 12th).

In order to identify yourself so that we can identify you and send you your swag, be sure you include your email as a header in every request to the endpoints listed above with the key `Email`, for example:
```bash
$ curl -X POST -H "Email: moneymover@paypal.com" https://samplemerchant-techexpo.herokuapp.com/nonce/transaction?nonce=a-great-nonce
```

Thanks again for participating!
