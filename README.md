# Braintree TechExpo Competition

Thanks for participating in the Braintree TechExpo competition! Your challenge is to create a simple web or mobile app that integrates with Braintree. You can find basic docs for integrating Braintree [here](https://developers.braintreepayments.com/start/overview).

Your challenge is just to create a client-side integration, we've already created the merchant server for you. We'll be giving away prizes to the first individuals or teams who are able to do any of the following:

 - Create a transasction
 - Create a customer
 - Vault a payment method

To keep your integration simple, we've already implemented a merchant server in Sandbox that you should use. There a just a few endpoints you'll need to know:

 - `GET /client_token` - retrieve a client token embedded in JSON under the key `client_token`. You use this client token to initalize your [set up your client](https://developers.braintreepayments.com/start/hello-client/android/v2). 

 - `POST /nonce/transaction` - create a $1 transaction with a nonce. The nonce should be included as a query param, e.g., `/nonce/transaction?nonce=your-nonce-from-braintree`.

 - `PUT /customers/:customer_id` - creates a customer with the given customer ID. You can then use this customer id to vault a payment method.

 - `POST /customers/:customer_id/vault` - vaults a payment method associated with a nonce. Again, the nonce should be included as a query param on the url, e.g, `/customers/your-customer-id/vault?nonce=your-nonce-from-braintree`.

For more context on these actions, check out our [server-side guides](https://developers.braintreepayments.com/guides/overview).

Our sample merchant server is deployed in Heroku, and can be found at 
```
https://samplemerchant-techexpo.herokuapp.com
```

# Sample Payment Method numbers

You can find a list of sample Credit Card numbers enabled in Sandbox [here](https://developers.braintreepayments.com/reference/general/testing/ruby#credit-card-numbers).

# But how will we know who won??

Good question! Make sure you include your email as a header in every request to the endpoints listed above with the key `Email`, for example:
```bash
$ curl -X POST -H "Email: moneymover@paypal.com" https://samplemerchant-techexpo.herokuapp.com/nonce/transaction?nonce=a-great-nonce
```
