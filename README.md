# Braintree TechExpo Competition

Thanks for participating in the Braintree TechExpo competition! Your challenge is to create a simple web or mobile app that integrates with Braintree. You can find basic docs for integrating Braintree [here](https://developers.braintreepayments.com/start/overview).

Your challenge is just to create a client-side integration, we've already created the merchant server for you. We'll be giving away prizes to the 
first individuals or teams who are able to do any of the following:

 - [Create a transasction](https://developers.braintreepayments.com/guides/transactions/ruby)
 - [Create a customer](https://developers.braintreepayments.com/guides/customers/ruby)
 - [Vault a payment method](https://developers.braintreepayments.com/guides/payment-methods/ruby)

To keep your integration simple, we've already implemented a merchant server in Sandbox that you should use. There a just a few endpoints you'll need to know:
* `GET /client_token` - retrieve a client token embedded in JSON under the key `client_token`. You use this client token to initalize your [Braintree Client](https://developers.braintreepayments.com/guides/authorization/client-token).
* `POST /nonce/transaction` - create a $1 transaction with a nonce. The nonce should be included as a query param, e.g., `http://<server>/nonce/transaction?nonce=your-nonce-from-braintree`.
* `PUT /customers/:customer_id` - creates a customer with the given customer ID. You can then use this customer Id to vault a payment method.
* `POST /customers/:customer_id/vault` - vaults a payment method associated with a nonce. Again, the nonce should be included as a query param on the url, e.g, `http://<server>/customers/your-customer-id/vault?nonce=your-nonce-from-braintree`.


# But how will we know who won??

Good question! Make sure you include your email as a header in every request to the endpoints listed above, e.g., `-H "Email: moneymover@paypal.com"`
