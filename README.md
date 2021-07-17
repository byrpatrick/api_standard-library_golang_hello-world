# Hello World API: Golang #

This repository contains a Golang API server. You'll secure these APIs with Auth0 to practice making secure API calls
from a client application.

## Get Started

### Register a Golang API with Auth0

- Open the [APIs](https://manage.auth0.com/#/apis) section of the Auth0 Dashboard.

- Click on the **Create API** button.

- Provide a **Name** value such as _Hello World API Server_.

- Set its **Identifier** to `https://api.example.com` or any other value of your liking.

- Leave the signing algorithm as `RS256` as it's the best option from a security standpoint.

- Click on the **Create** button.

> View ["Register APIs" document](https://auth0.com/docs/get-started/set-up-apis) for more details.

### Get API configuration values

Head back to your Auth0 API page, and follow these steps to get the Auth0 Audience:

![Get the Auth0 Audience to configure an API](https://images.ctfassets.net/23aumh6u8s0i/1CaZWZK062axeF2cpr884K/cbf29676284e12f8e234545de05dac58/get-the-auth0-audience)

- Click on the "Settings" tab.

- Locate the "Identifier" field and copy its value.

Now, follow these steps to get the Auth0 Domain value:

![Get the Auth0 Domain to configure an API](https://images.ctfassets.net/23aumh6u8s0i/37J4EUXKJWZxHIyxAQ8SYI/d968d967b5e954fc400163638ac2625f/get-the-auth0-domain)

- Click on the "Test" tab.

- Locate the section called "Asking Auth0 for tokens from my application".

- Click on the cURL tab to show a mock `POST` request.

- Locate your Auth0 domain, which is part of the `--url` parameter value: `tenant-name.region.auth0.com`.

**Tips to get the Auth0 Domain**

- The Auth0 Domain is the substring between the protocol, `https://` and the path `/oauth/token`.

- The Auth0 Domain follows this pattern: `tenant-name.region.auth0.com`.

- The `region` subdomain (`au`, `us`, or `eu`) is optional. Some Auth0 Domains don't have it.

### Run the API server:

Run the API server by using any of the following commands. Please replace `<auth0_identifier>` and `<auth0_domain>`
values appropriate as per your setup as per above instructions.

```shell
go run . -a <auth0_identifier> -d <auth0_domain>

# OR 
AUTH0_AUDIENCE=<auth0_identifier> AUTH0_DOMAIN=<auth0_domain> go run .

# OR
export AUTH0_AUDIENCE=<auth0_identifier>
export AUTH0_DOMAIN=<auth0_domain>
go run .
```

## Test the Protected Endpoints

You can get an access token from the Auth0 Dashboard to test making a secure call to your protected API endpoints.

Head back to your Auth0 API page and click on the "Test" tab.

Locate the section called "Sending the token to the API".

Click on the cURL tab of the code box.

Copy the sample cURL command:

```bash
curl --request GET \
  --url http://path_to_your_api/ \
  --header 'authorization: Bearer really-long-string-which-is-test-your-access-token'
```

Replace the value of `http://path_to_your_api/` with your protected API endpoint path (you can find all the available
API endpoints in the next section) and execute the command. You should receive back a successful response from the
server.

You can try out any of our full stack demos to see the client-server Auth0 workflow in action using your preferred
front-end and back-end technologies.

## API Endpoints

### 🔓 Get public message

```shell
GET /api/messages/public
```

#### Response

```shell
Status: 200 OK
```

```json
{
  "message": "The API doesn't require an access token to share this message."
}
```

### 🔓 Get protected message

> You need to protect this endpoint using Auth0.

```shell
GET /api/messages/protected
```

#### Response

```shell
Status: 200 OK
```

```json
{
  "message": "The API successfully validated your access token."
}
```

### 🔓 Get admin message

> You need to protect this endpoint using Auth0 and Role-Based Access Control (RBAC).

```shell
GET /api/messages/admin
```

#### Response

```shell
Status: 200 OK
```

```json
{
  "message": "The API successfully recognized you as an admin."
}
```
