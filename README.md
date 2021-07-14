# Hello World API: Golang #

This repository contains a Golang API server. You'll secure these APIs with Auth0 to practice making secure API calls
from a client application.

## Get Started

Run the API server:

```shell
go run .
```

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
