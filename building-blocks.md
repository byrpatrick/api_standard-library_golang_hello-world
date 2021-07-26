# Golang and Auth0 Building Blocks

This document walks you through the building blocks required to successfully integrate Auth0 authentication in your
golang API project. This is assumed that you are using golang `net/http` for setting up your APIs.

In this quick guide, you will examine the building blocks of implementing authentication with Auth0 in a golang
application using `net/http` for APIs. You can then create complex yet secure apps using these building blocks in your
application.

A common authentication strategy for golang APIs typically has following building block

- A routing setup that delegate API calls to matching handlers. Optionally, with a set of
  middleware [HandleFunc](https://pkg.go.dev/net/http#HandleFunc) chained together.
- Various API [Handlers](https://pkg.go.dev/net/http#Handler) which are responsible for generating appropriate response
  as per your business needs and sending it across to client.
- Among the middlewares, an authentication middleware that is responsible for parsing the validating the Auth0
  authentication token.

## Routing setup

You can use [ServerMux](https://pkg.go.dev/net/http#ServeMux) for setting up a simple routing engine as in following
example -

```go
package main

import (
	"log"
	"net/http"
)

func apiHandler(rw http.ResponseWriter, req *http.Request) {
	// this is where you implement the logic
	bytes := []byte("API successful Response")
	rw.Header().Add("Content-Type", "text/plain")
	_, err := rw.Write(bytes)
	if err != nil {
		log.Print("http response write error", err)
	}
}

func main() {
	router := http.NewServeMux()
	router.Handle("/api/example", http.HandlerFunc(apiHandler))

	server := &http.Server{
		Addr:    ":6060",
		Handler: router,
	}

	log.Printf("API server listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}
```

## Protect an API

To protect an API, you should create a middleware that takes care of validating the Auth0 token and add this middleware
in the routing setup. The validation middleware shall perform following tasks -

- Fetch the Auth0 tenants Json Web Keys (JWK), the keys are available
  at `https://my-tenant-domain-name/.well-known/jwks.json`. This is a one time operation and it is recommended to do it
  at application startup time. Fetching keys in the middleware flow is discouraged since it'll add unnecessary latency
  in the API invocation.
- Parse the jwt string from HTTP requests `Authorization` header
- Convert the jwt string to a [jwt.Token](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwt#Token) type while validating
  it with tenants JWK.
- Verify the audience within the token matches with the API setup on Auth0 management setup.

Following snippet adds these pieces as functions. For this example, we are using [jwx](github.com/lestrrat-go/jwx). You
are free to use any library of your own preference.

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

const (
	auth0Audience = "https://api.example.com"
	auth0Domain   = "my-tenant-name.region.auth0.com"
)

var (
	tenantKeys jwk.Set
)

func fetchTenantKeys() {
	set, err := jwk.Fetch(context.Background(),
		fmt.Sprintf("https://%s/.well-known/jwks.json", auth0Domain))
	if err != nil {
		log.Fatalf("failed to parse tenant json web keys: %s\n", err)
	}
	tenantKeys = set
}

func extractToken(req *http.Request) (jwt.Token, error) {
	bearerAndToken := strings.Split(req.Header.Get("Authorization"), " ")
	if len(bearerAndToken) < 2 {
		return nil, errors.New("malformed authorization header")
	}
	token, err := jwt.Parse([]byte(bearerAndToken[1]), jwt.WithKeySet(tenantKeys),
      jwt.WithValidate(true), jwt.WithAudience(auth0Audience))
	if err != nil {
		return nil, err
	}
	return token, nil
}

func validateToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		_, err := extractToken(req)
		if err != nil {
			fmt.Printf("failed to build token: %s\n", err)
			rw.WriteHeader(http.StatusUnauthorized)
			rw.Write([]byte("Unauthorized!!"))
			return
		}
		next.ServeHTTP(rw, req)
	})
}
```

The updated main function looks like following with validation middleware integrated:

```go
func main() {
	fetchTenantKeys()

	router := http.NewServeMux()
	router.Handle("/api/example", validateToken(http.HandlerFunc(apiHandler)))

	server := &http.Server{
	Addr:    ":6060",
	Handler: router,
	}

	log.Printf("API server listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}
```