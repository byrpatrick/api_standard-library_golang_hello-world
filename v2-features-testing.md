Tasks list -

### core features

- [x] vendor neutral (Is this library vendor neutral? #40)
    - branch `with-go-jwt-middleware` doesn't uses ANY Auth0 specific feature. All the logic is as per standard JWT
      specs.
- [x] replaceable validation logic (replace jwt-go #73)
    - branch `with-go-jwt-middleware` uses alternate validation logic with go-jose.v2/jwt)
- [x] allow custom error handler (Can't override ErrorHandler in New(Options) #51)
    - branch `core-v2-feature-test`, the `testErrorHandler` always raises internal server error.
- [x] error handler interface should take error type and not just string (Error handler interface is too restricted #52)
    - branch `core-v2-feature-test`, the `testErrorHandler` inspects the error type raised from core. It is no longer
      a `string`
- [x] clone request instead of shallow copy (CheckJWT should use net/http.Request.Clone #62)
    - `jwtmiddleware.CheckJWT` function utilizes following snippet to build up the request passed further down in the
      middleware chain. The `net/http.Request.Clone` is used as expected.
       ```go
        r = r.Clone(context.WithValue(r.Context(), ContextKey{}, validToken))
        ```
- [x] add FromCookie token extractor (add FromCookie token extractor #10 and Why you are not extracting token from session
  cookie? #63)
    - The `testTokenExtractor` uses `v2-test-cookie` cookie in addition to the `Authorization` header. Test successfully
      with `curl --cookie "v2-test-cookie=..."`
- [x] look at context key (allow JWT properties to be stored under non-string context key #64)
    - The `jwtmiddleware.ContextKey` is declared as empty struct (one of golang trick for least memory overhead) and it
      is used as the key to store JWT properties.
- [x] reorder fields for better alignment (Reorder fields in options for better alignment #61)
    - this feature is yet to completed and the PR is NOT yet merged to master. Requested change in the `Options` struct
      are not visible on the v2 branch yet.
- do not exclude SA1029 from linting (Makefile and workflows - see allow JWT properties to be stored under non-string
  context key #64)
    - Not sure how to verify this
- [x] look into providing a caching key provider feat: add JWKS provider to the josev2 validator #97
    - The code in this branch is using `josev2.CachingJWKSProvider` that caches the JWKS keys.
- [x] examples
    - Used number of examples from following sources. Admittedly, more examples would help by showing all the features
      from v2 effectively in the examples itself.
        - https://github.com/auth0/go-jwt-middleware/blob/v2/examples/http-example/main.go
        - https://github.com/auth0/go-jwt-middleware/blob/v2/examples/http-jwks-example/main.go
- [x] use github.com/pkg/errors -use github.com/pkg/errors #98
    - verified using code inspection. All "errors" imports have been replaced with "github.com/pkg/errors"

### validation features

- [x] support custom claims (Support for custom Claims #53)
    - the `core-v2-features-tests` uses `PermissionsClaim` to obtain custom permissions added as claim by Auth0. These
      additions are done in generic way without having any dependency on Auth0 itself.
- support clock skew (Clock skew can cause JWT parsing to fail #58)
    - To be tested
- add option for additional checks (add option for additional checks #74)
    - To be tested

### before launch

- update all documentation here (use go doc)
- update main Auth0 docs
- update Auth0 quickstarts
- create migration guide
- add a migration guide #99
- blog post about release