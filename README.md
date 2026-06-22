# sml-jwt

[![CI](https://github.com/sjqtentacles/sml-jwt/actions/workflows/ci.yml/badge.svg)](https://github.com/sjqtentacles/sml-jwt/actions/workflows/ci.yml)

JSON Web Tokens (RFC 7519) for the Standard ML web stack, using JWS compact
serialization (RFC 7515) with the HMAC signature family.

Built on [`sml-crypto`](https://github.com/sjqtentacles/sml-crypto) (HMAC-SHA256
+ constant-time compare), [`sml-codec`](https://github.com/sjqtentacles/sml-codec)
(Base64url), and [`sml-json`](https://github.com/sjqtentacles/sml-json) (claim
encode/parse) -- all vendored under `lib/` and committed, so builds need no
network. Pure Standard ML over the Basis library.

Verified on **MLton** and **Poly/ML** against the RFC 7515 Appendix A.1
HS256 worked example.

> **Authenticity, not secrecy.** A JWS token is tamper-evident but its payload
> is readable (Base64). Don't put secrets in a token payload.

## Algorithms

Only **HS256** is implemented. The vendored crypto stack provides HMAC over
SHA-256 only -- there is no SHA-384 or SHA-512 in the monorepo -- so HS384 and
HS512 are intentionally *absent* rather than faked. The `alg` datatype carries
only what can actually be computed; adding HS384/HS512 is a matter of adding
those hashes to `sml-codec` and one case to `Jwt.macOf`. The verifier never
accepts `alg:"none"`.

## API

```sml
structure Jwt : sig
  datatype alg = HS256
  type claims = (string * Json.json) list

  datatype ('ok, 'err) result = Ok of 'ok | Err of 'err
  datatype error =
      Malformed | BadHeader | UnsupportedAlg | BadSignature
    | BadPayload | Expired | NotYetValid

  val encodeB64u : string -> string                 (* base64url, no padding *)
  val decodeB64u : string -> string option

  val sign     : {alg : alg, secret : string, claims : claims} -> string
  val verifyAt : {secret : string, now : int} -> string -> (claims, error) result
  val verify   : {secret : string} -> string -> (claims, error) result
end
```

A token is `base64url(header) "." base64url(payload) "." base64url(signature)`,
where the header is `{"alg":"HS256","typ":"JWT"}`, the payload is the
JSON-encoded claim set, and the signature is the HMAC-SHA256 of
`header_b64 ++ "." ++ payload_b64`.

`verifyAt` takes an injected `now` (seconds since the epoch) so verification is
deterministic and testable; `verify` uses the real wall clock. Both recompute
the MAC, compare it in constant time (full length, no early exit), parse the
payload, and enforce `exp` (reject when `now >= exp`) and `nbf` (reject when
`now < nbf`).

### Example

```sml
val secret = "server-secret"
val tok =
  Jwt.sign { alg = Jwt.HS256, secret = secret,
             claims = [ ("sub", Json.JStr "alice")
                      , ("exp", Json.JInt 2000) ] }

(* later, on the next request *)
val claims =
  case Jwt.verifyAt {secret = secret, now = 1500} tok of
      Jwt.Ok cs => cs                       (* the claim list *)
    | Jwt.Err Jwt.Expired => raise Fail "token expired"
    | Jwt.Err _ => raise Fail "invalid token"
```

## Example

`make example` builds and runs [`examples/demo.sml`](examples/demo.sml), which
reproduces the RFC 7515 A.1 HS256 vector and runs a sign/verify round-trip with
an injected clock:

```
$ make example
RFC 7515 A.1 HS256 worked example:
  signature segment = dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
  verify (now=1300819379) = Ok

Sign / verify round-trip (HS256):
  token = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJhZG1pbiIsImV4cCI6MjAwMCwibmJmIjoxMDAwfQ.daQ40VSJuLVhiDYOdqjGJW-Fjm0JoOfXng7cqHQ_mMY
  verify (now=1500, in window) = Ok
  verify (now=2000, expired)   = Err Expired
  verify (now=500, not yet)    = Err NotYetValid
  verify (wrong secret)        = Err BadSignature
```

## Build & test

```sh
make test        # MLton
make test-poly   # Poly/ML
make all-tests   # both
make example     # build + run the demo
make clean
```

## Installing with smlpkg

```sh
smlpkg add github.com/sjqtentacles/sml-jwt
smlpkg sync
```

Reference `lib/github.com/sjqtentacles/sml-jwt/sml-jwt.mlb` from your own
`.mlb`, or feed `sources.mlb` to `tools/polybuild` (Poly/ML). The `sml-crypto`,
`sml-codec`, `sml-json` (and transitive `sml-parsec`) dependencies are vendored
under `lib/` and committed.

## Tests

24 deterministic checks: base64url round-trips across every padding class, the
RFC 7515 A.1 HS256 vector (sign produces the RFC's expected signature segment;
verify accepts the RFC's compact token), sign/verify round-trip with claim
recovery, tampered-payload and wrong-secret rejection, garbage-token handling,
`exp`/`nbf` window enforcement with an injected clock, and rejection of
`alg:"none"` / alg mismatch / missing alg. Run `make all-tests`.

## License

MIT. See [LICENSE](LICENSE).
