(* jwt.sig

   JSON Web Tokens (RFC 7519) using JWS compact serialization (RFC 7515) with
   the HMAC-SHA2 signature family. Only HS256 is implemented, because the
   vendored crypto stack provides HMAC over SHA-256 only (there is no SHA-384
   or SHA-512 anywhere in the monorepo). HS384/HS512 are intentionally absent
   rather than faked: the `alg` datatype carries only what we can actually
   compute.

   A signed token is the compact string

       base64url(header) "." base64url(payload) "." base64url(signature)

   where the header is the fixed JSON object {"alg":"HS256","typ":"JWT"}, the
   payload is the JSON-encoded claim set, and the signature is the HMAC-SHA256
   of the ASCII string `header_b64 ++ "." ++ payload_b64`.

   This gives integrity/authenticity, not confidentiality: the payload is
   readable (Base64), just not forgeable without the secret. *)

signature JWT =
sig
  (* Supported signature algorithms. Only HS256 can be computed with the
     available hashes; the type deliberately has no other inhabitants. *)
  datatype alg = HS256

  (* A claim set is an ordered association list of JSON members, matching the
     `Json.json` object representation. Registered claims like "exp"/"nbf" are
     ordinary members holding `Json.JInt` values (seconds since the epoch). *)
  type claims = (string * Json.json) list

  (* Verification result. We define our own two-armed type rather than lean on
     a Basis `result` (not portably present) or the vendored parsec `result`
     (whose error arm is a parse error, not ours). *)
  datatype ('ok, 'err) result = Ok of 'ok | Err of 'err

  (* Why verification can reject a token. *)
  datatype error =
      Malformed        (* not three base64url parts, or undecodable *)
    | BadHeader        (* header is not JSON, or missing/utf wrong fields *)
    | UnsupportedAlg   (* header alg is absent, "none", or not HS256 *)
    | BadSignature     (* signature does not match the recomputed MAC *)
    | BadPayload       (* payload is not a JSON object *)
    | Expired          (* now >= exp *)
    | NotYetValid      (* now < nbf *)

  (* base64url (RFC 4648 sec 5) without padding, and its inverse. `decodeB64u`
     returns NONE on stray characters or a structurally invalid length. *)
  val encodeB64u : string -> string
  val decodeB64u : string -> string option

  (* sign {alg, secret, claims} -> compact JWS string. *)
  val sign : {alg : alg, secret : string, claims : claims} -> string

  (* verifyAt {secret, now} token: recompute the MAC, compare in constant
     time, parse the payload, and enforce exp/nbf against the injected `now`
     (seconds since the epoch). Deterministic: it never reads the real clock. *)
  val verifyAt : {secret : string, now : int} -> string -> (claims, error) result

  (* verify: like verifyAt but using the real wall clock (Time.now). Not used
     by the deterministic test suite. *)
  val verify : {secret : string} -> string -> (claims, error) result
end
