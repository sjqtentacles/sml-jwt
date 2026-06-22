(* demo.sml - reproduce the RFC 7515 Appendix A.1 HS256 vector and run a
   sign/verify round-trip with an injected clock. Deterministic: same output on
   every run and compiler (fixed secret/claims, no RNG, no wall clock). *)

fun resultName r =
  case r of
      Jwt.Ok _ => "Ok"
    | Jwt.Err Jwt.Malformed => "Err Malformed"
    | Jwt.Err Jwt.BadHeader => "Err BadHeader"
    | Jwt.Err Jwt.UnsupportedAlg => "Err UnsupportedAlg"
    | Jwt.Err Jwt.BadSignature => "Err BadSignature"
    | Jwt.Err Jwt.BadPayload => "Err BadPayload"
    | Jwt.Err Jwt.Expired => "Err Expired"
    | Jwt.Err Jwt.NotYetValid => "Err NotYetValid"

(* RFC 7515 Appendix A.1 worked example. *)
val rfcSigningInput =
  "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
  ^ ".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQ"
  ^ "ogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
val rfcKey =
  case Jwt.decodeB64u
         ("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T"
          ^ "-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow") of
      SOME k => k | NONE => "<key decode failed>"
val rfcSig = Jwt.encodeB64u (Hmac.hmacSha256 rfcKey rfcSigningInput)
val rfcToken = rfcSigningInput ^ "." ^ rfcSig
val () = print "RFC 7515 A.1 HS256 worked example:\n"
val () = print ("  signature segment = " ^ rfcSig ^ "\n")
val () = print ("  verify (now=1300819379) = "
                ^ resultName (Jwt.verifyAt {secret = rfcKey, now = 1300819379} rfcToken) ^ "\n")

(* sign / verify round-trip with fixed claims. *)
val secret = "server-secret-key"
val claims = [ ("sub",  Json.JStr "alice")
             , ("role", Json.JStr "admin")
             , ("exp",  Json.JInt 2000)
             , ("nbf",  Json.JInt 1000) ]
val tok = Jwt.sign {alg = Jwt.HS256, secret = secret, claims = claims}
val () = print "\nSign / verify round-trip (HS256):\n"
val () = print ("  token = " ^ tok ^ "\n")
val () = print ("  verify (now=1500, in window) = "
                ^ resultName (Jwt.verifyAt {secret = secret, now = 1500} tok) ^ "\n")
val () = print ("  verify (now=2000, expired)   = "
                ^ resultName (Jwt.verifyAt {secret = secret, now = 2000} tok) ^ "\n")
val () = print ("  verify (now=500, not yet)    = "
                ^ resultName (Jwt.verifyAt {secret = secret, now = 500} tok) ^ "\n")
val () = print ("  verify (wrong secret)        = "
                ^ resultName (Jwt.verifyAt {secret = "other", now = 1500} tok) ^ "\n")
