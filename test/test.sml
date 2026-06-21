(* Tests for sml-jwt.

   HS256 vectors come from RFC 7515 Appendix A.1 (the JWS spec's worked
   example). Time-dependent claims are checked with an injected `now` so the
   suite is deterministic across compilers and never touches the wall clock. *)

structure JwtTests =
struct
  open Harness

  (* Pull the verify result apart for assertions. *)
  fun isOk (Jwt.Ok _) = true
    | isOk _ = false

  fun errName e =
    case e of
        Jwt.Malformed => "Malformed"
      | Jwt.BadHeader => "BadHeader"
      | Jwt.UnsupportedAlg => "UnsupportedAlg"
      | Jwt.BadSignature => "BadSignature"
      | Jwt.BadPayload => "BadPayload"
      | Jwt.Expired => "Expired"
      | Jwt.NotYetValid => "NotYetValid"

  fun resultName r =
    case r of
        Jwt.Ok _ => "Ok"
      | Jwt.Err e => "Err " ^ errName e

  fun run () =
    let
      val () = section "base64url round-trip"

      (* Cover all three length classes mod 3 so we exercise the 0/1/2 padding
         cases of standard base64 (base64url drops the '=' but the bit-packing
         is the same). *)
      fun roundtrips name s =
        checkString name
          (s, case Jwt.decodeB64u (Jwt.encodeB64u s) of
                  SOME d => d
                | NONE => "<decode failed>")

      val () = roundtrips "empty" ""
      val () = roundtrips "len 1 (2 pad)" "f"
      val () = roundtrips "len 2 (1 pad)" "fo"
      val () = roundtrips "len 3 (0 pad)" "foo"
      val () = roundtrips "len 4" "foob"
      val () = roundtrips "len 5" "fooba"
      val () = roundtrips "len 6" "foobar"
      (* Bytes that map to '+'/'/' in standard base64 must come out as '-'/'_'
         and still round-trip. 0xfb 0xff 0xff -> "-___" (62,63,63,63). *)
      val () = checkString "url-safe alphabet"
        ("-___", Jwt.encodeB64u (String.implode [Char.chr 0xfb, Char.chr 0xff,
                                                 Char.chr 0xff]))
      val () = check "no padding char present"
        (not (List.exists (fn c => c = #"=")
               (String.explode (Jwt.encodeB64u "any padding here?"))))
      val () = checkBool "decode rejects stray char"
        (false, isSome (Jwt.decodeB64u "abc$def"))

      val () = section "RFC 7515 A.1 HS256 vector"

      (* The worked example from RFC 7515 Appendix A.1. The encoded header and
         payload are the RFC's exact bytes (they use CRLF whitespace inside the
         JSON, so we cannot regenerate them from a claim list -- we sign the
         RFC's literal signing input and check the signature segment). The HMAC
         key is the JWK "k" octet sequence, itself base64url; we decode it with
         our own decoder so the test also exercises that path. *)
      val rfcHeaderB64 = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
      val rfcPayloadB64 =
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQ"
        ^ "ogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
      val rfcSigningInput = rfcHeaderB64 ^ "." ^ rfcPayloadB64
      val rfcKey =
        case Jwt.decodeB64u
               ("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T"
                ^ "-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow") of
            SOME k => k
          | NONE => "<key decode failed>"
      val rfcExpectedSig = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

      (* Sign direction: HMAC-SHA256 over the RFC signing input, base64url'd,
         must equal the RFC's expected signature segment. *)
      val () = checkString "A.1 signature segment"
        (rfcExpectedSig,
         Jwt.encodeB64u (Hmac.hmacSha256 rfcKey rfcSigningInput))

      (* Verify direction: the full RFC A.1 compact token verifies under the
         RFC key. Its payload has exp=1300819380, so we inject a `now` before
         that instant. *)
      val rfcToken = rfcSigningInput ^ "." ^ rfcExpectedSig
      val () = checkString "A.1 verify accepts (resultName)"
        ("Ok", resultName (Jwt.verifyAt {secret = rfcKey, now = 1300819379}
                                        rfcToken))

      val () = section "sign / verify round-trip"

      val secret = "server-secret-key"
      val claims = [ ("sub", Json.JStr "alice")
                   , ("role", Json.JStr "admin")
                   , ("exp", Json.JInt 2000)
                   , ("nbf", Json.JInt 1000) ]
      val tok = Jwt.sign {alg = Jwt.HS256, secret = secret, claims = claims}

      (* Inside the [nbf, exp) window: accepted, and the claims come back. *)
      val () = checkString "valid window accepts"
        ("Ok", resultName (Jwt.verifyAt {secret = secret, now = 1500} tok))
      val () =
        case Jwt.verifyAt {secret = secret, now = 1500} tok of
            Jwt.Ok cs =>
              checkString "round-trip preserves sub"
                ("alice",
                 case List.find (fn (k, _) => k = "sub") cs of
                     SOME (_, Json.JStr s) => s
                   | _ => "<missing>")
          | Jwt.Err _ => check "round-trip preserves sub" false

      val () = checkString "wrong secret -> BadSignature"
        ("Err BadSignature",
         resultName (Jwt.verifyAt {secret = "other", now = 1500} tok))

      val () = section "tampering"

      (* Flip a byte in the payload segment; the signature no longer matches. *)
      fun tamperPayload t =
        case String.fields (fn c => c = #".") t of
            [h, p, s] =>
              let
                val c0 = String.sub (p, 0)
                val c0' = if c0 = #"A" then #"B" else #"A"
                val p' = String.str c0' ^ String.extract (p, 1, NONE)
              in
                h ^ "." ^ p' ^ "." ^ s
              end
          | _ => t
      val () = checkString "tampered payload -> BadSignature"
        ("Err BadSignature",
         resultName (Jwt.verifyAt {secret = secret, now = 1500}
                                  (tamperPayload tok)))
      val () = checkString "garbage token -> Malformed"
        ("Err Malformed",
         resultName (Jwt.verifyAt {secret = secret, now = 1500} "not-a-jwt"))

      val () = section "exp / nbf enforcement"

      val () = checkString "now >= exp -> Expired"
        ("Err Expired",
         resultName (Jwt.verifyAt {secret = secret, now = 2000} tok))
      val () = checkString "now past exp -> Expired"
        ("Err Expired",
         resultName (Jwt.verifyAt {secret = secret, now = 9999} tok))
      val () = checkString "now < nbf -> NotYetValid"
        ("Err NotYetValid",
         resultName (Jwt.verifyAt {secret = secret, now = 500} tok))
      val () = checkString "now == nbf -> accepted"
        ("Ok", resultName (Jwt.verifyAt {secret = secret, now = 1000} tok))

      val () = section "algorithm rejection"

      (* Hand-build tokens with arbitrary header JSON to probe alg handling.
         The signature is a real HMAC over the signing input, so these reach
         the alg check rather than failing earlier on the MAC. *)
      fun forge headerJson payloadJson =
        let
          val hB = Jwt.encodeB64u headerJson
          val pB = Jwt.encodeB64u payloadJson
          val si = hB ^ "." ^ pB
          val sg = Jwt.encodeB64u (Hmac.hmacSha256 secret si)
        in
          si ^ "." ^ sg
        end
      val payloadJson = "{\"sub\":\"x\"}"
      val () = checkString "alg \"none\" -> UnsupportedAlg"
        ("Err UnsupportedAlg",
         resultName (Jwt.verifyAt {secret = secret, now = 1500}
                       (forge "{\"alg\":\"none\",\"typ\":\"JWT\"}" payloadJson)))
      val () = checkString "alg \"RS256\" mismatch -> UnsupportedAlg"
        ("Err UnsupportedAlg",
         resultName (Jwt.verifyAt {secret = secret, now = 1500}
                       (forge "{\"alg\":\"RS256\",\"typ\":\"JWT\"}" payloadJson)))
      val () = checkString "missing alg -> UnsupportedAlg"
        ("Err UnsupportedAlg",
         resultName (Jwt.verifyAt {secret = secret, now = 1500}
                       (forge "{\"typ\":\"JWT\"}" payloadJson)))
    in () end
end
