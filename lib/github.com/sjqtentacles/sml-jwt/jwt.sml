(* jwt.sml *)

structure Jwt :> JWT =
struct
  datatype alg = HS256

  type claims = (string * Json.json) list

  datatype ('ok, 'err) result = Ok of 'ok | Err of 'err

  datatype error =
      Malformed
    | BadHeader
    | UnsupportedAlg
    | BadSignature
    | BadPayload
    | Expired
    | NotYetValid

  (* ---- base64url ----
     The vendored Base64 already offers `encodeUrl` (URL-safe alphabet, no
     padding) and a `decode` that tolerates either alphabet with optional
     padding, so base64url is a thin adapter: encode is just `encodeUrl`, and
     decode reuses the codec's tolerant decoder. We keep explicit names so the
     JWT call sites read clearly and so the round-trip is unit-tested here. *)
  fun encodeB64u s = Base64.encodeUrl s
  fun decodeB64u s = Base64.decode s

  (* The fixed JWS header for HS256, written as a literal so its byte form is
     deterministic and independent of any JSON object-key ordering. RFC 7515
     allows any member order; we pick the conventional {"alg","typ"}. *)
  val headerHS256 = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"

  fun algName HS256 = "HS256"

  (* Compute the raw MAC for an algorithm over the signing input. Only HS256
     exists, so this is total; adding HS384/HS512 later means adding a hash
     and a case here. *)
  fun macOf HS256 secret signingInput = Hmac.hmacSha256 secret signingInput

  fun sign {alg, secret, claims} =
    let
      val headerB64 = encodeB64u headerHS256
      val payloadB64 = encodeB64u (JsonPretty.toString (Json.JObj claims))
      val signingInput = headerB64 ^ "." ^ payloadB64
      val sigB64 = encodeB64u (macOf alg secret signingInput)
    in
      signingInput ^ "." ^ sigB64
    end

  fun verifyAt {secret, now} token =
    let
      (* Split on '.' into exactly three parts. *)
      fun splitDots s =
        case String.fields (fn c => c = #".") s of
            [h, p, sg] => SOME (h, p, sg)
          | _ => NONE

      (* Find a member in a JSON object by key. *)
      fun lookup k kvs =
        case List.find (fn (k', _) => k' = k) kvs of
            SOME (_, v) => SOME v
          | NONE => NONE

      (* The header alg field must name a supported algorithm. We never accept
         "none": an absent/none/unknown alg is UnsupportedAlg. *)
      fun algFromHeader hdrJson =
        case hdrJson of
            Json.JObj kvs =>
              (case lookup "alg" kvs of
                   SOME (Json.JStr "HS256") => SOME HS256
                 | _ => NONE)
          | _ => NONE

      fun checkTime claims =
        let
          fun asInt (SOME (Json.JInt n)) = SOME n
            | asInt _ = NONE
          val expOk =
            case asInt (lookup "exp" claims) of
                SOME exp => now < exp     (* reject when now >= exp *)
              | NONE => true
          val nbfOk =
            case asInt (lookup "nbf" claims) of
                SOME nbf => now >= nbf    (* reject when now < nbf *)
              | NONE => true
        in
          if not expOk then Err Expired
          else if not nbfOk then Err NotYetValid
          else Ok claims
        end
    in
      case splitDots token of
          NONE => Err Malformed
        | SOME (headerB64, payloadB64, sigB64) =>
            (case decodeB64u headerB64 of
                 NONE => Err Malformed
               | SOME headerRaw =>
                   (case Json.parseJson headerRaw of
                        CharParsec.Err _ => Err BadHeader
                      | CharParsec.Ok hdrJson =>
                          (case algFromHeader hdrJson of
                               NONE => Err UnsupportedAlg
                             | SOME alg =>
                                 let
                                   val signingInput = headerB64 ^ "." ^ payloadB64
                                   val expectedMac = macOf alg secret signingInput
                                 in
                                   case decodeB64u sigB64 of
                                       NONE => Err Malformed
                                     | SOME gotMac =>
                                         (* Full-length constant-time compare;
                                            does not early-exit on first byte. *)
                                         if not (Hmac.constantEq expectedMac gotMac)
                                         then Err BadSignature
                                         else
                                           (case decodeB64u payloadB64 of
                                                NONE => Err Malformed
                                              | SOME payloadRaw =>
                                                  (case Json.parseJson payloadRaw of
                                                       CharParsec.Err _ => Err BadPayload
                                                     | CharParsec.Ok (Json.JObj claims) =>
                                                         checkTime claims
                                                     | CharParsec.Ok _ => Err BadPayload))
                                 end)))
    end

  fun verify {secret} token =
    let
      (* Seconds since the Unix epoch, from the real clock. *)
      val now = Int.fromLarge (Time.toSeconds (Time.now ()))
    in
      verifyAt {secret = secret, now = now} token
    end
end
