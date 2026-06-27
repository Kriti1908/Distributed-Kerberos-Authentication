# SECURITY.md

## 1) Why one compromised authority cannot forge tickets
Each AS/TGS authority signs independently with its own Schnorr key pair `(x_i, y_i)`.
A ticket is accepted only if at least two distinct authority signatures verify.

If one authority is compromised, the attacker can produce only one valid signature.
That is insufficient to satisfy the verifier rule (`>= 2` distinct valid signatures), so forged tickets are rejected.

## 2) Why two compromised authorities break security
If two authorities are compromised, the attacker can produce two valid independent signatures for any payload.
Because the verifier requires two valid signatures, the attacker can satisfy acceptance rules.

This is the explicit trust boundary of the 2-of-3 model.

## 3) Why requiring two independent signatures prevents single-node forgery
The verifier checks each signature separately against the signer public key and authority identity binding:
- `e_i = H(m || R_i || ID_i)`
- Verify `g^{s_i} == R_i * y_i^{e_i} (mod p)`

The ticket is valid only when checks succeed for at least two different `ID_i`.
A single node cannot satisfy that condition alone.

## 4) Nonce reuse risks
Schnorr signatures require a fresh random nonce `k_i` per signature.
If nonce is reused across two different messages for same authority:
- `s1 = k + e1*x`
- `s2 = k + e2*x`
- `x = (s1 - s2) * (e1 - e2)^{-1} mod q`

So nonce reuse can leak the private key.

Mitigations in this implementation:
- OS RNG for nonces
- Nonce bound challenge with `message`, `R`, and `authorityID`

## 5) Key share / private key leakage impact
Under this independent multi-signature design, leaking one authority private key compromises only that authority.
It still does not allow ticket forgery because one signature is insufficient.

If two authority private keys leak, security is broken for ticket issuance (attacker can sign with two identities).

## 6) Replay attack handling
Replay is blocked using authenticator freshness + replay caches.

Checks:
- Fresh timestamp window
- HMAC verification with session key
- Nonce included in authenticator and replay key
- Request context included in TGS replay keying

This prevents high-concurrency false replays and blocks actual ticket/authenticator replay attempts.

## 7) Ticket integrity and validation
Service/TGS validation includes:
- AES decryption using server-side key
- Recompute signed payload bytes and compare with signed bytes
- Verify signatures for at least two distinct authorities
- Enforce key version match
- Enforce ticket type and expiration checks

## 9) Attack simulation coverage
`attacks.cpp` covers required scenarios:
1. Single malicious authority forging ticket
2. Modified ticket payload
3. Replay attempt
4. One authority key leakage scenario
5. Authority offline scenario
6. One-signature ticket scenario

Expected/observed result on fresh isolated stack:
- All attack attempts are blocked
- System remains operational with one authority offline
