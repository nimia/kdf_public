This note identifies a possible security problem in the "Hybrid key exchange in
TLS 1.3" document, stemming from how cryptographic secrets are combined. In
short: constructions that concatenate secrets are vulnerable when the underlying
hash function is not collision-resistant. We are unaware of a full attack
that leverages the underlying problem. However, we view this as an opportunity
to defend-in-depth against such issues, while the document is not yet finalized.
We propose a new construction that seems robust to this potential issue, and we
are in the process of writing a technical report that includes a full security
proof.

# Concatenating Secrets May Be Dangerous

The APOP attack (see appendix for a brief description) demonstrates that
concatenating secrets to potentially attacker-controlled input might be
dangerous. Currently, the "Hybrid key exchange in TLS 1.3" document uses secret
concatenation as the preferred way to combine secrets. (This was an
understandable design choice given how little this issue has been studied.)

We recommend a defense-in-depth approach against this potential issue. We should
not concede to an attacker even the ability to cause a collision in an internal
state of the key schedule. Moreover, this part of TLS is likely particularly
amenable to ossification: Whatever we standardize will likely persist for 5-10
years. (We do note that TLS mixes in the client and server nonces, so additional
offensive techniques would be required to exploit this for a full attack.)

(We note that concatenation is also used in the "TLS 1.3 Extended Key Schedule"
document.)

# Our proposed construction

We have identified an alternative construction that we believe could provide
defense-in-depth against this issue. We are in the process of writing a
technical report that includes a full security proof.
The required assumptions on the hash function appear to be much milder than
collision resistance; instead, we likely only need multi-preimage-resistance:
Essentially, requiring only that computing preimages for multiple images is
hard.

The construction is: \
combined_key = H(HMAC(key=H1(k1), data=2||F(k2)) xor HMAC(key=H2(k2), data=1||F(k1))) \
where || denotes concatenation, H denotes the underlying hash function, and: \
H1(k) = H('derive1' || k) \
H2(k) = H('derive2' || k) \
F is defined as follows:
Let m denote the input to F. We split m into blocks, according to the block size
of H: \
m = m1||m2||...||mn \
Let j~=3 denote an “expanding factor” (the value chosen for j in practice
depends on how strong an assumption we want to rely on; we expect 3 to be enough).
Then \
F(m) = H(0||m1)||H(1||m1)||...||H(j-1||m1)||H(0||m2)||H(1||m2)||...||H(j-1||m2)||H(0||mn)||H(1||mn)||...||H(j-1||mn)

This construction is cheap to calculate and would be used only in the key
schedule, which is not a bottleneck for TLS performance.

# Adding another layer to the TLS key schedule may also be problematic

Another strategy for mixing secrets is to add the second secret to another layer
of the TLS key schedule. This strategy is already used to mix a PSK and an ECDHE
secret in TLS 1.3, as well as in AuthKEM, and it was also considered for the
Hybrid key exchange document. This strategy is vulnerable as well to collisions
in the underlying hash function, and we propose using one secure construction
for mixing secrets.

Consider a standard PSK+ECDHE TLS 1.3 handshake. Then \
handshake_secret = HKDF_Extract(IKM=ECDHE_secret, salt=Derive_Secret(early_secret)) \
early_secret = HKDF_Extract(IKM=PSK, salt=000) \
HKDF_Extract(IKM, salt) = HMAC(k=salt, data=IKM)

Therefore, early_secret = HMAC(k=000, data=PSK). \
Assume a non-collision-resistant hash function. Then an attacker that can
establish multiple PSKs of their choice with another party can cause two
sessions with two different PSKs to share the same early_secret. If the other
party reuses ECDH(E) values, the attacker can also cause the handshake_secret to
be identical.

Furthermore, \
Client_Handshake_Traffic_Secret = \
  HMAC(k=Handshake_Secret, data=Label||H(ClientHello...ServerHello)) \
If the attacker is the server, and the hash function allows for chosen-prefix
collisions, the attacker can choose two ServerHello messages such that for two
different ClientHello messages, H(ClientHello...ServerHello) is identical.
This leads to identical values for an actual key output of the key schedule,
Client-Handshake-Traffic-Secret (if the client reuses an ECDH(E) value, or in a
hypothetical PQ TLS, which uses a KEM and the server chooses the encapsulated
key).

We note that the full version of the HKDF paper explicitly disclaims security in
the presence of attacker-controlled entropy. Also, note that by definition, a
KEM allows one party to control the secret.

# Appendix: The APOP Attack

APOP is an old challenge-response protocol used in email, relevant here because
it demonstrates the attack well. Broadly, in APOP the challenger sends a
challenge, and the responder needs to respond with:
MD5(challenge || password)
where || denotes concatenation.

The attacker wants to e.g. test whether the password starts with 'a'. They
pick an MD5 collision x, y such that MD5(x) = MD5(y) and both x and y end with
'a'. They wait for the client to connect in two different sessions, and send
x[:-1] and y[:-1] as the challenges, where [:-1] denotes removing the last byte
from a string. If the password starts with 'a', and the MD5 blocks align, then
the response will be the same for both challenges. The attacker can therefore
test a single guess for the starting byte with two sessions, and learn that byte
after at most 512 sessions. See [1], [2].

best wishes,
Nimrod Aviram, Benjamin Dowling, Ilan Komargodski, Kenny Paterson, Eyal Ronen, Eylon Yogev

References: \
[1] Practical key-recovery attack against APOP, an MD5-based challenge-response authentication. Leurent, Gaetan.

[2] Practical Password Recovery on an MD5 Challenge and Response.
Sasaki, Yu and Yamamoto, Go and Aoki, Kazumaro.
