# attacker_elgamal.py
#
# Practical nonce-reuse attack against the buggy ElGamal hash-signer
# implemented in buggy_elgamal.py.
#
# Idea (see the report for the full derivation):
#   sign_hash always uses the SAME secret nonce k, so any two signatures
#   (r, s1) on h1 and (r, s2) on h2 satisfy:
#       s1 = k^-1 * (h1 - x*r)  mod n
#       s2 = k^-1 * (h2 - x*r)  mod n         (n = p - 1)
#   Subtracting eliminates x:
#       k = (h1 - h2) * inv(s1 - s2)  mod n
#   Then x is recovered from either equation:
#       x = (h1 - k*s1) * inv(r)  mod n
#
# Once x (and k) are known, we can forge a valid signature on ANY new
# message/hash h3 exactly the way the "device" would, because forging
# only requires the private key x (a fresh nonce can be used, or the
# leaked k can be reused).

from hashlib import sha256
import buggy_elgamal as dev  # simulated HSM / secure element


def modinv(a, m):
    return dev.modinv(a, m)


def recover_k_and_x(h1, s1, h2, s2, r, n):
    """Recover the reused nonce k and the private key x from two
    signatures (r, s1) on h1 and (r, s2) on h2 that share the same r
    (i.e. the same nonce k was used)."""
    ds = (s1 - s2) % n
    dh = (h1 - h2) % n
    k = (dh * modinv(ds, n)) % n
    x = ((h1 - k * s1) * modinv(r, n)) % n
    return k, x


def forge_signature(h, x, p, g, k_forge=None):
    """Forge a valid ElGamal signature on hash h given the recovered
    private key x. A (possibly fresh) nonce k_forge is used -- the
    attacker does not need the device at all anymore."""
    import math
    import secrets

    n = p - 1
    if k_forge is None:
        while True:
            k_forge = secrets.randbelow(n - 1) + 1
            if math.gcd(k_forge, n) == 1:
                r_forge = pow(g, k_forge, p)
                if math.gcd(r_forge, n) == 1:
                    break
    else:
        r_forge = pow(g, k_forge, p)

    r_forge = pow(g, k_forge, p)
    s_forge = ((h - x * r_forge) * modinv(k_forge, n)) % n
    return r_forge, s_forge


def main():
    # ---- Step 0: get the (legitimate) public parameters from the device ----
    p, g, y = dev.keygen()
    n = p - 1
    print(f"Public parameters: p={p}, g={g}, y={y}")

    # ---- Step 1: ask the "device" to sign two DIFFERENT messages ----
    m1 = b"Transfer 10 credits to Alice"
    m2 = b"Transfer 10 credits to Bob"

    h1 = dev.H_bytes(m1, p)
    h2 = dev.H_bytes(m2, p)

    r1, s1 = dev.sign_hash(h1, p, g)
    r2, s2 = dev.sign_hash(h2, p, g)

    print(f"\nSignature 1: h1={h1}, r1={r1}, s1={s1}")
    print(f"Signature 2: h2={h2}, r2={r2}, s2={s2}")
    print(f"r1 == r2 (nonce reused)?  {r1 == r2}")

    assert r1 == r2, "This attack requires the nonce (and thus r) to repeat."
    r = r1

    # sanity check: both signatures verify correctly on their own messages
    assert dev.verify_hash(h1, (r1, s1), p, g, y)
    assert dev.verify_hash(h2, (r2, s2), p, g, y)
    print("Both original signatures verify correctly (as expected).")

    # ---- Step 2: recover k and x using ONLY public info + the two signatures ----
    k_recovered, x_recovered = recover_k_and_x(h1, s1, h2, s2, r, n)
    print(f"\nRecovered nonce k = {k_recovered}")
    print(f"Recovered private key x = {x_recovered}")

    # verify the recovered private key against the public key y = g^x mod p
    y_check = pow(g, x_recovered, p)
    print(f"g^x_recovered mod p = {y_check}  (matches public y: {y_check == y})")
    assert y_check == y, "Recovered private key does not match public key!"

    # ---- Step 3: forge a signature on a NEW message, without the device ----
    m3 = b"Transfer 1000000 credits to Attacker"
    h3 = dev.H_bytes(m3, p)

    r3, s3 = forge_signature(h3, x_recovered, p, g)
    forged_ok = dev.verify_hash(h3, (r3, s3), p, g, y)

    print(f"\nForged message: {m3!r}")
    print(f"Forged hash h3 = {h3}")
    print(f"Forged signature: (r3, s3) = ({r3}, {s3})")
    print(f"verify_hash accepts the forged signature: {forged_ok}")

    assert forged_ok, "Forged signature was rejected -- attack failed."
    print("\n=> ATTACK SUCCESSFUL: private key fully recovered from nonce reuse,")
    print("   and a valid signature was forged on an arbitrary new message")
    print("   without ever touching the secure device again.")


if __name__ == "__main__":
    main()
