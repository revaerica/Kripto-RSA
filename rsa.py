#!/usr/bin/env python3
"""
MeowBid — Implementasi RSA Murni Python
Tidak menggunakan library kriptografi eksternal.
Digunakan sebagai backend logic untuk simulasi lelang sealed-bid.
"""
import random
import hashlib
import json

# ─────────────────────────────────────────
#  ARITMETIKA MODULAR
# ─────────────────────────────────────────

def mod_pow(base: int, exp: int, mod: int) -> int:
    """Modular exponentiation cepat (square-and-multiply)."""
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = result * base % mod
        base = base * base % mod
        exp >>= 1
    return result


def gcd(a: int, b: int) -> int:
    """Greatest Common Divisor — Euclidean."""
    while b:
        a, b = b, a % b
    return a


def mod_inv(a: int, m: int) -> int | None:
    """Invers modular via Extended Euclidean Algorithm."""
    r0, r1 = a, m
    s0, s1 = 1, 0
    while r1:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        s0, s1 = s1, s0 - q * s1
    return ((s0 % m) + m) % m if r0 == 1 else None


# ─────────────────────────────────────────
#  UJI PRIMALITAS  (Miller-Rabin)
# ─────────────────────────────────────────

_SMALL = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]


def is_prime(n: int, rounds: int = 20) -> bool:
    """Uji primalitas probabilistik Miller-Rabin."""
    for p in _SMALL:
        if n == p:   return True
        if n % p == 0: return False
    d, s = n - 1, 0
    while not (d & 1):
        d >>= 1
        s += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = mod_pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits: int) -> int:
    """Bangkitkan bilangan prima acak sepanjang `bits` bit."""
    while True:
        n = random.getrandbits(bits)
        n |= (1 << (bits - 1)) | 1   # set MSB & LSB (ganjil)
        if is_prime(n):
            return n


# ─────────────────────────────────────────
#  PEMBANGKITAN KUNCI RSA
# ─────────────────────────────────────────

E = 65537   # Eksponen publik standar (bilangan prima Fermat F4)


def gen_keys(bits: int) -> dict:
    """
    Bangkitkan pasangan kunci RSA.

    Args:
        bits: panjang tiap bilangan prima (kunci publik = 2*bits bit)

    Returns:
        dict berisi p, q, n, phi, e, d (semua hex string)
    """
    while True:
        p = gen_prime(bits)
        q = gen_prime(bits)
        if p == q:
            continue
        n   = p * q
        phi = (p - 1) * (q - 1)
        if gcd(E, phi) != 1:
            continue
        d = mod_inv(E, phi)
        return {
            "p":   hex(p),
            "q":   hex(q),
            "n":   hex(n),
            "phi": hex(phi),
            "e":   hex(E),
            "d":   hex(d),
        }


# ─────────────────────────────────────────
#  ENKRIPSI  /  DEKRIPSI  RSA
# ─────────────────────────────────────────

def encrypt(text: str, n_hex: str, e_hex: str) -> list[dict]:
    """
    Enkripsi teks menjadi list blok ciphertext.

    Setiap blok:  c = m^e mod n
    Prefix 0x01 pada m untuk menjaga byte nol di depan.

    Returns:
        list of { "m": hex, "c": hex }
    """
    n, e   = int(n_hex, 16), int(e_hex, 16)
    k      = (n.bit_length() - 1) // 8 - 1   # ukuran blok dalam byte
    data   = text.encode("utf-8")
    blocks = []
    for i in range(0, max(len(data), 1), k):
        chunk = data[i : i + k]
        m = 1
        for byte in chunk:
            m = (m << 8) | byte
        c = mod_pow(m, e, n)
        blocks.append({"m": hex(m), "c": hex(c)})
    return blocks


def decrypt(ciphers: list[str], n_hex: str, d_hex: str) -> str:
    """
    Dekripsi list ciphertext hex menjadi teks asli.

    m = c^d mod n
    """
    n, d   = int(n_hex, 16), int(d_hex, 16)
    result = bytearray()
    for c_hex in ciphers:
        m  = mod_pow(int(c_hex, 16), d, n)
        mh = hex(m)[2:]
        if len(mh) % 2:
            mh = "0" + mh
        raw = bytes.fromhex(mh)[1:]   # buang prefix 0x01
        result += raw
    return result.decode("utf-8")


# ─────────────────────────────────────────
#  TANDA TANGAN DIGITAL
# ─────────────────────────────────────────

def sha256_hex(data: str) -> str:
    """SHA-256 dari string, kembalikan hex."""
    return hashlib.sha256(data.encode()).hexdigest()


def sign(digest_hex: str, d_hex: str, n_hex: str) -> str:
    """Buat tanda tangan digital:  s = hash^d mod n  (kunci privat)."""
    return hex(mod_pow(int(digest_hex, 16), int(d_hex, 16), int(n_hex, 16)))


def verify(sig_hex: str, e_hex: str, n_hex: str, expected_hex: str) -> bool:
    """Verifikasi tanda tangan:  s^e mod n == hash  (kunci publik)."""
    recovered = mod_pow(int(sig_hex, 16), int(e_hex, 16), int(n_hex, 16))
    return recovered == int(expected_hex, 16)


# ─────────────────────────────────────────
#  SIMULASI LELANG SEALED-BID
# ─────────────────────────────────────────

def bid_digest(auction_id: str, bidder: str, amount: int, note: str) -> str:
    """Hash deterministik dari data bid (untuk tanda tangan)."""
    return sha256_hex(f"{auction_id}|{bidder}|{amount}|{note}")


def place_bid(auction_pub: dict, bidder_priv: dict,
              bidder_name: str, amount: int, note: str = "") -> dict:
    """
    Buat bid tersegel:
      1. Hitung hash bid
      2. Tanda tangani dengan kunci privat peserta
      3. Enkripsi payload dengan kunci publik lelang
    """
    digest = bid_digest("demo", bidder_name, amount, note)
    sig    = sign(digest, bidder_priv["d"], bidder_priv["n"])
    payload = json.dumps({"amount": amount, "note": note, "sig": sig})
    blocks  = encrypt(payload, auction_pub["n"], auction_pub["e"])
    return {"bidder": bidder_name, "ct": [b["c"] for b in blocks]}


def open_bid(sealed: dict, auction_priv: dict,
             bidders: dict, min_price: int) -> dict:
    """
    Buka segel bid:
      1. Dekripsi ciphertext
      2. Verifikasi tanda tangan
      3. Cek nominal vs harga awal
    """
    try:
        pt   = decrypt(sealed["ct"], auction_priv["n"], auction_priv["d"])
        obj  = json.loads(pt)
        amt  = int(obj["amount"])
        who  = sealed["bidder"]
        pub  = bidders.get(who, {})
        digest = bid_digest("demo", who, amt, obj.get("note", ""))
        sig_ok = verify(obj["sig"], pub["e"], pub["n"], digest) if pub else False
        valid  = sig_ok and amt >= min_price
        return {"bidder": who, "amount": amt, "sig_ok": sig_ok,
                "valid": valid, "note": obj.get("note", "")}
    except Exception as exc:
        return {"bidder": sealed["bidder"], "amount": 0,
                "sig_ok": False, "valid": False, "note": str(exc)}


# ─────────────────────────────────────────
#  CONTOH PENGGUNAAN
# ─────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  MeowBid — Demo Lelang Sealed-Bid RSA")
    print("=" * 55)

    # 1. Kunci lelang (penyelenggara)
    print("\n[1] Bangkitkan kunci lelang (256 bit per prima)...")
    auction = gen_keys(256)
    print(f"    n = {auction['n'][:28]}...")
    print(f"    e = {auction['e']}")

    # 2. Kunci peserta
    print("\n[2] Bangkitkan kunci peserta...")
    budi  = gen_keys(192)
    siti  = gen_keys(192)
    wati  = gen_keys(192)
    bidders = {"Budi": budi, "Siti": siti, "Wati": wati}
    print("    Budi, Siti, Wati — kunci 384-bit siap")

    # 3. Kirim bid tersegel
    print("\n[3] Peserta mengirim bid tersegel...")
    MIN_PRICE = 500_000
    bids = [
        place_bid(auction, budi, "Budi",  850_000, "Bayar tunai"),
        place_bid(auction, siti, "Siti", 1_200_000, "Transfer BCA"),
        place_bid(auction, wati, "Wati",  720_000, ""),
    ]
    for b in bids:
        print(f"    {b['bidder']:6s} -> {len(b['ct'])} blok ciphertext terkirim")

    # 4. Buka segel
    print("\n[4] Buka segel & verifikasi...")
    results = [open_bid(b, auction, bidders, MIN_PRICE) for b in bids]
    valid   = sorted([r for r in results if r["valid"]],
                     key=lambda r: -r["amount"])

    for r in results:
        status = "VALID" if r["valid"] else "DITOLAK"
        sig    = "ok" if r["sig_ok"] else "GAGAL"
        print(f"    {r['bidder']:6s}  Rp {r['amount']:>10,}  "
              f"sig={sig}  [{status}]")

    # 5. Pemenang
    print("\n[5] Hasil akhir:")
    if valid:
        winner = valid[0]
        print(f"    PEMENANG: {winner['bidder']} "
              f"dengan Rp {winner['amount']:,}")
    else:
        print("    Tidak ada bid valid.")
    print("=" * 55)
