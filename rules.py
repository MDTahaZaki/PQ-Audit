import re

RULES = [
    {
        "name": "RSA",
        "pattern": re.compile(r"(RSA\.generate|RSAPrivateKey|\b2048-bit\b|\b4096-bit\b|RSAKey)", re.IGNORECASE),
        "risk": "High Risk / Broken by Shor's Algorithm",
        "recommendation": "ML-KEM (Kyber-768/1024) for Key Exchange\nML-DSA (Dilithium3) or SLH-DSA (SPHINCS+) for Signatures"
    },
    {
        "name": "ECC / ECDSA",
        "pattern": re.compile(r"(ECDSA|secp256k1|prime256v1|EllipticCurve)", re.IGNORECASE),
        "risk": "High Risk / Broken by Shor's Algorithm",
        "recommendation": "ML-KEM (Kyber-768/1024) for Key Exchange\nML-DSA (Dilithium3) or SLH-DSA (SPHINCS+) for Signatures"
    },
    {
        "name": "AES-128",
        "pattern": re.compile(r"(AES\.MODE_|AES-128|\b128-bit key\b)", re.IGNORECASE),
        "risk": "Medium Risk / Grover's Algorithm weakens bit-security to 64-bit",
        "recommendation": "AES-256 (Quantum-Resistant Symmetric Key Length)"
    },
    {
        "name": "SHA-1 / MD5",
        "pattern": re.compile(r"(\bsha1\b|\bmd5\b)", re.IGNORECASE),
        "risk": "High Risk / Deprecated Classical Collision",
        "recommendation": "SHA-256 / SHA-3 (Classical Best Practice)"
    }
]
