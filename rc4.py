def KSA(key):
    S = list(range(256))

    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    return S

def PRGA(S):
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        yield K

def RC4(key):
    S = KSA(key)
    return PRGA(S)

def encrypt(key, text):
    keystream = RC4(key)

    ct = b""
    for ch in text:
        ct += bytes([int(ch) ^ next(keystream)])

    return ct

def decrypt(key, text):
    keystream = RC4(key)

    pt = b""
    for ch in text:
        pt += bytes([int(ch) ^ next(keystream)])

    return pt
