local bit = bit32

local band, bor, bxor, rshift, lshift, bnot = bit.band, bit.bor, bit.bxor, bit.rshift, bit.lshift, bit.bnot

local H = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

local K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local function ROTR(x, n)
    return bor(rshift(x, n), lshift(x, 32 - n))
end

local function Ch(x, y, z)
    return bxor(band(x, y), band(bnot(x), z))
end

local function Maj(x, y, z)
    return bxor(bxor(band(x, y), band(x, z)), band(y, z))
end

local function Sigma0(x)
    return bxor(ROTR(x, 2), bxor(ROTR(x, 13), ROTR(x, 22)))
end

local function Sigma1(x)
    return bxor(ROTR(x, 6), bxor(ROTR(x, 11), ROTR(x, 25)))
end

local function sigma0(x)
    return bxor(ROTR(x, 7), bxor(ROTR(x, 18), rshift(x, 3)))
end

local function sigma1(x)
    return bxor(ROTR(x, 17), bxor(ROTR(x, 19), rshift(x, 10)))
end

local function tobytes(msg)
    local bytes = {}
    for i = 1, #msg do
        bytes[#bytes+1] = string.byte(msg, i)
    end
    return bytes
end

local function tohex(x)
    return string.format("%08x", x)
end

local function sha256(msg)
    local bytes = tobytes(msg)
    local len = #bytes * 8

    -- padding
    bytes[#bytes+1] = 0x80
    while (#bytes % 64) ~= 56 do
        bytes[#bytes+1] = 0
    end

    for i = 7, 0, -1 do
        bytes[#bytes+1] = band(rshift(len, 8 * i), 0xFF)
    end

    local h = {unpack(H)}
    for i = 1, #bytes, 64 do
        local w = {}
        for j = 0, 15 do
            local b = i + j * 4
            w[j] = lshift(bytes[b], 24) + lshift(bytes[b+1], 16) + lshift(bytes[b+2], 8) + bytes[b+3]
        end
        for j = 16, 63 do
            w[j] = (sigma1(w[j-2]) + w[j-7] + sigma0(w[j-15]) + w[j-16]) % 2^32
        end

        local a,b,c,d,e,f,g,h0 = unpack(h)

        for j = 0, 63 do
            local t1 = (h0 + Sigma1(e) + Ch(e,f,g) + K[j+1] + w[j]) % 2^32
            local t2 = (Sigma0(a) + Maj(a,b,c)) % 2^32
            h0 = g
            g = f
            f = e
            e = (d + t1) % 2^32
            d = c
            c = b
            b = a
            a = (t1 + t2) % 2^32
        end

        h = {
            (h[1] + a) % 2^32,
            (h[2] + b) % 2^32,
            (h[3] + c) % 2^32,
            (h[4] + d) % 2^32,
            (h[5] + e) % 2^32,
            (h[6] + f) % 2^32,
            (h[7] + g) % 2^32,
            (h[8] + h0) % 2^32,
        }
    end

    return table.concat({
        tohex(h[1]), tohex(h[2]), tohex(h[3]), tohex(h[4]),
        tohex(h[5]), tohex(h[6]), tohex(h[7]), tohex(h[8]),
    })
end

return sha256
