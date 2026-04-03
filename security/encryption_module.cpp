#include <pybind11/pybind11.h>
#include <vector>
#include <cstdint>
#include <string>
#include <stdexcept>

namespace py = pybind11;

// ---------------------- Block ----------------------
struct block128 {
    uint64_t hi, lo;

    block128 operator^(const block128 &b) const {
        return {hi ^ b.hi, lo ^ b.lo};
    }
};

// ---------------------- SBOX / PBOX ----------------------
constexpr uint8_t SBOX[16] = {
    0xE,0x4,0x8,0x5,0x6,0x1,0x9,0xF,
    0xD,0xC,0xA,0x7,0xB,0x0,0x2,0x3
};

constexpr int PBOX[64] = {
    0,16,32,48,1,17,33,49,2,18,34,50,3,19,35,51,
    4,20,36,52,5,21,37,53,6,22,38,54,7,23,39,55,
    8,24,40,56,9,25,41,57,10,26,42,58,11,27,43,59,
    12,28,44,60,13,29,45,61,14,30,46,62,15,31,47,63
};

constexpr uint64_t ROUND_CONST[5] = {
    0x3E8958737D12B0E6,0x23BE4C2D477C985A,
    0x2BDC0D262847E5B3,0x36EB19781229CD0F,
    0x3479AD88170CA4EF
};

// ---------------------- Cipher Core ----------------------
inline uint64_t apply_sbox(uint64_t x) {
    uint64_t y = 0;
    for (int i = 0; i < 16; i++)
        y |= (uint64_t)SBOX[(x >> (i*4)) & 0xF] << (i*4);
    return y;
}

inline uint64_t apply_pbox(uint64_t x) {
    uint64_t y = 0;
    for (int i = 0; i < 64; i++)
        y |= ((x >> i) & 1ULL) << PBOX[i];
    return y;
}

inline uint64_t feistel(uint64_t R, uint64_t rk) {
    return apply_pbox(apply_sbox(R ^ rk));
}

inline uint64_t key_expansion(uint64_t k[3], int r) {
    uint64_t temp = (k[0]>>3)|(k[0]<<61);
    temp ^= (k[0]>>4)|(k[0]<<60);
    temp ^= k[2] ^ ROUND_CONST[r % 5];

    uint64_t out = k[2];
    k[2] = k[1];
    k[1] = k[0];
    k[0] = temp;

    return out;
}

inline void encrypt128(uint64_t &L, uint64_t &R, uint64_t k[3]) {
    for (int r = 0; r < 32; r++) {
        uint64_t rk = key_expansion(k, r);
        uint64_t tmp = L;
        L = R;
        R = tmp ^ feistel(R, rk);
    }
}

block128 encrypt_block(block128 in, uint64_t key[3]) {
    uint64_t L = in.hi, R = in.lo;
    uint64_t tmp[3] = {key[0], key[1], key[2]};
    encrypt128(L, R, tmp);
    return {L, R};
}

// ---------------------- GF(2^128) for GHASH ----------------------
block128 gf_mul(block128 X, block128 Y) {
    block128 Z = {0,0};
    block128 V = X;

    for (int i = 0; i < 128; i++) {
        if ((Y.hi >> (127 - i)) & 1)
            Z = Z ^ V;

        bool lsb = V.lo & 1;

        V.lo = (V.lo >> 1) | (V.hi << 63);
        V.hi >>= 1;

        if (lsb)
            V.hi ^= 0xE100000000000000ULL;
    }

    return Z;
}

block128 ghash(const std::vector<block128>& data, block128 H) {
    block128 Y = {0,0};
    for (auto &X : data)
        Y = gf_mul(Y ^ X, H);
    return Y;
}

// ---------------------- Utilities ----------------------
uint64_t bytes_to_u64(const std::string &s, size_t off) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= (uint64_t)(uint8_t)s[off+i] << (56 - 8*i);
    return v;
}

std::string u64_to_bytes(uint64_t x) {
    std::string out(8, '\0');
    for (int i = 0; i < 8; i++)
        out[i] = (x >> (56 - 8*i)) & 0xFF;
    return out;
}

std::string pad(const std::string &data) {
    size_t p = 16 - (data.size() % 16);
    return data + std::string(p, (char)p);
}

std::string unpad(const std::string &data) {
    return data.substr(0, data.size() - (uint8_t)data.back());
}

std::vector<block128> bytes_to_blocks(const std::string &data) {
    std::vector<block128> out;
    for (size_t i = 0; i < data.size(); i += 16) {
        out.push_back({
            bytes_to_u64(data, i),
            bytes_to_u64(data, i+8)
        });
    }
    return out;
}

std::string blocks_to_bytes(const std::vector<block128> &blocks) {
    std::string out;
    for (auto &b : blocks) {
        out += u64_to_bytes(b.hi);
        out += u64_to_bytes(b.lo);
    }
    return out;
}

// ---------------------- SESSION ----------------------
class CryptoSession {
private:
    uint64_t key[3];
    block128 base_nonce;
    uint64_t counter;

    block128 next_nonce() {
        block128 n = base_nonce;
        n.lo += counter++;
        return n;
    }

public:
    CryptoSession(py::bytes key_bytes, py::bytes nonce_bytes) {
        std::string k = key_bytes;
        std::string n = nonce_bytes;

        if (k.size() != 24) throw std::runtime_error("Key must be 24 bytes");
        if (n.size() != 16) throw std::runtime_error("Nonce must be 16 bytes");

        key[0] = bytes_to_u64(k, 0);
        key[1] = bytes_to_u64(k, 8);
        key[2] = bytes_to_u64(k, 16);

        base_nonce = {bytes_to_u64(n, 0), bytes_to_u64(n, 8)};
        counter = 0;
    }

    py::tuple encrypt(py::bytes plaintext) {
        std::string input = plaintext;
        auto blocks = bytes_to_blocks(pad(input));

        std::vector<block128> ct(blocks.size());

        for (size_t i = 0; i < blocks.size(); i++) {
            block128 ks = encrypt_block(next_nonce(), key);
            ct[i] = blocks[i] ^ ks;
        }

        block128 H = encrypt_block({0,0}, key);
        block128 tag = ghash(ct, H);

        std::string tag_bytes = u64_to_bytes(tag.hi) + u64_to_bytes(tag.lo);

        return py::make_tuple(
            py::bytes(blocks_to_bytes(ct)),
            py::bytes(tag_bytes)
        );
    }

    py::bytes decrypt(py::bytes ciphertext, py::bytes tag_bytes) {
        std::string ct = ciphertext;
        std::string tag_in = tag_bytes;

        auto blocks = bytes_to_blocks(ct);

        block128 H = encrypt_block({0,0}, key);
        block128 expected = ghash(blocks, H);

        std::string expected_tag =
            u64_to_bytes(expected.hi) + u64_to_bytes(expected.lo);

        if (expected_tag != tag_in)
            throw std::runtime_error("Authentication failed");

        std::vector<block128> pt(blocks.size());

        for (size_t i = 0; i < blocks.size(); i++) {
            block128 ks = encrypt_block(next_nonce(), key);
            pt[i] = blocks[i] ^ ks;
        }

        return py::bytes(unpad(blocks_to_bytes(pt)));
    }
};

// ---------------------- PYBIND ----------------------
PYBIND11_MODULE(encryption_module, m) {
    py::class_<CryptoSession>(m, "CryptoSession")
        .def(py::init<py::bytes, py::bytes>())
        .def("encrypt", &CryptoSession::encrypt)
        .def("decrypt", &CryptoSession::decrypt);
}