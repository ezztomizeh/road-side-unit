#include <cstdint>
#include <tuple>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

// ---------------------- S-box ----------------------
uint8_t sbox[16] = {
    0xE, 0x4, 0x8, 0x5, 0x6, 0x1, 0x9, 0xF,
    0xD, 0xC, 0xA, 0x7, 0xB, 0x0, 0x2, 0x3
};

// ---------------------- PRESENT-style P-box ----------------------
int present_pbox[64] = {
    0, 16, 32, 48, 1, 17, 33, 49,
    2, 18, 34, 50, 3, 19, 35, 51,
    4, 20, 36, 52, 5, 21, 37, 53,
    6, 22, 38, 54, 7, 23, 39, 55,
    8, 24, 40, 56, 9, 25, 41, 57,
    10, 26, 42, 58, 11, 27, 43, 59,
    12, 28, 44, 60, 13, 29, 45, 61,
    14, 30, 46, 62, 15, 31, 47, 63
};

// ---------------------- Round constants ----------------------
uint64_t round_constant[] = {
    0x3E8958737D12B0E6, 0x23BE4C2D477C985A,
    0x2BDC0D262847E5B3, 0x36EB19781229CD0F,
    0x3479AD88170CA4EF
};

// ---------------------- Apply S-box ----------------------
uint64_t apply_sbox(uint64_t input) {
    uint64_t output = 0;
    for (int i = 0; i < 16; ++i) {
        uint8_t nibble = (input >> (i * 4)) & 0xF;
        output |= ((uint64_t)sbox[nibble] << (i * 4));
    }
    return output;
}

// ---------------------- Apply P-box ----------------------
uint64_t apply_pbox(uint64_t input) {
    uint64_t output = 0;
    for (int i = 0; i < 64; ++i) {
        uint64_t bit = (input >> i) & 1ULL;
        output |= (bit << present_pbox[i]);
    }
    return output;
}

// ---------------------- Feistel Function ----------------------
uint64_t feistel(uint64_t R, uint64_t round_key) {
    uint64_t xored = R ^ round_key;
    uint64_t substituted = apply_sbox(xored);
    return apply_pbox(substituted);
}

// ---------------------- Key Schedule ----------------------
uint64_t keyExpansion(uint64_t key[3], int round) {
    uint64_t temp = (key[0] >> 3) | (key[0] << (64 - 3));
    temp ^= key[2];
    temp ^= (key[0] >> 4) | (key[0] << (64 - 4));
    temp ^= round_constant[round % 5];

    uint64_t keyI = key[2];
    uint64_t temp2 = key[1];

    key[1] = key[0];
    key[0] = temp;
    key[2] = temp2;

    return keyI;
}

// ---------------------- Encryption ----------------------
void encrypt128(uint64_t &L, uint64_t &R, uint64_t key[3]) {
    for (int round = 0; round < 32; ++round) {
        uint64_t roundKey = keyExpansion(key, round);
        uint64_t temp = R;
        R = L ^ feistel(R, roundKey);
        L = temp;
    }
}

// ====================== PYBIND11 WRAPPER ======================

namespace py = pybind11;

// Python-friendly wrapper
std::tuple<uint64_t, uint64_t> encrypt_block(
    uint64_t L,
    uint64_t R,
    uint64_t k0,
    uint64_t k1,
    uint64_t k2
) {
    // Release GIL for performance
    py::gil_scoped_release release;

    uint64_t key[3] = {k0, k1, k2};

    encrypt128(L, R, key);

    return std::make_tuple(L, R);
}

// ---------------------- Module Definition ----------------------
PYBIND11_MODULE(encryption_module, m) {
    m.doc() = "SIMON-based cipher (C++ accelerated)";

    m.def("encrypt_block", &encrypt_block,
          "Encrypt a 128-bit block",
          py::arg("L"),
          py::arg("R"),
          py::arg("k0"),
          py::arg("k1"),
          py::arg("k2"));
}