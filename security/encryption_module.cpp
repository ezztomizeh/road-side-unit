#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <vector>
#include <cstdint>
#include <thread>

namespace py = pybind11;

// ---------------------- Block type ----------------------
struct block128 {
    uint64_t hi;
    uint64_t lo;

    inline block128 operator^(const block128 &b) const { return {hi ^ b.hi, lo ^ b.lo}; }
    inline block128& operator^=(const block128 &b) { hi ^= b.hi; lo ^= b.lo; return *this; }
};

// ---------------------- SIMON Block Cipher ----------------------
// S-box
constexpr uint8_t SBOX[16] = {0xE,0x4,0x8,0x5,0x6,0x1,0x9,0xF,0xD,0xC,0xA,0x7,0xB,0x0,0x2,0x3};
// PRESENT-style P-box
constexpr int PRESENT_PBOX[64] = {
    0,16,32,48,1,17,33,49,2,18,34,50,3,19,35,51,4,20,36,52,5,21,37,53,6,22,38,54,7,23,39,55,
    8,24,40,56,9,25,41,57,10,26,42,58,11,27,43,59,12,28,44,60,13,29,45,61,14,30,46,62,15,31,47,63
};
// Round constants
constexpr uint64_t ROUND_CONST[5] = {0x3E8958737D12B0E6,0x23BE4C2D477C985A,0x2BDC0D262847E5B3,0x36EB19781229CD0F,0x3479AD88170CA4EF};

// ---------------------- Apply S-box ----------------------
inline uint64_t apply_sbox(uint64_t x) {
    return
        (static_cast<uint64_t>(SBOX[(x >>  0) & 0xF]) <<  0)  |
        (static_cast<uint64_t>(SBOX[(x >>  4) & 0xF]) <<  4)  |
        (static_cast<uint64_t>(SBOX[(x >>  8) & 0xF]) <<  8)  |
        (static_cast<uint64_t>(SBOX[(x >> 12) & 0xF]) << 12)  |
        (static_cast<uint64_t>(SBOX[(x >> 16) & 0xF]) << 16)  |
        (static_cast<uint64_t>(SBOX[(x >> 20) & 0xF]) << 20)  |
        (static_cast<uint64_t>(SBOX[(x >> 24) & 0xF]) << 24)  |
        (static_cast<uint64_t>(SBOX[(x >> 28) & 0xF]) << 28)  |
        (static_cast<uint64_t>(SBOX[(x >> 32) & 0xF]) << 32)  |
        (static_cast<uint64_t>(SBOX[(x >> 36) & 0xF]) << 36)  |
        (static_cast<uint64_t>(SBOX[(x >> 40) & 0xF]) << 40)  |
        (static_cast<uint64_t>(SBOX[(x >> 44) & 0xF]) << 44)  |
        (static_cast<uint64_t>(SBOX[(x >> 48) & 0xF]) << 48)  |
        (static_cast<uint64_t>(SBOX[(x >> 52) & 0xF]) << 52)  |
        (static_cast<uint64_t>(SBOX[(x >> 56) & 0xF]) << 56)  |
        (static_cast<uint64_t>(SBOX[(x >> 60) & 0xF]) << 60);
}

// ---------------------- Apply P-box ----------------------
inline uint64_t apply_pbox(uint64_t x) {
    return
        (((x >> 0) & 1ULL) <<  0) |  (((x >> 1) & 1ULL) << 16) |
        (((x >> 2) & 1ULL) << 32) |  (((x >> 3) & 1ULL) << 48) |
        (((x >> 4) & 1ULL) <<  1) |  (((x >> 5) & 1ULL) << 17) |
        (((x >> 6) & 1ULL) << 33) |  (((x >> 7) & 1ULL) << 49) |
        (((x >> 8) & 1ULL) <<  2) |  (((x >> 9) & 1ULL) << 18) |
        (((x >> 10) & 1ULL) << 34) | (((x >> 11) & 1ULL) << 50) |
        (((x >> 12) & 1ULL) << 3) |  (((x >> 13) & 1ULL) << 19) |
        (((x >> 14) & 1ULL) << 35) | (((x >> 15) & 1ULL) << 51) |
        (((x >> 16) & 1ULL) << 4) |  (((x >> 17) & 1ULL) << 20) |
        (((x >> 18) & 1ULL) << 36) | (((x >> 19) & 1ULL) << 52) |
        (((x >> 20) & 1ULL) << 5) |  (((x >> 21) & 1ULL) << 21) |
        (((x >> 22) & 1ULL) << 37) | (((x >> 23) & 1ULL) << 53) |
        (((x >> 24) & 1ULL) << 6) |  (((x >> 25) & 1ULL) << 22) |
        (((x >> 26) & 1ULL) << 38) | (((x >> 27) & 1ULL) << 54) |
        (((x >> 28) & 1ULL) << 7) |  (((x >> 29) & 1ULL) << 23) |
        (((x >> 30) & 1ULL) << 39) | (((x >> 31) & 1ULL) << 55) |
        (((x >> 32) & 1ULL) << 8) |  (((x >> 33) & 1ULL) << 24) |
        (((x >> 34) & 1ULL) << 40) | (((x >> 35) & 1ULL) << 56) |
        (((x >> 36) & 1ULL) << 9) |  (((x >> 37) & 1ULL) << 25) |
        (((x >> 38) & 1ULL) << 41) | (((x >> 39) & 1ULL) << 57) |
        (((x >> 40) & 1ULL) << 10) | (((x >> 41) & 1ULL) << 26) |
        (((x >> 42) & 1ULL) << 42) | (((x >> 43) & 1ULL) << 58) |
        (((x >> 44) & 1ULL) << 11) | (((x >> 45) & 1ULL) << 27) |
        (((x >> 46) & 1ULL) << 43) | (((x >> 47) & 1ULL) << 59) |
        (((x >> 48) & 1ULL) << 12) | (((x >> 49) & 1ULL) << 28) |
        (((x >> 50) & 1ULL) << 44) | (((x >> 51) & 1ULL) << 60) |
        (((x >> 52) & 1ULL) << 13) | (((x >> 53) & 1ULL) << 29) |
        (((x >> 54) & 1ULL) << 45) | (((x >> 55) & 1ULL) << 61) |
        (((x >> 56) & 1ULL) << 14) | (((x >> 57) & 1ULL) << 30) |
        (((x >> 58) & 1ULL) << 46) | (((x >> 59) & 1ULL) << 62) |
        (((x >> 60) & 1ULL) << 15) | (((x >> 61) & 1ULL) << 31) |
        (((x >> 62) & 1ULL) << 47) | (((x >> 63) & 1ULL) << 63);
}

inline uint64_t feistel(uint64_t R,uint64_t rk) {
    return apply_pbox(apply_sbox(R^rk));
}

inline uint64_t key_expansion(uint64_t k[3], int r) {
    uint64_t temp = (k[0]>>3)|(k[0]<<61);
    temp ^= (k[0]>>4)|(k[0]<<60);
    temp ^= k[2]^ROUND_CONST[r%5];
    uint64_t out = k[2];
    k[2]=k[1]; k[1]=k[0]; k[0]=temp;
    return out;
}

inline void encrypt128(uint64_t &L,uint64_t &R,uint64_t k[3]) {
    for(int r=0;r<32;r++) {
        uint64_t rk = key_expansion(k,r);
        uint64_t temp=L; L=R; R=temp^feistel(R,rk);
    }
}

// ---------------------- CTR mode ----------------------
inline block128 encrypt_block_ctr(block128 ctr,uint64_t key[3]) {
    uint64_t L=ctr.hi,R=ctr.lo;
    uint64_t temp_key[3]={key[0],key[1],key[2]};
    encrypt128(L,R,temp_key);
    return {L,R};
}

// ---------------------- GF(2^128) multiply (simplified Karatsuba) ----------------------
block128 gf128_mul(const block128 &X,const block128 &Y){
    uint64_t Xh=X.hi,Xl=X.lo,Yh=Y.hi,Yl=Y.lo;
    uint64_t Z0l=Xl&Yl,Z0h=Xl&Yh,Z2l=Xh&Yl,Z2h=Xh&Yh,Z1l=(Xh^Xl)&(Yh^Yl),Z1h=Z1l^Z0h^Z2l;
    block128 out; out.hi=Z2h^Z1h; out.lo=Z0l^Z1l^Z2l;
    out.lo ^= (out.hi>>57)^(out.hi>>62)^(out.hi>>63); out.hi&=0x7FFFFFFFFFFFFFFF;
    return out;
}

// ---------------------- GHASH ----------------------
block128 ghash_block(const block128 &X,const block128 &H){
    block128 Z=X^H,out={0,0},x=Z,y=H;
    for(int i=0;i<128;i++){
        bool bit = (i<64)?(y.hi&(1ULL<<(63-i))):(y.lo&(1ULL<<(127-i)));
        if(bit) out^=x;
        bool msb = x.hi & (1ULL<<63);
        x.hi=(x.hi<<1)|(x.lo>>63); x.lo<<=1;
        if(msb) x.lo^=0x87ULL;
    }
    return out;
}

block128 ghash(const std::vector<block128> &data,const block128 &H){
    size_t n=data.size(); block128 tag={0,0};
    size_t num_threads=std::thread::hardware_concurrency(); if(num_threads==0) num_threads=1;
    std::vector<block128> partial(num_threads,{0,0}); std::vector<std::thread> threads;
    for(size_t t=0;t<num_threads;t++){
        threads.emplace_back([&,t](){
            block128 local={0,0};
            for(size_t i=t;i<n;i+=num_threads) local=gf128_mul(local^data[i],H);
            partial[t]=local;
        });
    }
    for(auto &th:threads) th.join();
    for(auto &p:partial) tag=gf128_mul(tag^p,H);
    return tag;
}

// ---------------------- GCM Encrypt / Decrypt ----------------------
void gcm_encrypt(const std::vector<block128> &plaintext,std::vector<block128> &ciphertext,
                 uint64_t key[3],block128 nonce,block128 &auth_tag){
    size_t n=plaintext.size(); ciphertext.resize(n);
    block128 H=encrypt_block_ctr({0,0},key);
    size_t num_threads=std::thread::hardware_concurrency(); if(num_threads==0) num_threads=1;
    std::vector<std::thread> threads;
    for(size_t t=0;t<num_threads;t++){
        threads.emplace_back([&,t](){
            block128 ctr=nonce;
            for(size_t i=t;i<n;i+=num_threads){
                ctr.lo=nonce.lo+i;
                ciphertext[i]=plaintext[i]^encrypt_block_ctr(ctr,key);
            }
        });
    }
    for(auto &th:threads) th.join();
    auth_tag=ghash(ciphertext,H);
}

bool gcm_decrypt(const std::vector<block128> &ciphertext,std::vector<block128> &plaintext,
                 uint64_t key[3],block128 nonce,const block128 &auth_tag){
    size_t n=ciphertext.size(); plaintext.resize(n);
    block128 H=encrypt_block_ctr({0,0},key);
    block128 computed_tag=ghash(ciphertext,H);
    if(computed_tag.hi!=auth_tag.hi || computed_tag.lo!=auth_tag.lo) return false;
    size_t num_threads=std::thread::hardware_concurrency(); if(num_threads==0) num_threads=1;
    std::vector<std::thread> threads;
    for(size_t t=0;t<num_threads;t++){
        threads.emplace_back([&,t](){
            block128 ctr=nonce;
            for(size_t i=t;i<n;i+=num_threads){
                ctr.lo=nonce.lo+i;
                plaintext[i]=ciphertext[i]^encrypt_block_ctr(ctr,key);
            }
        });
    }
    for(auto &th:threads) th.join();
    return true;
}

// ---------------------- Python Wrappers ----------------------
std::vector<block128> pylist_to_blocks(const py::list &lst){
    std::vector<block128> out;
    for(auto item:lst){
        auto tup=item.cast<std::tuple<uint64_t,uint64_t>>();
        out.push_back({std::get<0>(tup),std::get<1>(tup)});
    }
    return out;
}

py::list blocks_to_pylist(const std::vector<block128> &blocks){
    py::list out;
    for(auto &b:blocks) out.append(py::make_tuple(b.hi,b.lo));
    return out;
}

py::tuple py_gcm_encrypt(const py::list &plaintext,uint64_t k0,uint64_t k1,uint64_t k2,
                         uint64_t nonce_hi,uint64_t nonce_lo){
    uint64_t key[3]={k0,k1,k2}; block128 nonce={nonce_hi,nonce_lo};
    std::vector<block128> pt=pylist_to_blocks(plaintext),ct; block128 tag;
    gcm_encrypt(pt,ct,key,nonce,tag);
    return py::make_tuple(blocks_to_pylist(ct),py::make_tuple(tag.hi,tag.lo));
}

py::tuple py_gcm_decrypt(const py::list &ciphertext,uint64_t k0,uint64_t k1,uint64_t k2,
                         uint64_t nonce_hi,uint64_t nonce_lo,uint64_t tag_hi,uint64_t tag_lo){
    uint64_t key[3]={k0,k1,k2}; block128 nonce={nonce_hi,nonce_lo}; block128 auth_tag={tag_hi,tag_lo};
    std::vector<block128> ct=pylist_to_blocks(ciphertext),pt;
    bool ok=gcm_decrypt(ct,pt,key,nonce,auth_tag);
    return py::make_tuple(ok,blocks_to_pylist(pt));
}

// ---------------------- Module ----------------------
PYBIND11_MODULE(encryption_module,m){
    m.doc()="SIMON-based GCM AE cipher (C++ accelerated)";
    m.def("gcm_encrypt",&py_gcm_encrypt,"Encrypt list of 128-bit blocks",
          py::arg("plaintext"),py::arg("k0"),py::arg("k1"),py::arg("k2"),
          py::arg("nonce_hi"),py::arg("nonce_lo"));
    m.def("gcm_decrypt",&py_gcm_decrypt,"Decrypt list of 128-bit blocks",
          py::arg("ciphertext"),py::arg("k0"),py::arg("k1"),py::arg("k2"),
          py::arg("nonce_hi"),py::arg("nonce_lo"),py::arg("tag_hi"),py::arg("tag_lo"));
}