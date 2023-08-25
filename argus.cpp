//
// Created by jpacg on 2022/12/20.
//

#include "argus.h"
#include "base64.h"
#include <string>
#include "common.h"
extern "C" {
#include "simon.h"
#include "pkcs7_padding.h"
}
#include "aes.hpp"
#include "ByteBuf.hpp"
#include "ByteBuf.h"
#include <digestpp.hpp>


int decrypt_enc_pb(uint8_t *data, uint32_t len) {
    // 后8位
    ByteBuf ba(&data[len-8], 8);
    for (int i = 0; i < len; ++i) {
        data[i] = data[i] ^ ba.data()[i % 4];
    }
    std::reverse(data, data+len);
    return 0;
}

std::string aes_cbc_decrypt(uint8_t *data, uint32_t len, uint8_t key[16], uint8_t iv[16]) {
    std::string result;
    result.resize(padding_size(len));
    memcpy(result.data(), data, len);

    AES_ctx ctx{};
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_decrypt_buffer(&ctx, (uint8_t *) result.data(), result.size());

    auto padding_size = pkcs7_padding_data_length(reinterpret_cast<uint8_t *>(result.data()), result.size(), 16);
    if (padding_size == 0) {
        return result;
    }
    return {result.data(), padding_size};
}

std::string decrypt_argus(const char *x_argus) {
    auto argus = base64_decode(std::string(x_argus));
    if (argus.empty()) {
        return "";
    }
    uint16_t rand_right = *(uint16_t *)argus.data();

    std::string sign_key_array[] = {
            "jr36OAbsxc7nlCPmAp7YJUC8Ihi7fq73HLaR96qKovU=",  // com.ss.android.ugc.aweme
            "wC8lD4bMTxmNVwY5jSkqi3QWmrphr/58ugLko7UZgWM=",  // com.zhiliaoapp.musically
            "oZ2VbHzgo5UYZCJv1QBvQfhCxpEze6oNiRCj5inPG7I=",  // com.ss.android.ugc.trill
            "OFZfG2ApxcPkYeMDXsCjAs7acx8jlF6gVJxM9FNvUj4=",  // com.zhiliaoapp.musically.go
            "rBrarpWnr5SlEUqzs6l92ABQqgo5MUxAUoyuyVJWwow=",  // unidbg
            "cY+CAKtjNGQRUDrD5B2qu7NILFyC++FdPRuHynmef3E=",  // 抖音火山版
            "GeVxhvFoBjyq7+dNVHAQtXMxc39qUapIeHqQh6Uc76A=",  // 抖音火山版(老版本)
            "Z5IFAcZF0pCPguwmKrQnyARLolMWrPHZaUIJOmQcoQQ=",  // 抖店
            "AIJX98Bt3JdPu6iUUHM6R+08duolzUsLisT2AOaG8cM=",  // 西瓜视频
            "lrpicn/pKdjB7w085M0UQbwENZ+dobF8yhcUoGLefFQ=",  // 抖音盒子
            "7LUXMlMnhanH0hz8GVMH1/sp76hCxdCiLUIX3dTziYU=",  // 可颂
            "nlsF8XSbbY3t+6Me0vNx/dIB8oH0NVfSaT3tkPcYxoo=",  // 抖音极速版

    };
    std::string output;
    std::string sign_key;
    for (const auto &key : sign_key_array) {
        sign_key = base64_decode(key);
        uint8_t aes_key[16] = {0};
        uint8_t aes_iv[16] = {0};
        digestpp::md5().absorb(sign_key.data(), 16).digest(aes_key);
        digestpp::md5().absorb(sign_key.data() + 16, 16).digest(aes_iv);
        output = aes_cbc_decrypt(reinterpret_cast<uint8_t *>(argus.data() + 2), argus.size()-2, aes_key, aes_iv);

        if ((output[5] != 0x0 && output[5] != 0x1) ||  output[8] != 0x18) {
            output.clear();
            continue;
        }
        break;
    }

    if (output.empty()) {
        return "";
    }

    // 第一个字节 0x35(抖音), 0xec(tiktok), 0xdc(com.ss.android.ugc.trill), 0xd0(com.zhiliaoapp.musically.go)
    // 再后面四个字节是 random 的数据, 没参与任何运算
    // 再后面四个字节是 (01 02 0c 18), 01与18是不变的, 02,0c 是根据 url query 和 x-ss-stub 算来的
    // 数据
    // 倒数2个字节是随机数高位
    uint32_t len = output.size();
    uint16_t rand_left = *(uint16_t *)&output[len - 2];

    uint32_t random_num = rand_left;
    random_num = random_num << 16 | rand_right;

    uint32_t bsize = len-9-2;
    auto *b_buffer = new uint8_t[bsize];
    memcpy(b_buffer, &output[9], bsize);

    decrypt_enc_pb(b_buffer, bsize);
    auto size = sign_key.size() + 4 + sign_key.size();
    sh::ByteBuf sm3Buf;
    sm3Buf.writeBytes(sign_key.data(), sign_key.size());
    sm3Buf.writeBytes(reinterpret_cast<const char *>(&random_num), 4);
    sm3Buf.writeBytes(sign_key.data(), sign_key.size());
    unsigned char sm3_output[32] = {0};
    digestpp::sm3().absorb(sm3Buf.data(), size).digest(sm3_output);

    uint64_t key[] = {0, 0, 0, 0};
    memcpy(key, sm3_output, 32);

    uint64_t ct[2] = {0, 0};
    uint64_t pt[2] = {0, 0};

    uint8_t *p = &b_buffer[8];
    uint32_t new_len = bsize - 8;

    auto *protobuf = new uint8_t[new_len];
    for (int i = 0; i < new_len / 16; ++i) {
        memcpy(&ct, &p[i * 16], 16);
        simon_dec(pt, ct, key);
        // 定位到行，写一行(16字节)
        memcpy(&protobuf[i * 16], &pt[0], 8);
        memcpy(&protobuf[i * 16 + 8], &pt[1], 8);
    }

    ByteBuf pb_ba(protobuf, new_len);
    delete[] b_buffer;
    delete[] protobuf;
    uint32_t padding_size = pb_ba.remove_padding();
    if (padding_size == new_len) {
        return {(const char *)pb_ba.data(), pb_ba.size()};
    }
    return {(const char *)pb_ba.data(), pb_ba.size()};
}
