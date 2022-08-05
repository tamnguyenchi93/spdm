
#include "test_helpers.hpp"

#include <spdmcpp/common.hpp>
#include <spdmcpp/connection.hpp>
#include <spdmcpp/context.hpp>
#include <spdmcpp/hash.hpp>
#include <spdmcpp/helpers.hpp>

#include <array>
#include <cstring>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace spdmcpp;

std::array<uint8_t, 512> refBuf = {
    0xc7, 0x9b, 0x3d, 0xdc, 0xd3, 0xe4, 0xf7, 0x2e, 0xf9, 0xc2, 0x74, 0xc0,
    0x9c, 0x9b, 0xc6, 0xcb, 0xa4, 0x63, 0xb9, 0x57, 0x09, 0xa9, 0x4d, 0xe7,
    0x0f, 0xb8, 0xdb, 0x79, 0x60, 0x7f, 0xae, 0x72, 0x42, 0x88, 0x59, 0xfe,
    0x03, 0x9d, 0x5c, 0x2e, 0xf3, 0xb9, 0x38, 0xf0, 0x52, 0x8a, 0xeb, 0x78,
    0x09, 0xa0, 0x11, 0xb0, 0xa1, 0x4a, 0xdf, 0x0e, 0x03, 0xc9, 0xbf, 0x87,
    0xd0, 0x33, 0x14, 0x98, 0xa8, 0x8b, 0x82, 0x74, 0x7b, 0x83, 0xf4, 0xab,
    0x01, 0x1f, 0x3f, 0x1d, 0xb6, 0xd6, 0x53, 0x46, 0x47, 0x9e, 0xb2, 0x97,
    0xeb, 0xb0, 0x3f, 0x4d, 0x75, 0xa0, 0x41, 0x17, 0x61, 0x8a, 0x9b, 0x12,
    0xc5, 0x48, 0x12, 0x1d, 0xaf, 0x8b, 0x8c, 0xa0, 0x24, 0x7f, 0x1a, 0xb7,
    0x3f, 0x35, 0x27, 0xfe, 0xed, 0x2e, 0xae, 0xfe, 0x3d, 0x89, 0x92, 0x18,
    0x8e, 0x47, 0x13, 0x30, 0xd7, 0x73, 0x68, 0x6d, 0x25, 0x01, 0x31, 0x81,
    0x7e, 0x76, 0xb6, 0xcb, 0xfc, 0x04, 0xe0, 0xbf, 0x80, 0xfd, 0x1c, 0x31,
    0xe9, 0x23, 0x5e, 0x2f, 0x3a, 0x08, 0xdf, 0x66, 0x23, 0x2b, 0x3d, 0x0b,
    0x98, 0xf6, 0x90, 0x5c, 0xf5, 0x07, 0x74, 0x8c, 0x21, 0xc7, 0xc2, 0x91,
    0x34, 0x73, 0x2d, 0xfb, 0x70, 0x87, 0x57, 0xe2, 0xf7, 0xa2, 0x25, 0x1d,
    0xd8, 0x70, 0xab, 0x38, 0x1c, 0x6c, 0x17, 0xa1, 0xf7, 0x61, 0x32, 0x06,
    0x15, 0xfa, 0x45, 0xc2, 0xa6, 0x08, 0x8c, 0x98, 0xb2, 0x95, 0xf6, 0xd4,
    0x47, 0xbc, 0x3c, 0xe9, 0xd8, 0xc9, 0x3a, 0x66, 0xb0, 0x55, 0x28, 0x70,
    0x34, 0x43, 0x12, 0xea, 0xc0, 0x36, 0x2e, 0x50, 0x20, 0x36, 0x3a, 0x8b,
    0x48, 0x5c, 0x09, 0xe5, 0x41, 0x9f, 0xab, 0x0f, 0xc2, 0x77, 0x3a, 0x2e,
    0x9d, 0xc2, 0xe9, 0xfd, 0x8b, 0xfd, 0x60, 0x52, 0x04, 0xf8, 0xd4, 0xbf,
    0xd1, 0x06, 0x15, 0x15, 0x2c, 0x69, 0xd6, 0xd4, 0x90, 0xdb, 0x5a, 0x02,
    0x25, 0x3b, 0x1a, 0x89, 0x8f, 0x3c, 0xb6, 0x7f, 0xf3, 0x9f, 0xbf, 0x3a,
    0x5f, 0x0c, 0xc2, 0xb2, 0x13, 0x5d, 0x9f, 0x96, 0xb8, 0xba, 0x0b, 0xde,
    0x65, 0xdb, 0x2a, 0x53, 0x47, 0x68, 0x3a, 0x71, 0x4e, 0xe2, 0x23, 0xe4,
    0xb2, 0x65, 0x0e, 0x85, 0x95, 0xb5, 0x2e, 0x16, 0x82, 0xde, 0x48, 0xac,
    0x5f, 0xb4, 0x81, 0x69, 0x20, 0x3e, 0x22, 0xed, 0xd8, 0xff, 0x65, 0xde,
    0x2c, 0xa4, 0xcd, 0x49, 0xe9, 0xea, 0xd4, 0x2d, 0xb7, 0xf7, 0x1a, 0xc1,
    0xe9, 0xf3, 0x94, 0xac, 0xe6, 0xb5, 0x90, 0x0a, 0x03, 0xb2, 0xfe, 0x5d,
    0x22, 0xca, 0xb1, 0xd8, 0x56, 0xbb, 0x2e, 0xec, 0x24, 0x2f, 0xab, 0xed,
    0x4e, 0x25, 0x9d, 0x51, 0xef, 0xcf, 0x34, 0xb9, 0x1f, 0x11, 0x65, 0xb8,
    0xb2, 0x02, 0xf1, 0x39, 0x2a, 0x32, 0x75, 0xb2, 0x48, 0x47, 0x35, 0x15,
    0x4f, 0x68, 0xcb, 0xea, 0x18, 0x75, 0xde, 0xae, 0xd5, 0x40, 0xae, 0xad,
    0x4c, 0x8d, 0x2b, 0xaf, 0xeb, 0x31, 0x13, 0x2c, 0x79, 0x83, 0x5c, 0x48,
    0x29, 0xfc, 0xf7, 0x1c, 0x38, 0xfd, 0xb6, 0xfa, 0xe1, 0x81, 0xab, 0x5c,
    0x25, 0xec, 0xcb, 0x5c, 0x37, 0x91, 0xf4, 0x34, 0x16, 0xdd, 0xa4, 0x8b,
    0x9d, 0x4f, 0x7b, 0x6d, 0x2b, 0x1d, 0x41, 0x06, 0xbb, 0xde, 0xf5, 0x4a,
    0xed, 0x75, 0xbd, 0x0d, 0x3c, 0x4d, 0xc3, 0xce, 0x4c, 0x9e, 0x48, 0xc3,
    0xc4, 0x7b, 0xaf, 0x6e, 0x46, 0xdb, 0x2a, 0x4b, 0x1b, 0xd7, 0x7d, 0x31,
    0xd5, 0x02, 0x53, 0xae, 0x98, 0xa8, 0x2f, 0x5b, 0x53, 0xdd, 0xb2, 0xb2,
    0x80, 0x9d, 0xdf, 0x52, 0xd4, 0xbd, 0x4c, 0x87, 0x08, 0x86, 0xa5, 0x14,
    0xde, 0x79, 0xd9, 0xf4, 0x04, 0x05, 0x27, 0x1e, 0x2f, 0x8a, 0x48, 0x09,
    0x51, 0x22, 0x15, 0xb1, 0x5e, 0x8c, 0xe7, 0xc6};

uint8_t charToUint(char c)
{
    if (c >= '0' && c <= '9')
    {
        return static_cast<uint8_t>(c - '0');
    }
    if (c >= 'a' && c <= 'f')
    {
        return static_cast<uint8_t>((c - 'a') + 10);
    }
    if (c >= 'A' && c <= 'F')
    {
        return static_cast<uint8_t>((c - 'A') + 10);
    }
    std::cerr << "char_to_uint() invalid character '" << c << "'\n";
    SPDMCPP_ASSERT(false);
    return 0;
}

template <size_t N>
void stringToHash(std::array<uint8_t, N>& arr, const char* str)
{
    size_t len = strlen(str);
    ASSERT_EQ(len, 2 * N);
    for (size_t i = 0; i < N; ++i)
    {
        // NOLINTNEXTLINE cppcoreguidelines-pro-bounds-pointer-arithmetic
        arr[i] = charToUint(str[2 * i + 1]);
        // NOLINTNEXTLINE cppcoreguidelines-pro-bounds-pointer-arithmetic
        arr[i] |= charToUint(str[2 * i]) << 4;
    }
}

TEST(Hash, SHA256)
{
    std::array<uint8_t, 32> refHash{};
    stringToHash(
        refHash,
        "33c452d940f6b206bc539bfe92b3151317fb70dfe2c17ecf59375c9f745d1102");

    /*std::ofstream file;
    file.open("ref_buf.bin", std::ios::out | std::ios::app |
    std::ios::binary);
    file << ref_buf;
    file.close();*/

    /*uint8_t ref_buf[512];
    std::ifstream file;
    file.open("ref_buf.bin", std::ios::in | std::ios::binary);
    file.read(ref_buf, sizeof(ref_buf));
    file.close();*/

    std::vector<uint8_t> hash;
    {
        HashEnum en = HashEnum::TPM_ALG_SHA_256;
        EXPECT_EQ(en, toHash(BaseHashAlgoFlags::TPM_ALG_SHA_256));
        EXPECT_EQ(en, toHash(MeasurementHashAlgoFlags::TPM_ALG_SHA_256));
        HashClass::compute(hash, en, refBuf.data(), refBuf.size());
    }
    // ASSERT_THAT(hash, ElementsAre(ref_hash));
    EXPECT_EQ(hash.size(), refHash.size());
    EXPECT_EQ(memcmp(hash.data(), refHash.data(), refHash.size()), 0);
}

TEST(Hash, SHA384)
{
    std::array<uint8_t, 48> refHash{};
    stringToHash(
        refHash,
        "6625f7f39c1f107ae4344afd711dfde3e2045cc8c467f1a785e75ade18986e5f5db2d8e73b680051d92295e307915533");

    std::vector<uint8_t> hash;
    {
        HashEnum en = HashEnum::TPM_ALG_SHA_384;
        EXPECT_EQ(en, toHash(BaseHashAlgoFlags::TPM_ALG_SHA_384));
        EXPECT_EQ(en, toHash(MeasurementHashAlgoFlags::TPM_ALG_SHA_384));
        HashClass::compute(hash, en, refBuf.data(), refBuf.size());
    }

    // ASSERT_THAT(hash, ElementsAre(ref_hash));
    EXPECT_EQ(hash.size(), refHash.size());
    EXPECT_EQ(memcmp(hash.data(), refHash.data(), refHash.size()), 0);
}

TEST(Hash, SHA512)
{
    std::array<uint8_t, 64> refHash{};
    stringToHash(
        refHash,
        "64fff176528eba19be10b0122741796ebb753dc72cfe9259e95eff49cada7cab50e2cdb9b380e3334065d0d44493ec1d01ac0bbcf8bd64115554a41a33a12a57");

    std::vector<uint8_t> hash;
    {
        HashEnum en = HashEnum::TPM_ALG_SHA_512;
        EXPECT_EQ(en, toHash(BaseHashAlgoFlags::TPM_ALG_SHA_512));
        EXPECT_EQ(en, toHash(MeasurementHashAlgoFlags::TPM_ALG_SHA_512));
        HashClass::compute(hash, en, refBuf.data(), refBuf.size());
    }

    // ASSERT_THAT(hash, ElementsAre(ref_hash));
    EXPECT_EQ(hash.size(), refHash.size());
    EXPECT_EQ(memcmp(hash.data(), refHash.data(), refHash.size()), 0);
}
