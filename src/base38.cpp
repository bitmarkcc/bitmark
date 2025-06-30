// Copyright (c) 2014-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <base38.h>

#include <hash.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <assert.h>
#include <string.h>

#include <limits>

/** All alphanumeric characters except for "0", "I", "O", and "l" */
static const char* pszBase38 = "_0123456789abcdefghijklmnopqrstuvwxyz-";
static const int8_t mapBase38[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,37,-1,-1,
     1, 2, 3, 4, 5, 6, 7, 8,  9,10,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1, 0,
    -1,11,12,13,14,15,16,17, 18,19,20,21,22,23,24,25,
    26,27,28,29,30,31,32,33, 34,35,36,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
};

bool IsBase38 (const std::string str) {
    const char * s1 = str.c_str();
    while (*s1 != 0) {
	bool match = false;
	for (int j=0; j<38; j++) {
	    if (*s1==pszBase38[j])
		match = true;
	}
	if (!match) {
	    return false;
	}
	s1++;
    }
    return true;
}

[[nodiscard]] static bool DecodeBase38(const char* psz, std::vector<unsigned char>& vch, int max_ret_len)
{
    // Skip leading spaces.
    while (*psz && IsSpace(*psz))
        psz++;
    // Skip and count leading '1's.
    int zeroes = 0;
    int length = 0;
    while (*psz == '_') {
        zeroes++;
        if (zeroes > max_ret_len) return false;
        psz++;
    }
    // Allocate enough space in big-endian base256 representation.
    int size = strlen(psz) * 657 /1000 + 1; // log(38) / log(256), rounded up.
    std::vector<unsigned char> b256(size);
    // Process the characters.
    static_assert(std::size(mapBase38) == 256, "mapBase58.size() should be 256"); // guarantee not out of range
    while (*psz && !IsSpace(*psz)) {
        // Decode base58 character
        int carry = mapBase38[(uint8_t)*psz];
        if (carry == -1)  // Invalid b58 character
            return false;
        int i = 0;
        for (std::vector<unsigned char>::reverse_iterator it = b256.rbegin(); (carry != 0 || i < length) && (it != b256.rend()); ++it, ++i) {
            carry += 38 * (*it);
            *it = carry % 256;
            carry /= 256;
        }
        assert(carry == 0);
        length = i;
        if (length + zeroes > max_ret_len) return false;
        psz++;
    }
    // Skip trailing spaces.
    while (IsSpace(*psz))
        psz++;
    if (*psz != 0)
        return false;
    // Skip leading zeroes in b256.
    std::vector<unsigned char>::iterator it = b256.begin() + (size - length);
    // Copy result into output vector.
    vch.reserve(zeroes + (b256.end() - it));
    vch.assign(zeroes, 0x00);
    while (it != b256.end())
        vch.push_back(*(it++));
    return true;
}

std::string EncodeBase38(Span<const unsigned char> input)
{
    // Skip & count leading zeroes.
    int zeroes = 0;
    int length = 0;
    while (input.size() > 0 && input[0] == 0) {
        input = input.subspan(1);
        zeroes++;
    }
    // Allocate enough space in big-endian base58 representation.
    int size = input.size() * 153 / 100 + 1; // log(256) / log(38), rounded up.
    std::vector<unsigned char> b38(size);
    // Process the bytes.
    while (input.size() > 0) {
        int carry = input[0];
        int i = 0;
        // Apply "b58 = b58 * 256 + ch".
        for (std::vector<unsigned char>::reverse_iterator it = b38.rbegin(); (carry != 0 || i < length) && (it != b38.rend()); it++, i++) {
            carry += 256 * (*it);
            *it = carry % 38;
            carry /= 38;
        }

        assert(carry == 0);
        length = i;
        input = input.subspan(1);
    }
    // Skip leading zeroes in base58 result.
    std::vector<unsigned char>::iterator it = b38.begin() + (size - length);
    while (it != b38.end() && *it == 0)
        it++;
    // Translate the result into a string.
    std::string str;
    str.reserve(zeroes + (b38.end() - it));
    str.assign(zeroes, '_');
    while (it != b38.end())
        str += pszBase38[*(it++)];
    return str;
}

bool DecodeBase38(const std::string& str, std::vector<unsigned char>& vchRet, int max_ret_len)
{
    if (!ContainsNoNUL(str)) {
        return false;
    }
    return DecodeBase38(str.c_str(), vchRet, max_ret_len);
}

std::string EncodeBase38Check(Span<const unsigned char> input)
{
    // add 4-byte hash check to the end
    std::vector<unsigned char> vch(input.begin(), input.end());
    uint256 hash = Hash(vch);
    vch.insert(vch.end(), (unsigned char*)&hash, (unsigned char*)&hash + 4);
    return EncodeBase38(vch);
}

[[nodiscard]] static bool DecodeBase38Check(const char* psz, std::vector<unsigned char>& vchRet, int max_ret_len)
{
    if (!DecodeBase38(psz, vchRet, max_ret_len > std::numeric_limits<int>::max() - 4 ? std::numeric_limits<int>::max() : max_ret_len + 4) ||
        (vchRet.size() < 4)) {
        vchRet.clear();
        return false;
    }
    // re-calculate the checksum, ensure it matches the included 4-byte checksum
    uint256 hash = Hash(Span{vchRet}.first(vchRet.size() - 4));
    if (memcmp(&hash, &vchRet[vchRet.size() - 4], 4) != 0) {
        vchRet.clear();
        return false;
    }
    vchRet.resize(vchRet.size() - 4);
    return true;
}

bool DecodeBase38Check(const std::string& str, std::vector<unsigned char>& vchRet, int max_ret)
{
    if (!ContainsNoNUL(str)) {
        return false;
    }
    return DecodeBase38Check(str.c_str(), vchRet, max_ret);
}
