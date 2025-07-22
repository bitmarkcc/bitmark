// Copyright (c) 2014-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <base82.h>

#include <hash.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <assert.h>
#include <string.h>

#include <limits>

/** All characters allowed in a URL path */
static const char* pszBase82 = "/0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-~.?#%!*'();:@&=+$";
static const int8_t mapBase82[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,70,-1,68,81,69,78,72, 73,74,71,80,-1,64,66, 0,
     1, 2, 3, 4, 5, 6, 7, 8,  9,10,76,75,-1,79,-1,67,
    77,11,12,13,14,15,16,17, 18,19,20,21,22,23,24,25,
    26,27,28,29,30,31,32,33, 34,35,36,-1,-1,-1,-1,63,
    -1,37,38,39,40,41,42,43, 44,45,46,47,48,49,50,51,
    52,53,54,55,56,57,58,59, 60,61,62,-1,-1,-1,65,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
};

bool IsBase82 (const std::string str) {
    const char * s1 = str.c_str();
    while (*s1 != 0) {
	bool match = false;
	for (int j=0; j<82; j++) {
	    if (*s1==pszBase82[j])
		match = true;
	}
	if (!match) {
	    return false;
	}
	s1++;
    }
    return true;
}

[[nodiscard]] static bool DecodeBase82(const char* psz, std::vector<unsigned char>& vch, int max_ret_len)
{
    // Skip leading spaces.
    while (*psz && IsSpace(*psz))
        psz++;
    // Skip and count leading '0's. TODO:check
    int zeroes = 0;
    int length = 0;
    while (*psz == '0') {
        zeroes++;
        if (zeroes > max_ret_len) return false;
        psz++;
    }
    // Allocate enough space in big-endian base256 representation.
    int size = strlen(psz) * 796 /1000 + 1; // log(82) / log(256), rounded up.
    std::vector<unsigned char> b256(size);
    // Process the characters.
    static_assert(std::size(mapBase82) == 256, "mapBase82.size() should be 256"); // guarantee not out of range
    while (*psz && !IsSpace(*psz)) {
        // Decode base82 character
        int carry = mapBase82[(uint8_t)*psz];
        if (carry == -1)  // Invalid b82 character
            return false;
        int i = 0;
        for (std::vector<unsigned char>::reverse_iterator it = b256.rbegin(); (carry != 0 || i < length) && (it != b256.rend()); ++it, ++i) {
            carry += 82 * (*it);
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

std::string EncodeBase82(Span<const unsigned char> input)
{
    // Skip & count leading zeroes.
    int zeroes = 0;
    int length = 0;
    while (input.size() > 0 && input[0] == 0) {
        input = input.subspan(1);
        zeroes++;
    }
    // Allocate enough space in big-endian base82 representation.
    int size = input.size() * 127 / 100 + 1; // log(256) / log(82), rounded up.
    std::vector<unsigned char> b82(size);
    // Process the bytes.
    while (input.size() > 0) {
        int carry = input[0];
        int i = 0;
        // Apply "b82 = b82 * 256 + ch".
        for (std::vector<unsigned char>::reverse_iterator it = b82.rbegin(); (carry != 0 || i < length) && (it != b82.rend()); it++, i++) {
            carry += 256 * (*it);
            *it = carry % 82;
            carry /= 82;
        }

        assert(carry == 0);
        length = i;
        input = input.subspan(1);
    }
    // Skip leading zeroes in base82 result.
    std::vector<unsigned char>::iterator it = b82.begin() + (size - length);
    while (it != b82.end() && *it == 0)
        it++;
    // Translate the result into a string.
    std::string str;
    str.reserve(zeroes + (b82.end() - it));
    str.assign(zeroes, '_');
    while (it != b82.end())
        str += pszBase82[*(it++)];
    return str;
}

bool DecodeBase82(const std::string& str, std::vector<unsigned char>& vchRet, int max_ret_len)
{
    if (!ContainsNoNUL(str)) {
        return false;
    }
    return DecodeBase82(str.c_str(), vchRet, max_ret_len);
}

std::string EncodeBase82Check(Span<const unsigned char> input)
{
    // add 4-byte hash check to the end
    std::vector<unsigned char> vch(input.begin(), input.end());
    uint256 hash = Hash(vch);
    vch.insert(vch.end(), (unsigned char*)&hash, (unsigned char*)&hash + 4);
    return EncodeBase82(vch);
}

[[nodiscard]] static bool DecodeBase82Check(const char* psz, std::vector<unsigned char>& vchRet, int max_ret_len)
{
    if (!DecodeBase82(psz, vchRet, max_ret_len > std::numeric_limits<int>::max() - 4 ? std::numeric_limits<int>::max() : max_ret_len + 4) ||
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

bool DecodeBase82Check(const std::string& str, std::vector<unsigned char>& vchRet, int max_ret)
{
    if (!ContainsNoNUL(str)) {
        return false;
    }
    return DecodeBase82Check(str.c_str(), vchRet, max_ret);
}
