// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BASE82_H
#define BITCOIN_BASE82_H

#include <span.h>

#include <string>
#include <vector>

bool IsBase82(const std::string str);

/**
 * Encode a byte span as a base82-encoded string
 */
std::string EncodeBase82(Span<const unsigned char> input);

/**
 * Decode a base82-encoded string (str) into a byte vector (vchRet).
 * return true if decoding is successful.
 */
[[nodiscard]] bool DecodeBase82(const std::string& str, std::vector<unsigned char>& vchRet, int max_ret_len);

/**
 * Encode a byte span into a base82-encoded string, including checksum
 */
std::string EncodeBase82Check(Span<const unsigned char> input);

/**
 * Decode a base82-encoded string (str) that includes a checksum into a byte
 * vector (vchRet), return true if decoding is successful
 */
[[nodiscard]] bool DecodeBase82Check(const std::string& str, std::vector<unsigned char>& vchRet, int max_ret_len);

#endif // BITCOIN_BASE82_H
