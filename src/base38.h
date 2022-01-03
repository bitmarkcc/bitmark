// Copyright (c) 2009-2010 Satoshi Nakamoto
// Original Code: Copyright (c) 2009-2014 The Bitcoin Core Developers
// Modified Code: Copyright (c) 2014 Project Bitmark
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#ifndef BITMARK_BASE38_H
#define BITMARK_BASE38_H

#include "chainparams.h"
#include "key.h"
#include "script.h"

#include <string>
#include <vector>

bool IsBase38(const char* s);

/**
 * Encode a byte sequence as a base38-encoded string.
 * pbegin and pend cannot be NULL, unless both are.
 */
std::string EncodeBase38(const unsigned char* pbegin, const unsigned char* pend);

/**
 * Encode a byte vector as a base38-encoded string
 */
std::string EncodeBase38(const std::vector<unsigned char>& vch);

/**
 * Decode a base38-encoded string (psz) into a byte vector (vchRet).
 * return true if decoding is successful.
 * psz cannot be NULL.
 */
bool DecodeBase38(const char* psz, std::vector<unsigned char>& vchRet);

/**
 * Decode a base38-encoded string (str) into a byte vector (vchRet).
 * return true if decoding is successful.
 */
bool DecodeBase38(const std::string& str, std::vector<unsigned char>& vchRet);

/**
 * Base class for all base38-encoded data
 */
class CBase38Data
{
protected:
    // the version byte(s)
    std::vector<unsigned char> vchVersion;

    // the actually encoded data
    typedef std::vector<unsigned char, zero_after_free_allocator<unsigned char> > vector_uchar;
    vector_uchar vchData;

public:
    CBase38Data();
    void SetData(const std::vector<unsigned char> &vchVersionIn, const void* pdata, size_t nSize);
    void SetData(const std::vector<unsigned char> &vchVersionIn, const unsigned char *pbegin, const unsigned char *pend);
  void SetData(const void* pdata, size_t nSize);
    bool SetString(const char* psz, unsigned int nVersionBytes = 1);
    bool SetString(const std::string& str);
    std::string ToString() const;
    int CompareTo(const CBase38Data& b38) const;

    bool operator==(const CBase38Data& b38) const { return CompareTo(b38) == 0; }
    bool operator<=(const CBase38Data& b38) const { return CompareTo(b38) <= 0; }
    bool operator>=(const CBase38Data& b38) const { return CompareTo(b38) >= 0; }
    bool operator< (const CBase38Data& b38) const { return CompareTo(b38) <  0; }
    bool operator> (const CBase38Data& b38) const { return CompareTo(b38) >  0; }
};

#endif // BITMARK_BASE38_H
