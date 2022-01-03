// Original Code: Copyright (c) 2014 The Bitcoin Core Developers
// Modified Code: Copyright (c) 2014 Project Bitmark
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base38.h"

#include "hash.h"
#include "uint256.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <vector>
#include <string>
#include <boost/variant/apply_visitor.hpp>
#include <boost/variant/static_visitor.hpp>

static const char* pszBase38 = "_0123456789abcdefghijklmnopqrstuvwxyz-";
static const char* pszBaseHex = "012345678abcdef";

/*bool IsHex (const char *s) {
  const char * s1 = s;
  while (*s1 != 0) {
    bool match = false;
    for (int j=0; j<16; j++) {
      if (*s1==pszBaseHex[j])
	match = true;
    }
    if (!match) {
      return false;
    }
    s1++;
  }
  return true;
  }*/

bool IsBase38 (const char *s) {
  const char * s1 = s;
  while (*s1 != 0) {
    bool match = false;
    for (int j=0; j<38; j++) {
      if (*s1==pszBase38[j])
	match = true;
    }
    if (!match) {
      printf("no match\n");
      return false;
    }
    s1++;
  }
  return true;
}

bool DecodeBase38(const char *psz, std::vector<unsigned char>& vch) {
    // Skip leading spaces.
    while (*psz && isspace(*psz))
        psz++;
    // Skip and count leading '_'s.
    int zeroes = 0;
    while (*psz == '_') {
        zeroes++;
        psz++;
    }
    // Allocate enough space in big-endian base256 representation.
    std::vector<unsigned char> b256(strlen(psz) * 657 / 1000 + 1); // log(38) / log(256), rounded up.
    // Process the characters.
    while (*psz && !isspace(*psz)) {
        // Decode base38 character
        const char *ch = strchr(pszBase38, *psz);
        if (ch == NULL) {
	  return false;
	}
        // Apply "b256 = b256 * 38 + ch".
        int carry = ch - pszBase38;
        for (std::vector<unsigned char>::reverse_iterator it = b256.rbegin(); it != b256.rend(); it++) {
            carry += 38 * (*it);
            *it = carry % 256;
            carry /= 256;
        }
        assert(carry == 0);
        psz++;
    }
    // Skip trailing spaces.
    while (isspace(*psz))
        psz++;
    if (*psz != 0) {
      return false;
    }
    // Skip leading zeroes in b256.
    std::vector<unsigned char>::iterator it = b256.begin();
    while (it != b256.end() && *it == 0)
        it++;
    // Copy result into output vector.
    vch.reserve(zeroes + (b256.end() - it));
    vch.assign(zeroes, 0x00);
    while (it != b256.end())
      vch.push_back(*(it++));
    return true;
}

std::string EncodeBase38(const unsigned char* pbegin, const unsigned char* pend) {
    // Skip & count leading zeroes.
    int zeroes = 0;
    while (pbegin != pend && *pbegin == 0) {
        pbegin++;
        zeroes++;
    }
    // Allocate enough space in big-endian base38 representation.
    std::vector<unsigned char> b38((pend - pbegin) * 153 / 100 + 1); // log(256) / log(38), rounded up.
    // Process the bytes.
    while (pbegin != pend) {
        int carry = *pbegin;
        // Apply "b38 = b38 * 256 + ch".
        for (std::vector<unsigned char>::reverse_iterator it = b38.rbegin(); it != b38.rend(); it++) {
            carry += 256 * (*it);
            *it = carry % 38;
            carry /= 38;
        }
        assert(carry == 0);
        pbegin++;
    }
    // Skip leading zeroes in base38 result.
    std::vector<unsigned char>::iterator it = b38.begin();
    while (it != b38.end() && *it == 0)
        it++;
    // Translate the result into a string.
    std::string str;
    str.reserve(zeroes + (b38.end() - it));
    str.assign(zeroes, '1');
    while (it != b38.end())
        str += pszBase38[*(it++)];
    return str;
}

std::string EncodeBase38(const std::vector<unsigned char>& vch) {
    return EncodeBase38(&vch[0], &vch[0] + vch.size());
}

bool DecodeBase38(const std::string& str, std::vector<unsigned char>& vchRet) {
    return DecodeBase38(str.c_str(), vchRet);
}

std::string EncodeBase38Check(const std::vector<unsigned char>& vchIn) {
    // add 4-byte hash check to the end
    std::vector<unsigned char> vch(vchIn);
    uint256 hash = Hash(vch.begin(), vch.end());
    vch.insert(vch.end(), (unsigned char*)&hash, (unsigned char*)&hash + 4);
    return EncodeBase38(vch);
}

bool DecodeBase38Check(const char* psz, std::vector<unsigned char>& vchRet) {
    if (!DecodeBase38(psz, vchRet) || (vchRet.size() < 4))
    {
        vchRet.clear();
        return false;
    }
    // re-calculate the checksum, insure it matches the included 4-byte checksum
    uint256 hash = Hash(vchRet.begin(), vchRet.end()-4);
    if (memcmp(&hash, &vchRet.end()[-4], 4) != 0)
    {
        vchRet.clear();
        return false;
    }
    vchRet.resize(vchRet.size()-4);
    return true;
}

bool DecodeBase38Check(const std::string& str, std::vector<unsigned char>& vchRet) {
    return DecodeBase38Check(str.c_str(), vchRet);
}

CBase38Data::CBase38Data() {
    vchVersion.clear();
    vchData.clear();
}

void CBase38Data::SetData(const std::vector<unsigned char> &vchVersionIn, const void* pdata, size_t nSize) {
    vchVersion = vchVersionIn;
    vchData.resize(nSize);
    if (!vchData.empty())
        memcpy(&vchData[0], pdata, nSize);
}

void CBase38Data::SetData(const std::vector<unsigned char> &vchVersionIn, const unsigned char *pbegin, const unsigned char *pend) {
    SetData(vchVersionIn, (void*)pbegin, pend - pbegin);
}

void CBase38Data::SetData(const void * pdata, size_t nSize) {
  vchData.resize(nSize);
  if (!vchData.empty())
    memcpy(&vchData[0],pdata,nSize);
}

bool CBase38Data::SetString(const char* psz, unsigned int nVersionBytes) {
    std::vector<unsigned char> vchTemp;
    bool rc38 = DecodeBase38Check(psz, vchTemp);
    if ((!rc38) || (vchTemp.size() < nVersionBytes)) {
        vchData.clear();
        vchVersion.clear();
        return false;
    }
    vchVersion.assign(vchTemp.begin(), vchTemp.begin() + nVersionBytes);
    vchData.resize(vchTemp.size() - nVersionBytes);
    if (!vchData.empty())
        memcpy(&vchData[0], &vchTemp[nVersionBytes], vchData.size());
    OPENSSL_cleanse(&vchTemp[0], vchData.size());
    return true;
}

bool CBase38Data::SetString(const std::string& str) {
    return SetString(str.c_str());
}

std::string CBase38Data::ToString() const {
    std::vector<unsigned char> vch = vchVersion;
    vch.insert(vch.end(), vchData.begin(), vchData.end());
    return EncodeBase38Check(vch);
}

int CBase38Data::CompareTo(const CBase38Data& b38) const {
    if (vchVersion < b38.vchVersion) return -1;
    if (vchVersion > b38.vchVersion) return  1;
    if (vchData < b38.vchData)   return -1;
    if (vchData > b38.vchData)   return  1;
    return 0;
}
