#include "HTTPDigest.h"
#include <string.h>
#include <stdio.h>
#include "MD5.h"  // 使用自定义 MD5

void CvtHex(const HASH Bin, HASHHEX Hex) {
    // 添加 const
    unsigned short i;
    unsigned char j;

    for (i = 0; i < HASHLEN; i++) {
        j = (Bin[i] >> 4) & 0xf;
        if (j <= 9)
            Hex[i * 2] = (j + '0');
        else
            Hex[i * 2] = (j + 'a' - 10);

        j = Bin[i] & 0xf;
        if (j <= 9)
            Hex[i * 2 + 1] = (j + '0');
        else
            Hex[i * 2 + 1] = (j + 'a' - 10);
    };
    Hex[HASHHEXLEN] = '\0';
}

/* calculate H(A1) as per spec */
void DigestCalcHA1(
    const char* pszAlg,
    char* pszUserName,
    char* pszRealm,
    char* pszPassword,
    char* pszNonce,
    char* pszCNonce,
    HASHHEX HA1
) {
    HASH HA1Bin;
    char pszHA1[256];

    snprintf(pszHA1, sizeof(pszHA1), "%s:%s:%s",
             pszUserName ? pszUserName : "",
             pszRealm ? pszRealm : "",
             pszPassword ? pszPassword : "");

    MD5Hash(pszHA1, strlen(pszHA1), HA1Bin);

    if (pszAlg && strcasecmp(pszAlg, "md5-sess") == 0) {
        char pszHA1Sess[512];
        HASHHEX HA1Hex;

        CvtHex(HA1Bin, HA1Hex);
        snprintf(pszHA1Sess, sizeof(pszHA1Sess), "%s:%s:%s",
                 HA1Hex,
                 pszNonce ? pszNonce : "",
                 pszCNonce ? pszCNonce : "");
        MD5Hash(pszHA1Sess, strlen(pszHA1Sess), HA1Bin);
    }

    CvtHex(HA1Bin, HA1);
}

/* calculate request-digest/response-digest as per HTTP Digest spec */
void DigestCalcResponse(
    HASHHEX HA1,
    char* pszNonce,
    char* pszNonceCount,
    char* pszCNonce,
    char* pszQop,
    int Reponse,
    char* pszMethod,
    char* pszDigestUri,
    HASHHEX HEntity,
    HASHHEX Response
) {
    HASH HA2Bin;
    HASHHEX HA2 = "";
    HASH RespHashBin;
    char pszHA2[256];
    char pszResponse[512];

    // calculate H(A2)
    if (pszQop && strcasecmp(pszQop, "auth-int") == 0) {
        snprintf(pszHA2, sizeof(pszHA2), "%s:%s:%s",
                 pszMethod ? pszMethod : "",
                 pszDigestUri ? pszDigestUri : "",
                 HEntity ? HEntity : "");
    }
    else {
        snprintf(pszHA2, sizeof(pszHA2), "%s:%s",
                 pszMethod ? pszMethod : "",
                 pszDigestUri ? pszDigestUri : "");
    }

    MD5Hash(pszHA2, strlen(pszHA2), HA2Bin);
    CvtHex(HA2Bin, HA2);

    // calculate response
    if (pszQop && (strcasecmp(pszQop, "auth") == 0 || strcasecmp(pszQop, "auth-int") == 0)) {
        snprintf(pszResponse, sizeof(pszResponse), "%s:%s:%s:%s:%s:%s",
                 HA1,
                 pszNonce ? pszNonce : "",
                 pszNonceCount ? pszNonceCount : "",
                 pszCNonce ? pszCNonce : "",
                 pszQop,
                 HA2);
    }
    else {
        snprintf(pszResponse, sizeof(pszResponse), "%s:%s:%s",
                 HA1,
                 pszNonce ? pszNonce : "",
                 HA2);
    }

    MD5Hash(pszResponse, strlen(pszResponse), RespHashBin);
    CvtHex(RespHashBin, Response);
}
