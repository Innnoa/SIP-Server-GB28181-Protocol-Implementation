#ifndef UTILS_HTTPDIGEST_H
#define UTILS_HTTPDIGEST_H

#ifdef __cplusplus
extern "C" {
#endif

#define HASHLEN 16
#define HASHHEXLEN 32

typedef unsigned char HASH[HASHLEN]; // 改为 unsigned char
typedef char HASHHEX[HASHHEXLEN + 1];

/**
 * 计算MD5哈希值
 * @param input 输入数据
 * @param length 数据长度
 * @param output 输出哈希值
 */
void MD5Hash(const char* input, unsigned int length, unsigned char* output);

/**
 * 将二进制哈希转换为十六进制字符串
 * @param Bin 二进制哈希
 * @param Hex 输出十六进制字符串
 */
void CvtHex(const HASH Bin, HASHHEX Hex);

/**
 * 计算HA1值
 * @param pszAlg 算法类型
 * @param pszUserName 用户名
 * @param pszRealm 域
 * @param pszPassword 密码
 * @param pszNonce 随机数
 * @param pszCNonce 客户端随机数
 * @param HA1 输出HA1值
 */
void DigestCalcHA1(
    const char* pszAlg,
    char* pszUserName,
    char* pszRealm,
    char* pszPassword,
    char* pszNonce,
    char* pszCNonce,
    HASHHEX HA1
);

/**
 * 计算MD5哈希值
 * @param HA1 H(A1)
 * @param pszNonce 随机数
 * @param pszNonceCount 8位十六进制
 * @param pszCNonce 客户端随机数
 * @param pszQop 保护质量
 * @param Reponse 是否为401响应
 * @param pszMethod HTTP方法
 * @param pszDigestUri 摘要URI
 * @param HEntity 实体哈希
 * @param Response 输出响应
 */
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
);

#ifdef __cplusplus
}
#endif

#endif /* UTILS_HTTPDIGEST_H */
