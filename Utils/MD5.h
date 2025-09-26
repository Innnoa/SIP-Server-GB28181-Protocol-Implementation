#ifndef MD5_H
#define MD5_H

/* 原有内容保持不变 */
typedef unsigned char* POINTER;
typedef unsigned short int UINT2;
typedef unsigned long int UINT4;

typedef struct {
    UINT4 state[4];
    UINT4 count[2];
    unsigned char buffer[64];
} MD5_CTX;

void MD5Init(MD5_CTX*);
void MD5Update(MD5_CTX*, unsigned char*, unsigned int);
void MD5Final(unsigned char [16], MD5_CTX*);

/* 添加 MD5Hash 声明 */
void MD5Hash(const char* input, unsigned int length, unsigned char* output);

#endif
