reference from: https://www.zybuluo.com/one30/note/1790974
author:one30, one30@m.scnu.edu.cn(email)
# 将一个加密算法整合到OpenSSL库中
## 一、测试环境和参考
### 1、测试环境
OpenSSL version: 1.1.1i
gcc version: 10.1.0
系统：Ubuntu 18.04LTS
IDE: VS Code
添加算法：https://github.com/one30/Fast_SM4.git
### 2、参考
OpenSSL wiki:https://wiki.openssl.org/index.php/How_to_Integrate_a_Symmetric_Cipher#Create_the_Cipher
在OpenSSL源码中添加自定义加密算法：https://blog.csdn.net/bytxl/article/details/40143983
下载、编译、安装、使用、调试openssl最新版：https://cloud.tencent.com/developer/article/1468839
Linux环境下OpenSSL的调试debug方法：https://www.jianshu.com/p/7bd1e08452da?utm_campaign=haruki
测试方法：http://blog.chinaunix.net/uid-20637781-id-5828617.html

## 二、添加加密算法到OpenSSL库中
### 1.在objects.txt中注册算法OID
crypto/objects 目录下面维护整个OpenSSL模块化的重要的程序，下面逐个做出介绍:
objects.txt 按照一定的语法结构，定义了SN_base, LN_base, NID_base，OBJ_base。经过perl程序objects.pl通过命令perl objects.pl objects.txt obj_mac.num obj_mac.h 处理后，生成了obj_mac.num 和obj_mac.h两个文件。
obj_mac.num 用来查阅 OBJ_base与NID_base之间的对应关系。
obj_mac.h 用来提供c语言类型SN_base, LN_base, NID_base，OBJ_base定义。
objects.h 同样提供了c语言类型SN_base, LN_base,NID_base，OBJ_base定义，在obj_mac.h 更新之后，必须对对应的objects.h 中的内容作出同步，
及保持与obj_mac.h的定义一至，同时objects.h中也声明了一些对OBJ_name的操作函数。
objects.h 经过perl程序perl obj_dat.pl objects.h obj_dat.h处理之后，生成obj_dat.h头文件。

实际操作如下：
首先在crypto/objects/目录中objects.txt中添加一行条目，然后运行：
```
perl objects.pl objects.txt obj_mac.num obj_mac.h
```
然后执行./config && make
注：修改object中的oid后 perl命令生成不了对应文件 可以尝试make update

以下是我们添加的算法sm4_bs(bitsliceb版本sm4)，在objects.txt中添加几行条目：
```
sm-scheme 104 8         : SM4-BS256-ECB       : sm4-bs256-ecb
sm-scheme 104 9         : SM4-BS256-CTR       : sm4-bs256-ctr
sm-scheme 104 10        : SM4-BS256-GCM       : sm4-bs256-gcm
```

会生成以下声明：
crypto/objects/obj_dat.h:
```
{"SM4-BS256-ECB", "sm4-bs256-ecb", NID_sm4_bs256_ecb, 8, &so[7761]},
{"SM4-BS256-CTR", "sm4-bs256-ctr", NID_sm4_bs256_ctr, 8, &so[7769]},
{"SM4-BS256-GCM", "sm4-bs256-gcm", NID_sm4_bs256_gcm, 8, &so[7777]},
...
```

### 2.密码算法接口的定义
#### (1)sm4_bs.c
首先，在crypto/sm4/下添加sm4_bs.c
```
touch sm4_bs.c
```
sm4_bs.c中的接口函数按照以下规范：
```
void SM4_BS256_encrypt(const uint8_t *in, uint8_t *out, int size, const SM4_BS256_KEY *ks)
int SM4_BS256_set_key(const uint8_t *key, SM4_BS256_KEY *ks)
```
在crypto/sm4/build.info中加入sm4_bs.c;

其次，在include/crypto/下添加sm4_bs.h
```
touch sm4_bs.h
```
sm4_bs.h中编写声明和定义结构体等：
```
typedef struct SM4_BS256_KEY_st {
    uint32_t rk[SM4_BS256_KEY_SCHEDULE];
    __m256i bs_rk[SM4_BS256_KEY_SCHEDULE][32];
} SM4_BS256_KEY;
```
#### (2)e_sm4_bs.c
在crypto/evp/下添加e_sm4_bs.c
```
#include "internal/cryptlib.h"
#ifndef OPENSSL_NO_BS_SM4
# include <openssl/evp.h>
# include "crypto/sm4_bs.h"
#include "crypto/sm4.h"
# include "crypto/evp.h"
# include "evp_local.h"
# include "openssl/objects.h"

typedef struct {
    SM4_BS256_KEY ks;
} EVP_SM4_BS256_KEY;

static int sm4_bs256_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc)
{
    SM4_BS256_set_key(key, EVP_CIPHER_CTX_get_cipher_data(ctx));
    return 1;
}

static int sm4_ecb_bs_encrypt(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in,
            size_t len)
{

    if (ctx->encrypt)
        SM4_BS256_encrypt(in, out, len, &((EVP_SM4_BS256_KEY *)ctx->cipher_data)->ks);
    else
        SM4_BS256_encrypt(in, out, len, &((EVP_SM4_BS256_KEY *)ctx->cipher_data)->ks);
    return 1;
}



static const EVP_CIPHER sm4_bs256_cipher = {
    NID_sm4_bs256_ecb, 1, 16, 16,
    EVP_CIPH_ECB_MODE,
    sm4_bs256_init_key,
    sm4_ecb_bs_encrypt, //sm4_ecb_bs_encrypt,
    NULL,
    sizeof(EVP_SM4_BS256_KEY),
    NULL, NULL, NULL, NULL
};

const EVP_CIPHER *EVP_sm4_bs256_ecb(void)
{
    return &sm4_bs256_cipher;
}
#endif
```
接下来在include/openssl/evp.h中添加算法声明：
```
# ifndef OPENSSL_NO_BS_SM4
const EVP_CIPHER *EVP_sm4_bs256_ecb(void);
const EVP_CIPHER *EVP_sm4_bs256_ctr(void);
const EVP_CIPHER *EVP_sm4_bs256_gcm(void);
# endif
```
#### (3)c_allc.c
最后在crypto/evp/c_allc.c中修改openssl_add_all_ciphers_int函数，使用Evp_add_cipher注册加密函数：
```
#ifndef OPENSSL_NO_BS_SM4
    EVP_add_cipher(EVP_sm4_bs256_ecb());
    EVP_add_cipher(EVP_sm4_bs256_ctr());
    EVP_add_cipher(EVP_sm4_bs256_gcm());
#endif
```
至此就可以使用此加密算法了。

### 3.编译、安装、测试及调试
#### (1)编译：
```
./config -d --prefix=$安装目录$
make -j4
```
添加-d参数方便调试，安装目录表示链接库安装的位置，可放在当前目录下方便调试。
#### (2)安装：
```
sudo make install
```
安装的库会在(1)中的安装目录下。
#### (3)测试及调试
在根目录下添加main.c以测试sm4_bs256_ecb函数是否正确运行：
```
void main()
{
    int have_sm4 = (OPENSSL_VERSION_NUMBER >= 0x10101001L);
    int have_aes = 1;
    int have_sm4_bs256 = 1;
    const unsigned char data[]=
    {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    unsigned char ivec[EVP_MAX_IV_LENGTH]; ///< IV 向量
    const unsigned char key1[16] = ///< key_data, 密钥内容, 至少16字节
    {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };

    test_case_t tc;
    tc.in_data = data;
    tc.in_data_len = sizeof(data);
    tc.in_data_is_already_padded = (tc.in_data_len % 16)==0; // Hard coded 16 as the cipher's block size
    tc.in_key = key1;
    tc.in_key_len = sizeof(key1);
    memset(ivec, 0x00, EVP_MAX_IV_LENGTH);
    tc.in_ivec = ivec;

#if defined(OPENSSL_NO_BS_SM4)
    have_sm4_bs256 = 0;
#endif
    if (have_sm4_bs256)
    {
        printf("[2]\n");
        printf("Debug: EVP_sm4_bs256_ecb() test\n");
        test_encrypt_with_cipher(&tc, EVP_sm4_bs256_ecb());
    }
}
```
编译及执行测试代码：
```
gcc -Iinclude -c main.c
gcc main.o libcrypto.so -o a.out
	
export LD_LIBRARY_PATH=`pwd`
ldd a.out
	
./a.out
```
执行a.out程序能够输出测试结果：
```
Debug: out_len=16
Debug: out_padding_len=0
68 1e df 34 d2 06 96 5e 86 b3 e9 4f 53 6e 42 46 
```
调试：
使用vscode和gdb调试(也可单独使用gdb调试),设置好参数和链接正确的动态库后可进入库文件函数调试！
```
launch.jason：
{
 https://go.microsoft.com/fwlink/?linkid=830387
    "version": "0.2.0",
    "configurations": [
        {
            "name": "gcc-10 - 生成和调试活动文件",
            "type": "cppdbg",
            "request": "launch",
            "program": "${workspaceFolder}/a.out",
            "args": [],
            "stopAtEntry": false,
            "cwd": "${workspaceFolder}",
            "environment": [],
            "externalConsole": false,
            "justMyCode": false,
            "MIMode": "gdb",
            "setupCommands": [
                {
                    "description": "为 gdb 启用整齐打印",
                    "text": "-enable-pretty-printing",
                    "ignoreFailures": true
                }
            ],
            "preLaunchTask": "build",
            "miDebuggerPath": "/usr/bin/gdb"
        }
    ]
}
tasks.json:
{
    "tasks": [
        
        {
            // 增量编译 
            "type": "shell",
            "label": "build",
            "command": 
            "export LD_LIBRARY_PATH=/home/one30/temp/openssl-1.1.1i;
            gcc -g -Iinclude -c main.c; 
            gcc -g main.o ./libcrypto.so -o a.out",
            "group": {
                "kind": "build",
                "isDefault": true
            }, 
        }
    ],
    "version": "2.0.0"
 }
```
compile:
export LD_LIBRARY_PATH=/home/one30/temp/openssl-1.1.1i
gcc -g -Iinclude -c test_bs-sm4.c 
gcc -g test_bs-sm4.o ./libcrypto.so -o test_bs-sm4
run:

