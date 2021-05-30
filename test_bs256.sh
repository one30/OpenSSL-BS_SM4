###
 # @Descripttion : 
 # @Version      : 
 # @Autor        : one30: one30@m.scnu.edu.cn(email)
 # @Date         : 2021-04-24 16:52:13
 # @LastEditTime : 2021-05-14 10:09:20
 # @FilePath     : /test_bs256.sh
### 
export LD_LIBRARY_PATH=/home/ubuntu/test/openssl-1.1.1i
gcc -g -Iinclude -c test_bs-sm4.c 
gcc -g test_bs-sm4.o ./libcrypto.so -o test_bs-sm4