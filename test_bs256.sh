###
 # @Descripttion : 
 # @Version      : 
 # @Autor        : one30: one30@m.scnu.edu.cn(email)
 # @Date         : 2021-04-24 16:52:13
 # @LastEditTime : 2021-04-24 21:26:32
 # @FilePath     : /test_bs256.sh
### 
export LD_LIBRARY_PATH=/home/one30/temp/openssl-1.1.1i
gcc -g -Iinclude -c main.c 
gcc -g main.o ./libcrypto.so -o a.out