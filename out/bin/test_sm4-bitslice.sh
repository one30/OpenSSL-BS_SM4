###
 # @Descripttion : 
 # @Version      : 
 # @Autor        : one30: one30@m.scnu.edu.cn(email)
 # @Date         : 2021-05-07 21:17:27
 # @LastEditTime : 2021-05-07 21:33:51
 # @FilePath     : /out/bin/test_sm4-bitslice.sh
### 
export LD_LIBRARY_PATH=/home/one30/temp/openssl-1.1.1i
./openssl speed -evp sm4-ecb > test_result.txt
./openssl speed -evp sm4-ctr >> test_result.txt
./openssl speed -evp sm4-gcm >> test_result.txt
./openssl speed -evp sm4-bs256-ecb >> test_result.txt
./openssl speed -evp sm4-bs256-ctr >> test_result.txt
./openssl speed -evp sm4-bs256-gcm >> test_result.txt