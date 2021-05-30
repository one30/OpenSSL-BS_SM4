###
 # @Descripttion : 
 # @Version      : 
 # @Autor        : one30: one30@m.scnu.edu.cn(email)
 # @Date         : 2021-05-13 09:18:51
 # @LastEditTime : 2021-05-27 15:50:56
 # @FilePath     : /test_bench.sh
### 
export LD_LIBRARY_PATH=/home/ubuntu/test/openssl-1.1.1i
./out/bin/openssl speed -evp sm4-ecb > testbench_core1_result.txt
./out/bin/openssl speed -evp sm4-ctr >> testbench_core1_result.txt
./out/bin/openssl speed -evp sm4-gcm >> testbench_core1_result.txt
./out/bin/openssl speed -evp sm4-bs256-ecb >> testbench_core1_result.txt
./out/bin/openssl speed -evp sm4-bs256-ctr >> testbench_core1_result.txt
./out/bin/openssl speed -evp sm4-bs256-gcm >> testbench_core1_result.txt
./out/bin/openssl speed -evp sm4-bs512-ecb >> testbench_core1_result.txt
./out/bin/openssl speed -evp sm4-bs512-ctr >> testbench_core1_result.txt
./out/bin/openssl speed -evp sm4-bs512-gcm >> testbench_core1_result.txt

./out/bin/openssl speed -evp sm4-ecb -multi 8 > testbench_core8_result.txt
./out/bin/openssl speed -evp sm4-ctr -multi 8 >> testbench_core8_result.txt
./out/bin/openssl speed -evp sm4-gcm -multi 8 >> testbench_core8_result.txt
./out/bin/openssl speed -evp sm4-bs256-ecb -multi 8 >> testbench_core8_result.txt
./out/bin/openssl speed -evp sm4-bs256-ctr -multi 8 >> testbench_core8_result.txt
./out/bin/openssl speed -evp sm4-bs256-gcm -multi 8 >> testbench_core8_result.txt
./out/bin/openssl speed -evp sm4-bs512-ecb -multi 8 >> testbench_core8_result.txt
./out/bin/openssl speed -evp sm4-bs512-ctr -multi 8 >> testbench_core8_result.txt
./out/bin/openssl speed -evp sm4-bs512-gcm -multi 8 >> testbench_core8_result.txt

./out/bin/openssl speed -evp sm4-ecb -multi 16 > testbench_core16_result.txt
./out/bin/openssl speed -evp sm4-ctr -multi 16 >> testbench_core16_result.txt
./out/bin/openssl speed -evp sm4-gcm -multi 16 >> testbench_core16_result.txt
./out/bin/openssl speed -evp sm4-bs256-ecb -multi 16 >> testbench_core16_result.txt
./out/bin/openssl speed -evp sm4-bs256-ctr -multi 16 >> testbench_core16_result.txt
./out/bin/openssl speed -evp sm4-bs256-gcm -multi 16 >> testbench_core16_result.txt
./out/bin/openssl speed -evp sm4-bs512-ecb -multi 16 >> testbench_core16_result.txt
./out/bin/openssl speed -evp sm4-bs512-ctr -multi 16 >> testbench_core16_result.txt
./out/bin/openssl speed -evp sm4-bs512-gcm -multi 16 >> testbench_core16_result.txt



