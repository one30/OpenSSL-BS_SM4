/*
 * @Descripttion : 
 * @Version      : 
 * @Autor        : one30: one30@m.scnu.edu.cn(email)
 * @Date         : 2021-04-18 11:40:09
 * @LastEditTime : 2021-04-18 11:41:30
 * @FilePath     : /md5.c
 */
#include<stdio.h>
#include"include/openssl/md5.h"
#include<string.h>

int main( int argc, char **argv )
{
MD5_CTX ctx;
unsigned char *data="123";
unsigned char md[16];
char buf[33]={'\0'};
char tmp[3]={'\0'};
int i;

MD5_Init(&ctx);
MD5_Update(&ctx,data,strlen(data));
MD5_Final(md,&ctx);

for( i=0; i<16; i++ ){
sprintf(tmp,"%02X",md[i]);
strcat(buf,tmp);
}
printf("%s\n",buf);
return 0;
}