 
#include <stdio.h> 
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/aes.h>

char aes_key[16];  

const unsigned long long int p[4] = {1697841911,1438810907,666397859,941857673}; 

long long int powerLL(long long int x, long long int n,long long int p) 
{ 
    long long int result = 1; 
    while (n) { 
        if (n & 1) 
            result = result * x % p; 
        n = n / 2; 
        x = x * x % p; 
    } 
    return result; 
}

char* aes_encrypt(char input[]){
	unsigned char iv[AES_BLOCK_SIZE];
	memset(iv, 0x00, AES_BLOCK_SIZE);
	unsigned char* enc_out=(char*)malloc(64);
	AES_KEY enc_key;
	AES_set_encrypt_key(aes_key, sizeof(aes_key)*8, &enc_key);
	AES_cbc_encrypt(input, enc_out, 64, &enc_key, iv, AES_ENCRYPT);
	return enc_out;
}

char* aes_decrypt(char input[]){
	unsigned char iv[AES_BLOCK_SIZE];
	memset(iv, 0x00, AES_BLOCK_SIZE);
	unsigned char* dec_out=malloc(64);
	AES_KEY dec_key;
	AES_set_decrypt_key(aes_key, sizeof(aes_key)*8, &dec_key);
	AES_cbc_encrypt(input, dec_out, 64, &dec_key, iv, AES_DECRYPT);
	return dec_out;	
}

void print_data(const char *tittle, const void* data, int len)
{
	printf("%s : ",tittle);
	const unsigned char * p = (const unsigned char*)data;
	int i = 0;
	
	for (; i<len; ++i)
		printf("0x%02X ", *p++);
	
	printf("\n");
}

long long int powerStrings(char sa[],char sb[],long long int p) 
{   
  
    long long int a = 0, b = 0, l1 = 0, l2 = 0; 
    for(l1=0;sa[l1]!='\0';l1++);
    for(l2=0;sb[l2]!='\0';l2++);
    for (int i = 0; i < l1; i++) 
        a = (a * 10 + (sa[i] - '0')) % p; 
    for (int i = 0; i < l2; i++) 
        b = (b * 10 + (sb[i] - '0')) % (p - 1); 
  
    return powerLL(a, b, p); 
} 
  
int main() 
{
	setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	setvbuf(stderr,0,2,0);
	alarm(0x40);
    char g[]="13061880230110805485346525688018595113271880103717720219673350299083396780730251766148414377512386061643807530751287373200960399392170617293251618992497053",private[]="10422968608693307863137141214340891187788901792174011897414048377454264566167517670937738507527260002611513269618864761458078722737075348771608752113412231",input[]="darkCON{d1ff13_h3llm4n_1s_vuln3r";
    char* y[4];
    int key[4];
    for(int i=0;i<4;i++){
    	y[i]=(char*)malloc(64);
    }
    int x[4];
    printf("These are public values\n");
    for(int i=0;i<4;i++){
    	x[i]=powerStrings(g,private,p[i]);
    	printf("%d\n",x[i]);
    }
    printf("Enter the public values\n");
    for(int i=0;i<4;i++){
		scanf("%s",y[i]);
		getchar();
    }
    for(int i=0;i<4;i++){
    	key[i]=powerStrings(y[i],private,p[i]);
    	memcpy(aes_key+(i*4),key+(i),4);
    }
    char* enc=aes_encrypt(input);
    print_data("ENCRYPT ",enc,32);
    return 0;
}