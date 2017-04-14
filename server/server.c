
#include <stdio.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>


#define PORTA_SERVICO 41089
#define TAM_MAX 20
#define TAM_Q 5

#define SUCCESS 1
#define FAIL 0


#define SERVIDOR_PADRAO "192.168.1.241"

#define REQUEST 20  /* Mensagem de Request */
#define RESPONSE 30  /* Mensagem de Resposta */
#define PUBKEY 10 /* Chave pública RSA para envio */

/* Essa struct define a estrutura da mensagem */
typedef struct {
	 int opcode;
	 int endereco_origem;
	 int endereco_destino;
 } Hdr;

/* Mensagem de Requisição */
typedef struct {
	 Hdr hdr;
	 int x;
	 int y;
	 int check1; 
	 int check2;
	 char nome_arquivo[50];
	 int desconecta_flag;
} REQUESTMsg;

/* Mensagem de Resposta */
typedef struct {
	 Hdr hdr;
	 long ciphertext;
	 int REQUESTcom;
	 unsigned char hash[SHA_DIGEST_LENGTH];
	 int status;
	 int desconecta_flag;
} RESPONSEMsg;

/* Chave pública RSA */
typedef struct {
	Hdr hdr;
	long e; /* Expoente de encriptação */
	long n; /* Módulo */
} PubKey;

/*Mensagem */
typedef struct {
	Hdr hdr; /* Cabeçalho de uma mensagem */
} Msg;



/* Assinatura das Fuñções */
int iniciaServidor ( );
void comunicaCliente (int);
void aceitaConexao (int);



/* Struct para o RSA */
typedef struct keys keys;
struct keys{
  long chave_publica;
  long chave_privada;
  long key_n;
};

long phi,M,n,e,d,C,FLAG;


int check() {
	FLAG = 0;
	return FLAG;
}


/* Função que realiza a encriptação RSA do arquivo */
void rsa_encripta() {
	long i;
	C = 1;
	
	for(i=0;i< e;i++) 
	  C=C*M%n;
	C = C%n;
}



/* Função que efetua a decriptação RSA */ 
void decrypt() {
	long i;
	M = 1;
	for(i=0;i< d;i++)
	M=M*C%n;
	M = M%n;
}


/* Função que gera um número primo randomicamente */
int ehPrimo(unsigned long numero) {
  
  	if(numero % 3 == 0) {
  		return numero == 3;
  	}
  
  	unsigned long primo = 5;
  
  	while (primo * primo <= numero) {
    	if (numero % primo == 0) {
    		return 0;
    	}
    
    	primo += 2;

    	if (numero % primo == 0) {
    		return 0;
    	}
    
    	p += 4;
  	}

  	return 1;
}


unsigned long randomPrimo(int menor, int maior) {
  
  unsigned long dispersao = maior - menor + 1;
  
  while(1) {
    
    unsigned long p = 1 | (rand() % dispersao + menor);
    
    if (ehPrimo(p)) 
    	return p;
  
  }
}

/* Gera as Chaves Pública e Privada */

keys* principalRSA() {
	int p,q,s;
	FILE *escreve_chaves;
	char nome_arquivo[] = "chaves.txt"
	keys *retorna_chave = (keys*)malloc(sizeof(keys));
	

	p = randomPrimo(50,5000);
	q = randomPrimo(501,8500);

	n = p * q;
	phi = (p-1)*(q-1);

	escreve_chaves = fopen(nome_arquivo, "a+");

	fprintf(escreve_chaves, "\n\tF(n) valor de phi \t= %li", phi);

	do {
		e = randomPrimo(phi/2,phi);
	} while(FLAG==1);

	d = 1;

	do {
		s = ( d * e) % phi;
		d++;
	} while(s != 1);
	
	d = d-1;
	fprintf(escreve_chaves, "\n\tChave Pública\t: {%lli,%lli}", e,n);
	fprintf(escreve_chaves, "\n\tChave Privada\t: {%lli,%lli}", d,n);

	retorna_chave->chave_publica = e;
	retorna_chave->chave_privada = d;
	retorna_chave->key_n = n;

	fclose(escreve_chaves);

	return retorna_chave;
}