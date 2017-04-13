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
	 int src_addr;
	 int dest_addr;
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


void rsa_encripta() {
	long i;
	C = 1;
	
	for(i=0;i< e;i++) 
	  C=C*M%n;
	C = C%n;
}

/*

CONTINUA...

*/