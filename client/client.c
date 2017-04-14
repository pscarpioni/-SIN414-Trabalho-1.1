
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <math.h>
#include <fcntl.h>
#include <unistd.h>
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
#define MAX_LEN 1024
#define SUCCESS 1
#define FAIL 0


#define SERVER_PADRAO "192.168.1.241"

#define REQUEST 20  /* Mensagem de Requisição */
#define RESPONSE 30  /* Mensagem de Resposta */
#define PUBKEY 10 /* Chave Pública RSA para envio */


/* Estrutura da Mensagem */
typedef struct {
	 int opcode;
	 int endereco_origem;
	 int endereco_destino;
 } Header;

/* REQUEST message */
typedef struct {
	 Header hdr;
	 int x;
	 int y;
	 int check1;
	 int check2;
	 char filename[50];
	 int flag_desconecta;
} ReqMsg;

/* RESPONSE message */
typedef struct {
	 Header hdr;
	 long texto_cifrado;
	 int reqcom;
	 unsigned char hash[SHA_DIGEST_LENGTH];
	 int status;
	 int flag_desconecta;
} RepMsg;


/* Chave Pública RSA */
typedef struct {
	Header hdr;
	long e; /* Expoente de Encriptação */
	long n; /* Módulo */
} PublicKey;


/* Estrutura para uma mensagem em geral */
typedef struct {
	Header hdr; /* Cabeçalho de uma mensagem */
} Msg;

/* Assinatura das Funções */
int conectaServidor (char *);
void comunicaServidor (int);


/* RSA*/

typedef struct keys keys;
struct keys{
  long chavepublica_e;
  long chaveprivada_d;
  long chave_n;
};

keys* get_chaves_RSA;
long phi,M,n,e,d,C,FLAG;


int check() {
	FLAG = 0;
	return FLAG;
}


void encripta() {
	long i;
	C = 1;
	for(i = 0; i < e; i++)
	  C = C * M % n;
	C = C % n;
}

void decripta() {
	long i;
	M = 1;
	for(i = 0; i < d; i++)
	M = M * C % n;
	M = M % n;
}



/* Gera um número primo aleatório */
int ehPrimo(unsigned long numero) {
  
  if(numero % 3 == 0) {
	  return n==3;
  }
  
  unsigned long primo = 5;
  while (primo * primo <= numero) {
    if (numero % primo == 0) return 0;
    primo += 2;
    if (numero % primo == 0) return 0;
    primo += 4;
  }
  return 1;
}

unsigned long randomPrimo(int menor, int maior) {
  unsigned long dispersao = maior - menor + 1;
  while(1) {
    unsigned long primo = 1 | (rand() % dispersao + menor);
    if (ehPrimo(primo)) return primo;
  }
}


keys* principalRSA() {
	int p,q,s;
	keys *retornaChave = (keys*)malloc(sizeof(keys));

	p = randomPrimo(50,500);
	q = randomPrimo(501,850);

	n = p * q;
	phi = (p-1) * (q-1);
	
	do {
		e = randomPrimo(phi/2,phi);
	}while(FLAG==1);
	
	d = 1;
	
	do {
		s = (d * e) % phi;
		d++;
	}while(s!=1);
	
	d = d-1;
	
	retornaChave->chavepublica_e = e;
	retornaChave->chaveprivada_d = d;
	retornaChave->chave_n = n;
	return retornaChave;
	
}



/* Conecta com o Servidor: socket() e connect() */
int conectaServidor ( char *clienteCnt ) {
   int connectServer;
   struct sockaddr_in servidorAddress;   /* Endereço do Servidor */
   int status;

   /* Requisita um socket descriptor */
   connectServer = socket (AF_INET, SOCK_STREAM, 0);
   if (connectServer == -1) {
      fprintf (stderr, "*** Erro no Cliente: impossível obter o socket descriptor\n");
      exit(1);
   }

   /* Define o endereço do Servidor */
   servidorAddress.sin_family = AF_INET;
   servidorAddress.sin_port = htons(PORTA_SERVICO);
   servidorAddress.sin_addr.s_addr = inet_addr(clienteCnt);
   bzero(&(servidorAddress.sin_zero),8);

   /* Configura a conexão com o Servidor */
   status = connect(connectServer, (struct sockaddr *)&servidorAddress, sizeof(struct sockaddr));
   if (status == -1) {
      fprintf(stderr, "*** Erro no Cliente: não conseguiu conexão com o Servidor!!!\n");
      exit(1);
   }

   fprintf(stderr, "Conectado com o Servidor\n");

   return connectServer;
}


/* Interação com o Servidor */
void comunicaServidor (int connectServer) {

   int numBytes, status, flag=1;
   int endereco_origem, endereco_destino;
   FILE *fp = NULL;
   ReqMsg envia_msg;
   RepMsg receive_msg;
   PublicKey chave_publica_envia;
   char caractere = ' ';
   endereco_destino = inet_addr("SERVER_PADRAO");
   endereco_origem = inet_addr("192.168.1.245");

   /* send the request message REQUEST to the server */
   printf("Enviando Chave Pública para o Servidor\n");  

   chave_publica_envia.hdr.opcode = PUBKEY;
   chave_publica_envia.hdr.endereco_origem = endereco_origem;
   chave_publica_envia.hdr.endereco_destino = endereco_destino;
   chave_publica_envia.e = get_chaves_RSA->chavepublica_e;
   chave_publica_envia.n = get_chaves_RSA->chave_n;

   
   status = send(connectServer, &chave_publica_envia, sizeof(PublicKey), 0);
   if (status == -1) {
      fprintf(stderr, "*** Erro no Servidor: impossível de efetuar o envio!\n");
      return;
    }

    printf("Digite o nome do arquivo que se quer do Servidor: ");
    scanf(" %s", envia_msg.filename);
    envia_msg.flag_desconecta = 0;
    printf("Arquivo: %s enviado!\n",envia_msg.filename);
    status = send(connectServer, &envia_msg, sizeof(ReqMsg), 0);
    if (status == -1) {
      fprintf(stderr, "*** Erro no Servidor: impossível de efetuar o envio!\n");
      return;
    }
    printf("Recebido:\t\tDecriptado:\tHash Calculada:\tRecebido: \tStatus:\n");
      while (flag) {
       numBytes = recv(connectServer, &receive_msg, sizeof(RepMsg), 0);
       if (numBytes == -1) {
          fprintf(stderr, "*** Erro no Cliente: não foi possível receber a solicitação\n");
          
       }
       switch ( receive_msg.hdr.opcode) {
        case RESPONSE:
                  
                  if(receive_msg.reqcom==0){
                    n = get_chaves_RSA->chave_n;
                    C=receive_msg.texto_cifrado;
                    d = get_chaves_RSA->chaveprivada_d;

                    if (flag) {

                      decripta();
                      
                      unsigned char thishash[SHA_DIGEST_LENGTH];
                      char text[2];
                      int i=0;
                        text[0] = M;
                        text[1] = '\0';
                        size_t length = sizeof(text);
                        SHA1((const unsigned char*)text, length, thishash);
                      
                        if(M>=1 && M<=25)
                            M += 64;
                        else if(M==0) 	//espaçamento
                          M=32;
                        else if(M>=26 && M<=51)		// de 'a' até 'z'
                            M += 71;
                        else if(M>=52 && M<=60)
                            M -= 4;
                        else if(M==61)		//vírgula(,)
                            M = 44;
                        else if(M==62)		//ponto final(.)
                            M = 46;
                        else if(M==63)		//exclamação(!)
                            M = 33;
                      printf("%li\t\t\t%c\t\t\t",C,(int)M);
                      i=0;
                      // for(i=0; i<1; i++){
                        if(thishash[i]!=receive_msg.hash[i]){
                          printf("Hash não coincidiu! Desconectando!!!!\n");
                          receive_msg.reqcom=3;
                          break;
                        }
                        else if(thishash[i]==receive_msg.hash[i])
                          printf("%d\t\t%d\t\t",thishash[i],receive_msg.hash[i]);
                          printf("Hash coincidiu!\n");
                      // }
                      
                      caractere = M;

                        char buffer[2] = {caractere, '\0'};

                       fp = fopen(envia_msg.filename, "a");
                       if(caractere>=0  && (caractere==9 || (caractere>31 && caractere<127) ))
                        fprintf(fp,"%s", buffer);
                       fclose(fp);
                    }
                  }
                  
                  else if(receive_msg.reqcom==1 || receive_msg.reqcom==3){
                      if(receive_msg.reqcom==1){
                      printf("Arquivo recebido!\nRequisição para desconexão enviada!\n");
                      envia_msg.flag_desconecta = 1;

                      status = send(connectServer, &envia_msg, sizeof(ReqMsg), 0);
                       if (status == -1) {
                          fprintf(stderr, "*** Erro no Servidor: impossível de efetuar o envio\n");
                          return;
                        }

                        numBytes = recv(connectServer, &receive_msg, sizeof(RepMsg), 0);
                         if (numBytes == -1) {
                            fprintf(stderr, "*** Erro no Cliente: não foi possível receber informação\n");
                            
                         }
                        if(receive_msg.flag_desconecta==1)
                          printf("Desconexão completa!\n");   
                      }

                      flag=0;
                  }

                  else if(receive_msg.reqcom==2){
                    printf("O arquivo não existe!\nDesconexão completa!\n");
                    flag=0;
                  }

                  break;
       default: 

               flag =0;
               break;  
       }
     }//end of while
}

int main ( int argc, char *argv[] )
{
   char clienteCnt[16];
   int connectServer;
   

   printf("******* Cliente iniciou a conexão ***** \n\n");
   
   get_chaves_RSA = principalRSA();

   strcpy(clienteCnt, (argc == 2) ? argv[1] : SERVER_PADRAO);
   connectServer = conectaServidor(clienteCnt);
   comunicaServidor (connectServer);
   close(connectServer);
   return 0;
}

