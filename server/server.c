
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
    
    	primo += 4;
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
	char nome_arquivo[] = "chaves.txt";
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




/* Inicia o Servidor */
int iniciaServidor ()
{
   int init_server;
   struct sockaddr_in endereco_server;   /* endereço do servidor */
   int status;


   /* Requisição (RESQUEST)  de um socket descriptor */
   init_server = socket(AF_INET, SOCK_STREAM, 0);
   if (init_server == -1) {
      fprintf(stderr, "*** ERRO no Servidor!!! Impossível obter um socket descriptor\n");
      exit(1);
   }

   /* Define os atributos da estrutura de endereços de Internet do Servidor */
   endereco_server.sin_family = AF_INET;            /* Valor padrão para a maioria das aplicações */
   endereco_server.sin_port = htons(PORTA_SERVICO);  
   endereco_server.sin_addr.s_addr = INADDR_ANY;    
   bzero(&(endereco_server.sin_zero),8);

   /* Liga o socket na porta definida para ficar a espera de requisições */
   status = bind(init_server, (struct sockaddr *)&endereco_server, sizeof(struct sockaddr));
   if (status == -1) {
      fprintf(stderr, "*** Erro no servidor: impossível de se iniciar na porta %d\n", PORTA_SERVICO);
      exit(2);
   }

   /* Espera por conexões na porta definida */
   status = listen(init_server,TAM_Q);
   if (status == -1) {
      fprintf(stderr, "*** Erro no servidor: Não é possível esperar por conexões\n");
      exit(3);
   }

   fprintf(stderr, "+++ Servidor iniciado com sucesso!!! Esperando na porta: %hd\n", PORTA_SERVICO);
   return init_server;
}


/* Aceita conexões de clientes e gera um processo filho para cada REQUEST */
void aceitaConexao(int init_server) {
   int comunicacao_cliente;
   struct sockaddr_in endereco_cliente;
   socklen_t tamanho;


    while (1) {
      /* Aceita a conexão de Clientes */
      comunicacao_cliente = accept(init_server, (struct sockaddr *)&endereco_cliente, &tamanho);
      if (comunicacao_cliente == -1) {
         fprintf(stderr, "*** Erro no Servidor: impossível aceitar o REQUEST\n");
         continue;
      }
     
      /* Separa (realiza um fork) um processo filho para processar os REQUESTs */
      if (!fork()) {                         //--------------
         comunicaCliente (comunicacao_cliente);
         fprintf(stderr, "**** Conexão encerrada com o Cliente!\n");
         close(comunicacao_cliente);
         exit(0);
      }

 
      close(comunicacao_cliente);

      while (waitpid(-1,NULL,WNOHANG) > 0);
   }
}


/* Interação do processo filho com o cliente */
void comunicaCliente ( int comunicacao_cliente )
{
   int status;
   int num_bytes;
   int endereco_origem, endereco_destino, printflag=0;

   RESPONSEMsg send_msg;
   REQUESTMsg recv_msg;
   PubKey public_key_got;

   endereco_destino = inet_addr("192.168.1.245");
   endereco_origem = inet_addr("SERVIDOR_PADRAO");
 
   /* Recebe uma resposta do servidor */
   num_bytes = recv(comunicacao_cliente, &public_key_got, sizeof(PubKey),0);
   if (num_bytes == -1) {
      fprintf(stderr, "*** Erro no Servidor: incapaz de receber\n");
      return;
   }
   

   switch ( public_key_got.hdr.opcode ) {
    
   case PUBKEY : /* Mensagem de REQUEST */
              printf("Mensagem:: com a chave pública(PUBKEY) recebida da origem: (%d)\n", recv_msg.hdr.endereco_origem);  
              send_msg.hdr.opcode = RESPONSE;
              send_msg.hdr.endereco_origem = endereco_origem;        
              send_msg.hdr.endereco_destino = endereco_destino;  
              send_msg.desconecta_flag = 0;
              printf("Os valores recebidos para a chave pública (PUBKEY) são: \n");
              printf("e = %li\n", public_key_got.e);
              printf("n = %li\n", public_key_got.n);
              
              printf("Enviando a resposta para a solicitação do Cliente . . . \n"); 
              status = send(comunicacao_cliente, &send_msg, sizeof(RESPONSEMsg), 0);
               if (status == -1) {
                fprintf(stderr, "*** Erro no Cliente: não foi possível fazer o envio!\n");
                return;
                }
              break;
    default: 
           printf("Código da mensagem recebida: %d\n", recv_msg.hdr.opcode);
           exit(0);  
   }


   while(1){

    num_bytes = recv(comunicacao_cliente, &recv_msg, sizeof(REQUESTMsg),0);
   if (num_bytes == -1) {
      fprintf(stderr, "*** Erro no Servidor: não foi possível receber a mensagem de solicitação\n");
      return;
   }

   if (recv_msg.desconecta_flag==0){	//recebe o nome do arquivo solicitado
              struct stat st;

              if(stat(recv_msg.nome_arquivo, &st)==0) {
              	send_msg.hdr.opcode = RESPONSE;
              	printf("O arquivo existe...\n Texto Normal:\t\tTexto Cifrado:\tHash Enviado:\n");
              	char ch;
              
              	FILE *fp;
              	fp = fopen (recv_msg.nome_arquivo,"r");

                while(ch!=EOF){
                  ch = fgetc(fp);
                  printf("%c\t\t",ch);
                  if(ch>=65 && ch<=90)
                      ch -= 64;
                  else if(ch==32)	//espaço
                    ch=0;
                  else if(ch>=97 && ch<=122)	//de 'a' até 'z'
                      ch -= 71;
                  else if(ch>=48 && ch<=57)
                      ch += 4;
                  else if(ch==44)	// vírgula(,)
                      ch = 61;
                  else if(ch==46)	//ponto final (.)
                      ch = 62;
                  else if(ch==33)	//exclamação(!)
                      ch = 63;

                  e = public_key_got.e;
                  M = ch;
                  n = public_key_got.n;

                  rsa_encripta();
                  
                    char texto[2];
                    texto[0] = ch;
                    texto[1] = '\0';
                    size_t length = sizeof(texto);
                    SHA1((const unsigned char*)texto, length, send_msg.hash);

                    printf("%li\t\t%li\n",C,(long int)send_msg.hash);

                    send_msg.ciphertext = C;
                    send_msg.REQUESTcom = 0;
                    status = send(comunicacao_cliente, &send_msg, sizeof(RESPONSEMsg), 0);
                     if (status == -1) {
                      fprintf(stderr, "*** Erro no Servidor: impossível de enviar\n");
                      return;
                      }
                  }
                  send_msg.REQUESTcom = 1;
              }

              if (stat(recv_msg.nome_arquivo, &st)!=0 || send_msg.REQUESTcom ==1){

                    if(stat(recv_msg.nome_arquivo, &st)!=0 && printflag==0){
                      printf("O arquivo não existe! Enviando mensagem para desconexão do Cliente!\n");
                      send_msg.REQUESTcom = 2;
                      printflag=1;
                    }
                    else
                      send_msg.REQUESTcom = 1;
                    status = send(comunicacao_cliente, &send_msg, sizeof(RESPONSEMsg), 0);
                     if (status == -1) {
                      fprintf(stderr, "*** Erro no Servidor: Envio impossível\n");
                      return;
                      }
              }
        }

      else if(recv_msg.desconecta_flag==1){
        printf("Solicitação de desconexão recebida pelo Cliente!\n");
          send_msg.desconecta_flag=1;
          printf("Enviando permissão de desconexão com o Cliente!\n");
          status = send(comunicacao_cliente, &send_msg, sizeof(RESPONSEMsg), 0);
           if (status == -1) {
            fprintf(stderr, "*** Erro no Cliente: Envio impossível\n");
            return;
            }
            break;
      }

   }
}


int main () {
   int init_server;
   init_server = iniciaServidor();   
   aceitaConexao(init_server);
   return 0;
}
  

