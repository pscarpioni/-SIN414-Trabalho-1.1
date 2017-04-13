# Transferência de Arquivo com RSA e SHA-1

Trabalho desenvolvido para a disciplina **SIN414 - Auditoria e Segurança de Sistemas de Informação** sob orientação do Professor **Bruno Guazzelli Batista**.

Esta aplicação consiste basicamente em uma arquitetura Cliente-Servidor, onde o Cliente envia uma REQUEST para o Servidor, solicitando um arquivo. O Servidor, por sua vez, envirá uma RESPONSE com o arquivo encriptado (com uma chave pública) e o cliente ira decriptá-lo com uma *chave privada*.


### Compilação

Para rodar o arquivo compilado, antes de mais nada, é preciso ter o pacote SHA. Para isto, basta instalá-lo utilizando o comando:


```sh
$ sudo apt-get install openssl
```

Para compilar o Servidor (Server)...

```sh
$ gcc server.c -o server -Wall -lcrypto
$ ./server
```

Para compilar o Cliente (Client)...

```sh
$ gcc client.c -o client -Wall -lcrypto
$ ./client 127.0.0.1
```
