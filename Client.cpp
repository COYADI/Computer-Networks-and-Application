#include <iostream>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <cstdio>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <iomanip>
#include <fstream>
#include <string>
#include <sys/wait.h>
#include <errno.h>

using namespace std;

int operation_handler(char*);
void homepage();
void login();
char* homepage_interface();
int login_interface();
int main(int argc, char const *argv[])
{
	///create Socket///
	int mysocket = 0;
	mysocket = socket(PF_INET, SOCK_STREAM, 0);

	if(mysocket == -1)
		cout << "Error : Fail to create a Socket.\n";

	///Connecting///
	char server_ip[25] = {};
	int server_port = 0;
	cout << "Please enter the Server's IP: \n";
	cin >> server_ip;
	cout << "Please enter the Server's port: \n";
	cin >> server_port;

	struct sockaddr_in Serveraddr;
	bzero(&Serveraddr, sizeof(Serveraddr));
	Serveraddr.sin_family = PF_INET;
	Serveraddr.sin_addr.s_addr = inet_addr(server_ip);
	Serveraddr.sin_port = htons(server_port);

	///connect to Server///
	int failconnect = connect(mysocket, (struct sockaddr*)&Serveraddr, sizeof(Serveraddr));
	if(failconnect == -1)
		cout << "Fail to connect\n";

	///send and receive///
	int receive_confirm, send_confirm;
	int switcher = 0;
	char send_message_buffer[100] = {};
	char receive_message_buffer[100] = {};
	receive_confirm = recv(mysocket, receive_message_buffer, sizeof(receive_message_buffer), 0);
	cout << receive_message_buffer;


	while(1)
	{
		char send_message[100] = {};
		char receive_message[100] = {};
        if(switcher == 0)
        {
        	char* message_pointer = homepage_interface();
        	strcpy(send_message, message_pointer);
        }
        else
        {
        	int text_switch = 0;
        	text_switch = login_interface();
        	if(text_switch == 1)
        		strcpy(send_message, "List");
        	else if(text_switch == 0)
        		strcpy(send_message, "Exit");
        	///////////////////////////////////////////////////////////////////////////
        	else if(text_switch == 2) //transaction//
        	{
        		int status;
	            if(fork() == 0)
	            {
	                char request_user[100], ip_address[50];
	                int portNumber;
	                memset(receive_message, '\0', sizeof(receive_message));
	                strcpy(send_message, "Send#");
	                cout << "Please enter the user you want to have transaction with:";
	                cin >> request_user;
	                strcat(send_message, request_user);
	                strcat(send_message, "\n");
	                send(mysocket, send_message, sizeof(send_message), 0);
	                recv(mysocket, receive_message, sizeof(receive_message), 0);
	                
	                if(strstr(receive_message, "230") != NULL)
	                    cout << "No found or not online!" << endl;
	                else
	                {
	                    strcpy(ip_address, strtok(receive_message, "#"));
	                    portNumber = atoi(strtok(NULL, "#"));                
	                }
	                cout << "Please enter the amount you want to send:";
	                char money[10];
	                cin >> money;

	                int mysocket2 = 0;
	                mysocket2 = socket(AF_INET , SOCK_STREAM , 0);

	                if(mysocket2 == -1){
	                    cout << "Fail to create a socket.";
	                    return 0;
	                }

	                struct sockaddr_in asClient;
	                bzero(&asClient,sizeof(asClient));
	                asClient.sin_family = PF_INET;
	                asClient.sin_addr.s_addr = inet_addr(ip_address);
	                asClient.sin_port = htons(portNumber);


	                int failconnect = connect(mysocket2,(struct sockaddr *)&asClient,sizeof(asClient));
	                if(failconnect == -1)
	                {
	                    cout << "Connection error";
	                    return 0;
	                }

/*
	                FILE *pri;
	                RSA *privateRSA = nullptr;
	                if((pri = fopen("payer_pri.pem","r")) == NULL) 
	                {
	                    cout << "pri Error" << endl;
	                    exit(-1);
	                }
	                // 初始化算法庫
	                OpenSSL_add_all_algorithms();
	                // 從 .pem 格式讀取公私鑰
	                if((privateRSA = PEM_read_RSAPrivateKey(pri, NULL,NULL,NULL)) == NULL) 
	                { 
	                    cout << "Read pri error" << endl;
	                }
	                fclose(pri);
	                int rsa_len = RSA_size(privateRSA); // 幫你算可以加密 block 大小，字數超過要分開加密
	                
	                const unsigned char * src = (const unsigned char *)money; //  測試的明文
	                // 要開空間來存放加解密結果，型態要改成 unsigned char *

	                unsigned char * enc = (unsigned char *)malloc(rsa_len);
	                // 加密時因為 RSA_PKCS1_PADDING 的關係，加密空間要減 11，回傳小於零出錯
	                if(RSA_private_encrypt(rsa_len-11, src, enc, privateRSA, RSA_PKCS1_PADDING) < 0) 
	                {
	                    cout << "enc error" << endl;
	                }
	                cout << "enc: " << enc << endl;
	                RSA_free(privateRSA);
*/
//	                send(mysocket2, (const char*)enc, strlen((const char*)enc), 0);
	                send(mysocket2, (const char*)money, strlen((const char*)money), 0);
	                sleep(1);
	            }
	            else
	                wait(&status);

	            strcpy(send_message, "List");
	        }
	        ////////////////////////////////////////////////////////////////////////////////////////////////
	        else
	        {
	        	int status, fd[2];
	            pipe(fd);
	            char enc_message[300];
	            memset(enc_message, '\0', sizeof(enc_message));

	            if(fork() == 0)
	            {
	                cout << "Please enter your port again:";
	                int socket_trans , asServer_socket , addr_size, port_trans;
	                cin >> port_trans;
	                struct sockaddr_in server2 , client2;
	                char *message2;
	                
	                //Create socket
	                socket_trans = socket(AF_INET , SOCK_STREAM , 0);
	                if (socket_trans == -1)
	                {
	                    printf("Could not create socket");
	                }
	                
	                //Prepare the sockaddr_in structure
	                server2.sin_family = AF_INET;
	                server2.sin_addr.s_addr = INADDR_ANY;
	                server2.sin_port = htons( port_trans );
	                
	                //Bind
	                if( bind(socket_trans,(struct sockaddr *)&server2 , sizeof(server2)) < 0)
	                {
	                    puts("bind failed");
	                    return 1;
	                }
	                puts("binded");
	                
	                //Listen
	                listen(socket_trans , 3);
	                
	                //Accept and incoming connection
	                puts("Waiting for incoming connections...");
	                addr_size = sizeof(struct sockaddr_in);
	                asServer_socket = accept(socket_trans, (struct sockaddr *)&client2, (socklen_t*)&addr_size);
	                if (asServer_socket < 0)
	                {
	                    perror("accept failed");
	                    return 1;
	                }
	                
	                puts("Connection accepted");

//Encryption
/*	                FILE *pri;
	                RSA *privateRSA = nullptr;
	                if((pri = fopen("payee_pri.pem","r")) == NULL) {
	                    cout << "pri Error" << endl;
	                    exit(-1);
	                }
	                // 初始化算法庫
	                OpenSSL_add_all_algorithms();
	                // 從 .pem 格式讀取公私鑰
	                if((privateRSA = PEM_read_RSAPrivateKey(pri, NULL,NULL,NULL)) == NULL) { 
	                    cout << "Read pri error" << endl;
	                }
	                fclose(pri);
	                int rsa_len = RSA_size(privateRSA); // 幫你算可以加密 block 大小，字數超過要分開加密
	                
*/
	                char recv_enc[1000];
	                memset(recv_enc, '\0', sizeof(recv_enc));
	                recv(asServer_socket, recv_enc, sizeof(recv_enc), 0);
	                sleep(1);
	                cout << "Received message: " << recv_enc << endl;
/*
	                const unsigned char * src = (const unsigned char *)recv_enc; //  測試的明文
	                // 要開空間來存放加解密結果，型態要改成 unsigned char *

	                unsigned char * enc = (unsigned char *)malloc(rsa_len);
	                // 加密時因為 RSA_PKCS1_PADDING 的關係，加密空間要減 11，回傳小於零出錯
	                if(RSA_private_encrypt(rsa_len-11, src, enc, privateRSA, RSA_PKCS1_PADDING) < 0) {
	                    cout << "enc error" << endl;
	                }
	                // 加密後就會變成一堆奇怪字元
	                // 因為是它的函式 new 出來的東東，需要用他的函式釋放記憶體
	                RSA_free(privateRSA);
	                cout << endl << enc << endl;
*/
	                close(fd[0]);
//	                write(fd[1], (const char*)enc, strlen((const char*)enc));
	                write(fd[1], (const char*)recv_enc, strlen((const char*)recv_enc));
	                close(fd[1]);

	                exit(0);
	            }
	            else
	            {
	                wait(&status);
	                close(fd[1]);
	                read(fd[0], enc_message, sizeof(enc_message));
	                close(fd[0]);
	            }

	            cout << endl << "encoding message:" << enc_message << endl;
	            //send(mysocket, enc_message, sizeof(enc_message), 0);
	            strcpy(send_message, enc_message);
		    }
        }
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

		strcpy(send_message_buffer, send_message);
		strcat(send_message_buffer, "\n");
		//printf("%s\n", send_message_buffer);

		send_confirm = send(mysocket, send_message_buffer, sizeof(send_message_buffer), 0);
		if(send_confirm == -1)
			cout << "Fail to send contents to server!\n";
		else
		{
			receive_confirm = recv(mysocket, receive_message, sizeof(receive_message), 0);
			strcpy(receive_message_buffer, receive_message);

			if(receive_confirm == -1)
				cout << "Fail to receive contents from server!\n";
			else
			{
				int operation_code = operation_handler(receive_message_buffer);
				cout << receive_message_buffer;
			
				if(operation_code == -1)
					break;
			}

			if(strncmp(send_message_buffer, "REGISTER#", 8) != 0 && strncmp(receive_message_buffer, "100 OK", 6) != 0 && strncmp(receive_message_buffer, "210 FAIL", 8) != 0 && strncmp(receive_message_buffer, "220 AUTH_FAIL", 13) != 0)
				switcher = 1;
		}

		memset(send_message, '\0', sizeof(send_message));
		memset(send_message_buffer, '\0', sizeof(send_message_buffer));
	}

	///close Socket///
	close(mysocket);

	return 0;
}

int operation_handler(char* received_message)
{
	if(strcmp(received_message, "Bye\n") == 0)
		return -1;
	else 
		return 0;
}
void homepage()
{
	cout << "+===============================================+\n";
	cout << "|                                               |\n";
	cout << "|                  HOME PAGE                    |\n";
	cout << "|                                               |\n";
	cout << "+===============================================+\n";
	cout << "PRESS R TO REGISTER, PRESS L TO LOGIN: ";
}
void login()
{
	cout << "+===============================================+\n";
	cout << "|                                               |\n";
	cout << "|                 WELCOME BACK                  |\n";
	cout << "|                                               |\n";
	cout << "+===============================================+\n";
	cout << "PRESS L TO LIST, E TO EXIT, S TO SEND, A TO ACCEPT TRANSFER: ";
}

char* homepage_interface()
{
	char switcher;
	static char return_buffer[50];
	
	
	homepage();
	cin >> switcher;
	while(1)
	{
		
		if(switcher == 'R')
		{
			strcpy(return_buffer, "REGISTER#");
			char username[50];
			cout << "Please enter a name: ";
			cin >> username;
			//cout << return_buffer << " hello\n";
			strcat(return_buffer, username);
			//cout << return_buffer << "hello \n";
			return return_buffer;
		}
		else if (switcher == 'L')
		{
			char username[50];
			char port[5];
			cout << "Please enter a name: ";
			cin >> username;
			cout << "Please enter a port: ";
			cin >> port;
			strcat(username, "#");
			strcat(username, port);
			strcpy(return_buffer, username);
			//cout << return_buffer;
			return return_buffer;
		}
		else
			cout << "insert error!\nPRESS R TO REGISTER, PRESS L TO LOGIN: ";
		cin >> switcher;
	}
	

}
int login_interface()
{
	login();
	char switcher;
	cin >> switcher;
	
	while(1)
	{
		if(switcher == 'L')
			return 1;
		else if(switcher == 'E')
			return 0;
		else if(switcher == 'S')
			return 2;
		else if(switcher == 'A')
			return 3;
		else
			cout << "insert error!\nPRESS L TO LIST, E TO EXIT, S TO SEND, A TO ACCEPT TRANSFER: ";
		cin >> switcher;
	}
	
}