#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<iostream>
#include<pthread.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <iomanip>
#include <fstream>
#include <string>
using namespace std;

class Thread_IP
{
    public:
        char IP[50];
        int client_socket;
};
class Client_info
{
    public:
        int port;
        char name[50];
        int balance;
        char IP[50];
};
Client_info clients[1000];
Thread_IP thread_ips[1000];
int THREADNUMS = 0;
int CLIENTNUM = 0;
int ONLINES = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
int payer_port, payee_port;

char* operation_switcher(char*);
void* connection_handler(void*);
int switcher_num(char*);
int main(int argc, char const *argv[])
{
    ///create Socket///
    int mysocket = 0;
    int port = 0;

    cout << "Enter port number: ";
    cin >> port;
    mysocket = socket(PF_INET, SOCK_STREAM, 0);

    if(mysocket == -1)
        cout << "Error : Fail to create a Socket.\n" << endl;

    ///conection///
    struct sockaddr_in serverAddr,clientAddr;
    int addrlen = sizeof(clientAddr);
    bzero(&serverAddr,sizeof(serverAddr));

    serverAddr.sin_family = PF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    int bind_check = 0;
    bind_check = bind(mysocket,(struct sockaddr *)&serverAddr, sizeof(serverAddr));
    if(bind_check < 0)
        cout << "Fail to Bind" << endl;
    listen(mysocket, 10);

    cout << "Waiting for Connections..." << endl;

    int client_socket, *client_socket_ptr;
    while(client_socket = accept(mysocket, (struct sockaddr*)&clientAddr, (socklen_t*)&addrlen))
    {
        cout << "connection accepted" << endl;
        char accept_message[25] = "connection accepted";
        strcat(accept_message, "\n");
        write(client_socket, accept_message, strlen(accept_message));

        //GET IP//
        struct sockaddr_in* pV4Addr = (struct sockaddr_in*)&clientAddr;
        struct in_addr ipAddr = pV4Addr->sin_addr;
        char clientip[INET_ADDRSTRLEN];
        inet_ntop( AF_INET, &ipAddr, clientip, INET_ADDRSTRLEN );

        thread_ips[THREADNUMS].client_socket = client_socket;
        strcpy(thread_ips[THREADNUMS].IP, clientip);
        //cout << "the client's IP: " << thread_ips[THREADNUMS].IP << " " << clientip << endl; 
        THREADNUMS ++;

        pthread_t handler_thread;
        client_socket_ptr = (int*)malloc(1);
        *client_socket_ptr = client_socket;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        if(pthread_create(&handler_thread, &attr, connection_handler, (void*) client_socket_ptr) < 0)
        {
            cout << "Can't create a thread" << endl;
            return -1;
        }
        //pthread_join(handler_thread, NULL);

        //close(client_socket);   
    }


    return 0;
}

void* connection_handler(void* client_socket_ptr)
{
    int client_socket = *(int*) client_socket_ptr;
    int this_thread_client_num = -1;
    int is_login = 0;

    char receive_message_buffer[100];
    char send_message_buffer[100];
    char* send_message;
    
    char this_thread_IP[50];
    for(int i = 0; i < THREADNUMS; i++)
    {
        //cout << "IP pool: " << client_socket << " " << thread_ips[i].client_socket << " " << thread_ips[i].IP << " ";
        if(thread_ips[i].client_socket == client_socket)
            strcpy(this_thread_IP, thread_ips[i].IP);
    }
    //cout << "this thread ip: " << this_thread_IP << endl;

    char name[100];
    char port[10];
    memset(receive_message_buffer, 0, 99);
    

/*
    send_message_buffer = "123";
    write(client_socket, send_message_buffer, strlen(send_message_buffer));
*/
    while(recv(client_socket, receive_message_buffer, sizeof(receive_message_buffer), 0) > 0)
    {
        memset(send_message_buffer, 0, 99);
        //memset(send_message, 0, 99);
        //cout << send_message_buffer << "is send buffer" << endl;
        strcpy(send_message_buffer, operation_switcher(receive_message_buffer));
        if(strcmp(send_message_buffer, "LOG") == 0) //LOGIN//
        {
            char* sharp_pos_ptr = strchr(receive_message_buffer, '#');
            int sharp_pos = sharp_pos_ptr - receive_message_buffer + 1;
            memset(name, 0, 99);
            strncpy(name, receive_message_buffer, sharp_pos - 1);
            cout << name << " is in login procedure" << endl;

            strncpy(port, receive_message_buffer + sharp_pos, strlen(receive_message_buffer) - sharp_pos - 1);
            cout << port << " is the login port" << endl;

            for(int i = 0; i < CLIENTNUM + 1; i++)
            {
                if(strcmp(name, clients[i].name) == 0)
                {
                    this_thread_client_num = i;
                    pthread_mutex_lock(&mutex);
                    strcpy(clients[i].IP, this_thread_IP);
                    pthread_mutex_unlock(&mutex);
                }
            }

            is_login = 1;

            //output//
            memset(send_message_buffer, 0, 99);
            char balance[10];
            char accounts_online[3];
            snprintf(balance, sizeof(balance), "%d", clients[this_thread_client_num].balance);
            snprintf(accounts_online, sizeof(accounts_online), "%d",  ONLINES);

            strcpy(send_message_buffer, balance);
            strcat(send_message_buffer, "\n");
            strcat(send_message_buffer, "numbers of accounts online: ");
            strcat(send_message_buffer, accounts_online);
            strcat(send_message_buffer, "\n");
            for(int i = 0; i < CLIENTNUM; i++)
            {
                if(clients[i].port != -1)
                {
                    char guest_port[10];
                    snprintf(guest_port, sizeof(guest_port), "%d", clients[i].port);

                    strcat(send_message_buffer, clients[i].name);
                    strcat(send_message_buffer, "#");
                    strcat(send_message_buffer, clients[i].IP);
                    strcat(send_message_buffer, "#");
                    strcat(send_message_buffer, guest_port);
                    strcat(send_message_buffer, "\n");

                    memset(guest_port, 0, 9);
                }
            }
            cout << "send message: " << endl << send_message_buffer << endl;
            send(client_socket, send_message_buffer, sizeof(send_message_buffer), 0);
        }
        else if(strcmp(send_message_buffer, "LIS") == 0 && is_login == 1) //LIST//
        {
            //output//
            memset(send_message_buffer, 0, 99);
            char balance[10];
            char accounts_online[3];
            snprintf(balance, sizeof(balance), "%d", clients[this_thread_client_num].balance);
            snprintf(accounts_online, sizeof(accounts_online), "%d",  ONLINES);

            strcpy(send_message_buffer, balance);
            strcat(send_message_buffer, "\n");
            strcat(send_message_buffer, "numbers of accounts online: ");
            strcat(send_message_buffer, accounts_online);
            strcat(send_message_buffer, "\n");
            for(int i = 0; i < CLIENTNUM; i++)
            {
                //cout <<"cli name : " << clients[i].name << " port: " << clients[i].port << endl;
                if(clients[i].port != -1)
                {
                    char guest_port[10];
                    snprintf(guest_port, sizeof(guest_port), "%d", clients[i].port);

                    strcat(send_message_buffer, clients[i].name);
                    strcat(send_message_buffer, "#");
                    strcat(send_message_buffer, clients[i].IP);
                    strcat(send_message_buffer, "#");
                    strcat(send_message_buffer, guest_port);
                    strcat(send_message_buffer, "\n");

                    memset(guest_port, 0, 9);
                }
            }
            cout << "send message: " << send_message_buffer;
            send(client_socket, send_message_buffer, sizeof(send_message_buffer), 0);
        }
        else if(strcmp(send_message_buffer, "LIS") == 0 && is_login == 0)
        {
            memset(send_message_buffer, 0, 99);
            strcpy(send_message_buffer, "220 AUTH_FAIL");
            strcat(send_message_buffer, "\n");
            send(client_socket, send_message_buffer, sizeof(send_message_buffer), 0);
            cout << send_message_buffer << endl;
        }
        ////////////////////////////////////////////////////////////////
        else if(strstr(send_message_buffer, "Send#") != NULL)
		{
			memset(send_message_buffer, '\0', sizeof(send_message_buffer));
			strtok(receive_message_buffer, "#");
			strcpy(receive_message_buffer, strtok(NULL, "#"));
			receive_message_buffer[strlen(receive_message_buffer)-1] = '\0';
			cout << receive_message_buffer << endl;		
			bool valid = 0;

			for(int i = 0 ; i <= CLIENTNUM ; i++)
			{
				if(strcmp(clients[i].name, receive_message_buffer) == 0 //&& user_id != i
				 && clients[i].port != -1)
				{
					valid = 1;
					strcpy(send_message_buffer, clients[i].IP);
					char temp[20];
					sprintf(temp, "%d", clients[i].port);
					strcat(send_message_buffer, "#");
					strcat(send_message_buffer, temp);
					write(client_socket , send_message_buffer , strlen(send_message_buffer));	
					cout << send_message_buffer << endl;	
					payer_port = clients[this_thread_client_num].port;
					payee_port = clients[i].port;
					cout << "payer_port: "<< payer_port << ", payee_port: " << payee_port << endl;			
					break;
				}
			}

			if(valid == 0)
			{	
				write(client_socket , "230FAILED", strlen("230FAILED"));
				cout << "230 Failed" << endl;	
			}
		}
		/////////////////////////////////////////////////////
        else if(strcmp(send_message_buffer, "Bye") == 0)
        {
            ////////BYE////////////
            if(strcmp(send_message_buffer, "Bye") == 0 && is_login == 1)
            {
                //strcpy(send_message, send_message_buffer);
                send_message = send_message_buffer;
                strcat(send_message, "\n");
                 //strcat(send_message, "\0");
                //cout << send_message << "is the last send message" << endl;
                send(client_socket, send_message, sizeof(send_message), 0);
                cout << send_message << endl;

                clients[this_thread_client_num].port = -1;
                memset(clients[this_thread_client_num].IP, 0, 49);
                /*for(int i = 0; i < CLIENTNUM; i++)
                    cout <<"cli name : " << clients[i].name << " port: " << clients[i].port << endl;
                */
                is_login = 0;
                close(client_socket);
                break;
            }
            else if(strcmp(send_message_buffer, "Bye") == 0 && is_login == 0)
            {
                memset(send_message_buffer, 0, 99);
                strcpy(send_message_buffer, "220 AUTH_FAIL");
                strcat(send_message_buffer, "\n");
                send(client_socket, send_message_buffer, sizeof(send_message_buffer), 0);
                cout << send_message_buffer << endl;
                //compensation//
                pthread_mutex_lock(&mutex);
                ONLINES++;
                pthread_mutex_unlock(&mutex);
            }
        }

        //////////////////////////////////////////////////
        else if(strcmp(send_message_buffer, "100 OK") == 0 || strcmp(send_message_buffer, "210 FAIL") == 0 )
        {
        	//strcpy(send_message, send_message_buffer);
            send_message = send_message_buffer;
            strcat(send_message, "\n");
            //strcat(send_message, "\0");
            //cout << send_message << "is the last send message" << endl;
            send(client_socket, send_message, sizeof(send_message), 0);
            cout << send_message << endl;
        }
        else
        {
        	cout << receive_message_buffer << endl;
/*
                FILE *payer, *payee;
                RSA *payerRSA = nullptr, *payeeRSA = nullptr;
                if((payer = fopen("payer_pub.pem","r")) == NULL) {
                    cout << "payer Error" << endl;
                    exit(-1);
                }
                if((payee = fopen("payee_pub.pem","r")) == NULL) {
                    cout << "payee Error" << endl;
                    exit(-1);
                }
                // 初始化算法庫
                OpenSSL_add_all_algorithms();
                // 從 .pem 格式讀取公私鑰
                if((payerRSA = PEM_read_RSA_PUBKEY(payer, NULL,NULL,NULL)) == NULL) { 
                    cout << "Read payer error" << endl;
                }
                fclose(payer);
                if((payeeRSA = PEM_read_RSA_PUBKEY(payee, NULL,NULL,NULL)) == NULL) { 
                    cout << "Read payee error" << endl;
                }
                fclose(payee);
                int rsa_len = RSA_size(payerRSA); // 幫你算可以加密 block 大小，字數超過要分開加密
                
                const unsigned char * src = (const unsigned char *)receive_message_buffer; //  測試的明文
                // 要開空間來存放加解密結果，型態要改成 unsigned char *

                unsigned char * dec = (unsigned char *)malloc(rsa_len); 
                // 加密時因為 RSA_PKCS1_PADDING 的關係，加密空間要減 11，回傳小於零出錯
                if(RSA_public_decrypt(rsa_len, src, dec, payeeRSA, RSA_PKCS1_PADDING) < 0) {
                    cout << "dec error" << endl;
                }
                if(RSA_public_decrypt(rsa_len, dec, dec, payerRSA, RSA_PKCS1_PADDING) < 0) {
                    cout << "dec error" << endl;
                }
                // 加密後就會變成一堆奇怪字元
                cout << "dec: " << dec << endl;
                // 因為是它的函式 new 出來的東東，需要用他的函式釋放記憶體
                RSA_free(payerRSA);
                RSA_free(payeeRSA);
*/                
                int money;
//                money = atoi((const char*)dec);
                money = atoi((const char*)receive_message_buffer); 
                cout << "transfered balance: " << money << endl;
                cout << "payer_port: "<< payer_port << ", payee_port: " << payee_port << endl;
                for(int i = 0; i < CLIENTNUM; i++)
                {
                	if(clients[i].port == payer_port)
                		clients[i].balance -= money;
                	else if(clients[i].port == payee_port)
                		clients[i].balance += money;
                }
                strcpy(send_message, "Transaction completed");
                strcat(send_message, "\n");
                send(client_socket, send_message, sizeof(send_message), 0);
                cout << send_message << endl;
        }

        memset(receive_message_buffer, 0, 99);
    }
    
}

char* operation_switcher(char* receive_message_buffer)
{
    char receive_message[100];
    static char return_message[100];
    memset(return_message, 0, 99);
    memset(receive_message, 0, 99);
    /////////////////////////////
    cout << receive_message_buffer << endl;
    /////////////////////////////
    int switch_num = switcher_num(receive_message_buffer);

    //cout << "switch_num = " << switch_num << endl;

    if(switch_num == 0) //exit//
    {
        ONLINES--;
        strcpy(return_message, "Bye");
        return return_message;
    }
    else if(switch_num == 1) //register//
    {
        strncpy(receive_message, receive_message_buffer + 9, strlen(receive_message_buffer) - 10);
        for(int i = 0; i < CLIENTNUM; i++)
        {
            //cout <<"reci name : " << receive_message << " cli name: " << clients[i].name << endl;
            if(strcmp(receive_message, clients[i].name) == 0)
            {
                strcpy(return_message, "210 FAIL");
                return return_message;
            }
        }
        pthread_mutex_lock(&mutex);
        strcpy(clients[CLIENTNUM].name, receive_message);
        clients[CLIENTNUM].balance = 10000;
        clients[CLIENTNUM].port = -1;
        CLIENTNUM++;
        pthread_mutex_unlock(&mutex);

        cout << "nums of client : " << CLIENTNUM << endl;

        /*for(int i = 0; i < CLIENTNUM; i++)
            cout << clients[i].name << endl;
        */    
        strcpy(return_message, "100 OK");
        return return_message;  
    }
    else if(switch_num == 2) //list//
    {
        strcpy(return_message, "LIS");
        return return_message;
    }
    else if(switch_num == 3) //login//
    {
    	char* sharp_pos_ptr = strchr(receive_message_buffer, '#');
	    int sharp_pos = sharp_pos_ptr - receive_message_buffer + 1;
	    char name[100];
	    memset(name, 0, 99);
	    strncpy(name, receive_message_buffer, sharp_pos - 1);

	        //cout << name << endl;

	    char port[6];
	    strncpy(port, receive_message_buffer + sharp_pos, strlen(receive_message_buffer) - sharp_pos - 1);
	    for(int i = 0; i < CLIENTNUM; i++)
	    {
	        if(strcmp(name, clients[i].name) == 0)
	        {
	            pthread_mutex_lock(&mutex);
	            clients[i].port = atoi(port);
	            ONLINES++;
	            pthread_mutex_unlock(&mutex);
                strcpy(return_message, "LOG");
                return return_message;
            }
        }
        strcpy(return_message, "220 AUTH_FAIL");
    	return return_message;
	}
	else if(switch_num == 4)
	{
		strcpy(return_message, receive_message_buffer);
		return return_message;
	}
    else if(switch_num == -1)
    {
        strcpy(return_message, "220 AUTH_FAIL");
        return return_message;
    }
    else if(switch_num == 5)
    {
    	strcpy(return_message, receive_message_buffer);	
    	return return_message;
    }
}

int switcher_num(char* receive_message)
{
    if(strncmp(receive_message, "REGISTER#", 9) == 0)
        return 1; //register//
    else if(strncmp(receive_message, "List", 4) == 0)
        return 2; //list//
    else if(strncmp(receive_message, "Exit", 4) == 0)
        return 0; //exit//
    else if(strstr(receive_message, "Send#") != NULL)
        return 4; //Send//
    else if(strstr(receive_message, "#") != NULL)
        return 3; //Login//
    else 
    	return 5;
}