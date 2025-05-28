
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include "luci_packet.h"
#include "crc16.h"
#include <stdlib.h>
#include <string>
#include <iostream>
#include<iostream>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <future>
#include <thread>

#define CLIENT_CERT 	"cert/client.pem"
#define CLIENT_KEY 	"cert/client.key"

using namespace std;

class LUCIClient {

 public:
 	
 	std::string mIP{};
 	std::string mPort{"7777"};
 	int mSock{};
 	SSL *mSSL{NULL};
 	SSL_CTX  *mCtx{NULL};

	LUCIClient(char* ip);
	bool createSecureClient(bool useCerts=true);
	bool createClient();
	LUCIPacket* packData(int MID , 
	                     const char* buffer,
	                     int length,
	                     int commandtype,
	                     int commandstatus,
	                     int remoteID);
	                     
	void sendCommand(LUCIPacket* packet);
	void handleResponse(uint8_t* buf);
	void printPacket(LUCIPacket* packet);
	void receiveThread(std::promise<void> exitThreadPromise);

};
