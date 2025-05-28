#include "luci_client.h"


LUCIClient::LUCIClient(char* ip){

	mIP.assign(ip);
}

bool LUCIClient::createSecureClient(bool useCerts){

	if(useCerts)
		printf("---Creating Secure Client with Client Certificates---\n");
	else
		printf("---Creating Secure Client without Client certificates---\n");
		
	struct addrinfo v,*res;
	int err{};
	SSL_METHOD  *method;
	
	memset(&v, 0, sizeof v);
	v.ai_family = AF_UNSPEC; 
	v.ai_socktype = SOCK_STREAM;

	getaddrinfo(mIP.c_str(), mPort.c_str(), &v, &res);

	SSL_library_init();
	SSL_load_error_strings();
	method = (SSL_METHOD*)TLS_client_method();

       printf("----going to init ssl ----\n");
	mCtx = SSL_CTX_new( method );  
	if(mCtx == NULL){
		ERR_print_errors_fp( stderr ); 
		return false;
	}
	
	if(useCerts){	
		/*Clinet Certificate Loading*/
		if (SSL_CTX_use_certificate_file(mCtx, CLIENT_CERT, SSL_FILETYPE_PEM) <= 0) {
			ERR_print_errors_fp(stderr);
			return false;
		}

		if (SSL_CTX_use_PrivateKey_file(mCtx, CLIENT_KEY, SSL_FILETYPE_PEM) <= 0) {
			ERR_print_errors_fp(stderr);
			return false;
		}


		if (!SSL_CTX_check_private_key(mCtx)) {
			ERR_print_errors_fp(stderr);
			return false;
		}
	}
      

/* Socket Communoication */

	mSock = socket (res->ai_family, res->ai_socktype, res->ai_protocol); 
	if(mSock < 0){
		err = errno;
		cout<<"Socket:"<<strerror( err )<<endl;
		return false;
	} 


	printf (" Connecting to LUCI Server... \n");
      
	err = connect(mSock, res->ai_addr, res->ai_addrlen); 
	if(err < 0){    
		err = errno;
		cout<<"Connect:"<<strerror( err)<<endl;
		return false;
	} 

	mSSL = SSL_new (mCtx);
	SSL_set_fd(mSSL, mSock);
        printf("===calling ssl connect---\n");
	err = SSL_connect(mSSL);
	if (err == -1){ 
		ERR_print_errors_fp(stderr);
		return false;
	}
	
	return true;
}

bool LUCIClient::createClient(){

	printf("---Creating Normal Client---\n");

	struct addrinfo v{}, *res{};
	int err{};
	

	memset(&v, 0, sizeof v);
	v.ai_family = AF_UNSPEC; 
	v.ai_socktype = SOCK_STREAM;

	getaddrinfo(mIP.c_str(), mPort.c_str(), &v, &res);

/* Socket Communoication */

	mSock = socket (res->ai_family, res->ai_socktype, res->ai_protocol); 
	if(mSock < 0){
		err = errno;
		cout<<"Socket:"<<strerror( err )<<endl;
		return false;
	} 


	printf (" Connecting to LUCI Server... \n");
        
	err = connect(mSock, res->ai_addr, res->ai_addrlen); 
	if(err < 0){    
		err = errno;
		cout<<"Connect:"<<strerror( err)<<endl;
		return false;
	} 
	
	return true;
}

LUCIPacket* LUCIClient::packData(int MID , 
	                     const char* buffer,
	                     int length,
	                     int commandtype,
	                     int commandstatus,
	                     int remoteID){
	                     
	uint8_t* buf = (uint8_t *)buffer;
	
	LUCIPacket* packet        = new LUCIPacket();
	uint16_t       RemoteID      = remoteID;
	uint8_t        CommandType   = commandtype;
	uint16_t       Command       = MID;
	uint8_t        CommandStatus = commandstatus;
	uint16_t       CRC           = 0;
	uint16_t       DataLen       = length;


	packet->setRemoteID(RemoteID);
	packet->setCommandType(CommandType);
	packet->setCommandStatus(CommandStatus);
	packet->setCommand(Command);
	packet->setAccessUnitData(buf,DataLen);

	return packet;                     
}

void LUCIClient::handleResponse(uint8_t* buf){

	uint8_t tot_Packet[5120] = {0};
	char *ptembuff = NULL;

	LUCIPacket* packet = new LUCIPacket();

	uint16_t  RemoteID      = ntohs(static_cast<int16_t>( buf[1] << 8 | buf[0]));
	uint8_t   CommandType   = (buf[2]);
	uint16_t  Command       = ntohs(static_cast<int16_t>( buf[4] << 8 | buf[3]));
	uint8_t   CommandStatus = (buf[5]);
	uint16_t  CRC           = ntohs(static_cast<int16_t>( buf[7] << 8 | buf[6]));
	uint16_t  DataLen       = ntohs(static_cast<int16_t>( buf[9] << 8 | buf[8]));
	uint16_t  mCRC;

	printf("\n******Response Received******\n");
    	if ( CRC !=0)
	{
		uint8_t *dbg = tot_Packet;
		int CRCDataLen = (10-2) + DataLen ;
		memcpy(tot_Packet,buf,6);
		memcpy(tot_Packet+6 , buf+8,2);

		if(DataLen > 0) {
			memcpy(tot_Packet+8, buf+10, DataLen);
		}

		mCRC = crc16_ccitt( dbg , CRCDataLen);
	}
	if (((CRC == 0)) || (mCRC ==CRC))
	{
		packet->setRemoteID(RemoteID);
		packet->setCommandType(CommandType);
		packet->setCommandStatus(CommandStatus);
		packet->setCommand(Command);
		packet->setAccessUnitData(&buf[10],DataLen);
		
	} else {
		printf(" CRC missmatch discard packet\n");
		goto exit;

	}
	
	if (CommandStatus > 1 )// Failure condition
	{
		printf(" LUCI error %d for command:%d \n",CommandStatus,Command);
		goto exit;
		
	}
	if(Command == 3)
	{
		printf("-----registre mid success ----\n");	
	}
	
	exit:
	
	printPacket(packet);
	printf("\n******END OF RESPONSE******\n");
	delete packet;	
}

void LUCIClient::sendCommand(LUCIPacket* packet){

	if(packet->pack()) {
		uint8_t*  pkt     = packet->getPacket();
		int       pktlen  = packet->getPacketLen();
		
		if(mSSL){
			if(SSL_write(mSSL, pkt, 	pktlen) < 0){
				printf(" failed to Send Packet \n");
				return;
			}
		}else
		{
			if(send(mSock, pkt, 	pktlen,0) < 0){
				printf(" failed to Send Packet \n");
				return;
			}
		}

		printf("\n***** Sent Command ***** \n");
		printPacket(packet);
	}
}

void LUCIClient::receiveThread(std::promise<void> exitThreadPromise){

	printf("----Starting response thread-----\n");
	fd_set readfds;
	int  bytesRead;
	int  activity;
	int maxSD = -1;
	int m_fds[2];
	uint8_t buffer[5120] = {};
	
	if (::pipe(m_fds) < 0 )
		printf("Pipe creation failed with error : %s\n", strerror(errno));
	else
		printf("CLIs m_fds[0] : %u m_fds[1] : %u\n", m_fds[0], m_fds[1]);
	
	while(1)
	{
		FD_ZERO(&readfds);
		FD_SET(mSock, &readfds);
		FD_SET(m_fds[0], &readfds);

		maxSD = m_fds[0];

		if(mSock > m_fds[0])
		maxSD = mSock;

		activity = select(maxSD + 1 , &readfds , NULL , NULL , NULL);
		if(   activity < 0 && errno != EINTR)
		{
			printf("---Select returned with error----\n");
			goto bailout;	 // need to exit thread
		}

		if(FD_ISSET(m_fds[0], &readfds))
		{
			printf("LUCINetworkController::LuciClient ::forced quit!!!!!!\n");
			goto bailout;
		}	

		if (FD_ISSET(mSock, &readfds))
		{
			
			if(mSSL)
				bytesRead = SSL_read( mSSL , buffer, sizeof(buffer));
			else
				bytesRead = recv( mSock , buffer, sizeof(buffer),0);
				
			if( bytesRead <= 0)
			{

				printf("----Something went wrong,exiting----\n");
				goto bailout;
			//recv
			}
			else
			{
				handleResponse(buffer);
				fwrite("5001" , 1 , 4 , stdin );
				fflush(stdin);
			}
		}
	}
	
	bailout:
	
	FD_CLR(mSock, &readfds);
	exitThreadPromise.set_value();
	fwrite("5001" , 1 , 4 , stdin );
	
}

void LUCIClient::printPacket(LUCIPacket* packet){
	
	packet->pack();
	uint8_t*  pkt     = packet->getPacket();
	int       pktlen  = packet->getPacketLen();	
	
	uint16_t  RemoteID      = (static_cast<int16_t>( pkt[1] << 8 | pkt[0]));
	uint8_t   CommandType   = (pkt[2]);
	uint16_t  Command       = (static_cast<int16_t>( pkt[4] << 8 | pkt[3]));
	uint8_t   CommandStatus = (pkt[5]);
	uint16_t  CRC           = (static_cast<int16_t>( pkt[7] << 8 | pkt[6]));
	uint16_t  DataLen       = (static_cast<int16_t>( pkt[9] << 8 | pkt[8]));
	
	printf("\n\n");
	printf("Remote ID\tCommandType\tCommand\tCommandStatus\tCRC\tDataLen\tData\n");
	printf("  %d     \t  %d       \t %d    \t  %d         \t%d \t %d    \t ",RemoteID,CommandType,Command,CommandStatus,CRC,DataLen);
	for(int i=9;i<pktlen;i++)
		printf("%c",pkt[i]);
		
	printf("\n\n");
	/*for(int i=0;i<pktlen;i++)
		printf("%0x\n",pkt[i]);*/

}

