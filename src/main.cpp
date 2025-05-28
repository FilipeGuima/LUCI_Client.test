
#include "luci_client.h"
#include "luci_packet.h"
#include <stdlib.h>
#include <getopt.h>
#include "utils.h"
#include <jsoncpp/json/json.h>



void printHelp(){

	printf("\nUsage: ./luciclient --ip address [option]\n");
	printf("options:\n");
	printf("\t--ssl-withcerts   \t\tSecure LUCI Client[Default Option]\n");
	printf("\t--ssl-withoutcerts\t\tSecure LUCI Client without client certificates\n");
	printf("\t--no-ssl          \t\tNormal LUCI Client\n");
	printf("\t--id value        \t\tIf you want to send registration data , pass a value\n");
	printf("\n");
	
}

void parseArguments(int argc, char *argv[],int withSSL,int& withoutSSL,int& withCerts,int& withoutCerts,string& ip,string& id){
	
	int c;	
	while (1)
	{
		static struct option long_options[] =
		{
		  
		  {"ssl-withcerts",  no_argument,      0, 'w'},
		  {"ssl-withoutcerts",  no_argument, 0,'x'},
		  {"no-ssl",  no_argument, 0, 'n'},
		  {"ip",     required_argument,       0, 'i'},
		  {"id",     required_argument,       0, 'd'},
		  {0, 0, 0, 0}
		};
		/* getopt_long stores the option index here. */
		int option_index = 0;

		c = getopt_long (argc, argv, "i",
			       long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		switch (c)
		{

			case 'i':
			  
			  ip.assign(optarg);
			  break;
			case 'd':
			  
			  id.assign(optarg);
			  break;
			case 'w':
				withCerts = 1;
				break;
			case 'x':
				withoutCerts = 1;
				break;
			case 'n':
				withoutSSL = 1;
				break;
			case '?':
			  /* getopt_long already printed an error message. */
			  break;

			default:
			  printf("-----undefined argument-------");
			  printHelp ();
			  return ;
			  
		}
	}
}

std::string getIPAddress()
{
	static char ip[32];
    FILE *f = popen("ip a | grep 'scope global' | grep -v ':' | awk '{print $2}' | cut -d '/' -f1", "r");
    int c, i = 0;
    while ((c = getc(f)) != EOF) i += sprintf(ip+i, "%c", c);
    pclose(f);
    printf("%s",ip);

    return std::string(ip,strlen(ip)-1);
}

void formRegistrationData(string id,std::string& data)
{
    if(id.empty())
    	return;
	Json::Value root(Json::objectValue);
	Json::Value app_info(Json::objectValue);

	app_info["version"] = "1.2.3";
	app_info["id"] = id;
	app_info["ip"] = getIPAddress();

	root["app_info"] = app_info;

	Json::StyledWriter styledWriter;
    data.assign(styledWriter.write(root));
}

int main(int argc, char *argv[]){
	
	int withSSL=-1,withoutSSL=-1,withCerts=-1,withoutCerts=-1;
	string ip{},id{};
	char buffer[1024]={0};
	bool sslClient{true},clientVertification{true},status{false};
	
	/**** Validate Arugmets ****/
	
	if(argc<2 || argc>6)
	{
		printf("---Invalid Arguments---\n");
		printHelp();
		return 0;
	}
	
	parseArguments(argc,argv,withSSL,withoutSSL,withCerts,withoutCerts,ip,id);
	
	if(ip.empty() || !validateIP(ip))
	{
		printf("----Provide Valid IP Address-----\n");
		printHelp();
		return 0;	
	}
	
	if(withoutSSL == 1){
		sslClient = false;
		clientVertification = false;
	}
	
	if(withoutCerts == 1){
		sslClient = true;
		clientVertification = false;
	}
	
	/*End Validate Arguments*/
	
	
	/****Create LUCI Client****/
	LUCIClient* luciClient = new LUCIClient((char*)ip.c_str());
	
	if(sslClient)
		status =luciClient->createSecureClient(clientVertification);
	else
		status = luciClient->createClient();
		
	if(!status)
	{
		printf("---Unable to create client----\n");
		return 0;
	}
	/****End Create LUCI Client****/
	
	/**** Start Response Thread and wait for messages  ****/
	std::promise<void> exitThreadPromise;
	std::future<void>  exitThreadFuture = exitThreadPromise.get_future();
	
	auto responseThread = std::thread(&LUCIClient::receiveThread,
                              std::ref(luciClient), // Pass by reference , otherwise the object will be copied by value and // will have undesirable consequences
		               std::move(exitThreadPromise));
		               
        responseThread.detach();
	/**** End of start Response thread ****/
	
	/****Send Register MB****/
	printf (" Sending Register message to LUCI Server \n"); 
	string registrationData{};
    formRegistrationData(id,registrationData);
    printf("Registration data:%s",registrationData.c_str());
	LUCIPacket* packet = luciClient->packData(3,registrationData.c_str(),strlen(registrationData.c_str()) ,2, 0, 0);
	luciClient->sendCommand(packet);
	delete packet;
	sleep(1);
	/**** End Send Register MB ****/
	
	/**** loop for sending commands ****/
	int messageBox,type;
	while (exitThreadFuture.wait_for(std::chrono::milliseconds(1)) == std::future_status::timeout)
	{
		memset(&buffer[0], 0, sizeof(buffer));
		printf("\nEnter Message Box Number :\n");

		scanf("%d",&messageBox);
		if (messageBox < 0 || messageBox >= 5000 ){
			printf("\nInvalid RemoteID \n");
			continue;
		}
		printf("\nDo you want to GET(1) or SET(2)\n");
		scanf("%d",&type);
		if(type == 2){
		   printf("\n Enter the Data to send :\n");
		   scanf("%s",buffer);
		}
		
		LUCIPacket* packet = luciClient->packData(messageBox,buffer,strlen(buffer) ,type, 0, 0);
		
		luciClient->sendCommand(packet);
	
		delete packet;
		sleep(1);
	}
	
	if(responseThread.joinable())
		responseThread.join();
	
	return 0;
	
}
