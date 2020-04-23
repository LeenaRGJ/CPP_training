/*
Headerfile for the Utility class, including all the functions and variables are declared here 
*/

#include<string>
#include<fstream>
#include <unordered_map>
#include <iterator>
#include "parser1.h"

using namespace std;

class PcapParsing
{
	public:
	Parser parse;
	ofstream fout;
    
	globalHeader global;
    packetHeader packet;
    ethernetHeader ethernet;
    ipv4 ip4;
    ipv6 ip6;
    protocolUdp udp;
    protocolTcp tcp;
	
	
	void openFolder(const char *foldername,const char *csvfolder);
	void openfile(char *fileName,const char *foldername,const char *csvfolder);
	void startParsing();
	void writeCSV();
	void uniqueIP(unordered_map<string,int> &uniqueIPmap);
	void showMap(unordered_map<string,int> &uniqueIPmap);
	std::string ipv4Address(unsigned short *ip);
	std::string ipv6Address(unsigned short *ip);
	
};


