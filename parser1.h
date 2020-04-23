/*
Headerfile for the Parser class, including all the functions and variables are declared here 
*/

#include<string>
#include<fstream>
#include "parserStructure.h"

using namespace std;

class Parser
{
	public:
		unsigned int flag=0,flag1=0,len=0,currentSize=0,pct;
		ifstream inputFile;
		ofstream outputFile;
		globalHeader global;
		packetHeader packet;
		ethernetHeader ether;
		ipv4 ip4;
		ipv6 ip6;
		protocolUdp udp;
		protocolTcp tcp;
		
  public:
    	void nextPacket();
    	void checkeof();
    	globalHeader globalHead();
    	packetHeader packHeader();
    	ethernetHeader etherHeader();
    	ipv4 ipvFour();
    	ipv6 ipvSix();
    	protocolUdp udpProtocol();
    	protocolTcp tcpProtocol();
};
