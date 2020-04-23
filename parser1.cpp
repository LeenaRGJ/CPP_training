/*
This is parser file whitch contains functions to open the file and to read the headers of pcap file when called by the utility class.
Right now contains Functions for reading Global Header, Packet Header, Ethernet Header, Ipv4 Header,ipv6 Header,Tcp Header,Udp Header. 
*/

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <netinet/in.h>
#include "parser1.h"

#define ONE_BYTE 1	
#define TWO_BYTES 2
#define FOUR_BYTES 4
#define PCT_HEADER_SIZE 16 //Packet header size is 16 bytes

using namespace std;

//defining the function to set file pointer at the start of next packet header
void Parser::nextPacket()
{
	inputFile.seekg(currentSize,ios::beg);
}

//defining the function to read a byte before checking for End of file
void Parser::checkeof()
{
	inputFile.read((char*)&(flag1), 1);
}

//defining the function to read global header of 24 bytes
globalHeader Parser::globalHead()
{	
	currentSize=0;
	cout << "GLOBAL HEADER" <<endl;
  inputFile.read((char*)&(global.magicNumber),FOUR_BYTES);
	cout<<std::hex<<global.magicNumber<<endl;										
    
    if(global.magicNumber==3569595041)
    {
    	flag=1; 
		cout << "It is Big endian" << endl; // d4c3b2a1
	}
	else if(global.magicNumber==2712812621)
	{
		flag=1;
		cout << "It is identical nanosec resolution files"; //a1b23c4d
	}
	else if(global.magicNumber==1295823521)
	{
		flag=1;
		cout << " It is swapped nanosec resolution files"; // 4d3cb2a1 
	}	
	else if(global.magicNumber==2712847316)
	{
		flag=1;
		cout << "It is Little endian";
	}
	
	inputFile.read((char*)&(global.versionMajor),TWO_BYTES);
	inputFile.read((char*)&(global.versionMinor),TWO_BYTES);
	inputFile.read((char*)&(global.thiszone),FOUR_BYTES);
	inputFile.read((char*)&(global.sigfigs),FOUR_BYTES);
	
	inputFile.read((char*)&(global.MaxLengthCapturedPacket),FOUR_BYTES);
	inputFile.read((char*)&(global.network),FOUR_BYTES);
	
	//Storing current pointer position
	currentSize=inputFile.tellg();
	return global;
}

//defining the function to read Packet header
packetHeader Parser::packHeader()
{
	cout << "PACKET HEADER" <<endl;
	inputFile.read((char*)&(packet.timeStampsec), FOUR_BYTES);
	inputFile.read((char*)&(packet.timeStampMicrosec), FOUR_BYTES);
	inputFile.read((char*)&(packet.inclLengthOfPacket), FOUR_BYTES);	
	inputFile.read((char*)&(packet.originalLen), FOUR_BYTES);

	
	//Adding Packet header and Packet data length in current pointer
	currentSize=currentSize + packet.inclLengthOfPacket + PCT_HEADER_SIZE;
	std::cout << currentSize << endl;
	
	return packet;
}

//defining the function to read Ethernet header
ethernetHeader Parser::etherHeader()
{  
	cout << "ETHERNET HEADER" <<endl;
	//reading source Mac Address of 6 bytes field
	inputFile.read((char*)&ether.sourceMacAddress[0], ONE_BYTE);

	inputFile.read((char*)&(ether.sourceMacAddress[1]), ONE_BYTE);
	inputFile.read((char*)&(ether.sourceMacAddress[2]), ONE_BYTE);
	inputFile.read((char*)&(ether.sourceMacAddress[3]), ONE_BYTE);
	inputFile.read((char*)&(ether.sourceMacAddress[4]), ONE_BYTE);
	inputFile.read((char*)&(ether.sourceMacAddress[5]), ONE_BYTE);
	 
	//reading destination Mac Address of 6 bytes field
	inputFile.read((char*)&(ether.destinationMacAddress[0]),ONE_BYTE);
	inputFile.read((char*)&(ether.destinationMacAddress[1]),ONE_BYTE);
	inputFile.read((char*)&(ether.destinationMacAddress[2]),ONE_BYTE);
	inputFile.read((char*)&(ether.destinationMacAddress[3]),ONE_BYTE);
	inputFile.read((char*)&(ether.destinationMacAddress[4]),ONE_BYTE);
	inputFile.read((char*)&(ether.destinationMacAddress[5]),ONE_BYTE);
	 
	//reading type of IP address of 2 bytes field
	inputFile.read((char*)&(ether.typeOfIp),TWO_BYTES);
	//Network to host short function convert it according to big or lil endian
	ether.typeOfIp= ntohs(ether.typeOfIp);
 
	return ether;
}

//defining the function to read Ipv4 header
ipv4 Parser::ipvFour()
{
	cout << "IPV4 HEADER" <<endl;
	//skipping first 2 bytes field
	inputFile.seekg(TWO_BYTES, ios::cur);
	
	inputFile.read((char*)&(ip4.totalLength), TWO_BYTES);
	
	inputFile.read((char*)&(ip4.identification), TWO_BYTES);
	
	inputFile.read((char*)&(ip4.fragmentOffset), TWO_BYTES);
	inputFile.read((char*)&(ip4.timetoLive), ONE_BYTE);
	inputFile.read((char*)&(ip4.protocol), ONE_BYTE);
	 
	//reading Header checksum of 2 bytes field
	inputFile.read((char*)&(ip4.headerChecksum), TWO_BYTES);
	
	//reading source IP address of 4 bytes field
	inputFile.read((char*)&(ip4.sourceAddress[0]),ONE_BYTE);
	inputFile.read((char*)&(ip4.sourceAddress[1]),ONE_BYTE);
	inputFile.read((char*)&(ip4.sourceAddress[2]),ONE_BYTE);
	inputFile.read((char*)&(ip4.sourceAddress[3]),ONE_BYTE);
	
	//reading Destination IP Address of 4 bytes field
	inputFile.read((char*)&(ip4.destinationAddress[0]),ONE_BYTE); 
	inputFile.read((char*)&(ip4.destinationAddress[1]),ONE_BYTE); 
	inputFile.read((char*)&(ip4.destinationAddress[2]),ONE_BYTE); 
	inputFile.read((char*)&(ip4.destinationAddress[3]),ONE_BYTE); 
	
	return ip4;
}

//defining the function to read Ipv6 header
ipv6 Parser::ipvSix()
{
	//Skip feilds of Version, Priority, Flowlable
	inputFile.seekg(4, ios::cur);
	
	std::cout<<"IPV6 HEADERRRRRR"<<endl;
	
	inputFile.read((char*)&(ip6.payload), TWO_BYTES);
	//reading Next Header i.e protocol of 1 byte field
	inputFile.read((char*)&(ip6.nextHeader),ONE_BYTE);
	inputFile.read((char*)&(ip6.hopLimit), ONE_BYTE);
	
	//reading source IP Address of 16 bytes field
	inputFile.read((char*)&(ip6.sourceAddress[0]), TWO_BYTES);
	ip6.sourceAddress[0]=ntohs(ip6.sourceAddress[0]);
	inputFile.read((char*)&(ip6.sourceAddress[1]), TWO_BYTES);
	ip6.sourceAddress[1]=ntohs(ip6.sourceAddress[1]);
	inputFile.read((char*)&(ip6.sourceAddress[2]), TWO_BYTES);
	ip6.sourceAddress[2]=ntohs(ip6.sourceAddress[2]);
	inputFile.read((char*)&(ip6.sourceAddress[3]), TWO_BYTES);
	ip6.sourceAddress[3]=ntohs(ip6.sourceAddress[3]);
	inputFile.read((char*)&(ip6.sourceAddress[4]), TWO_BYTES);
	ip6.sourceAddress[4]=ntohs(ip6.sourceAddress[4]);
	inputFile.read((char*)&(ip6.sourceAddress[5]), TWO_BYTES);
	ip6.sourceAddress[5]=ntohs(ip6.sourceAddress[5]);
	inputFile.read((char*)&(ip6.sourceAddress[6]), TWO_BYTES);
	ip6.sourceAddress[6]=ntohs(ip6.sourceAddress[6]);
	inputFile.read((char*)&(ip6.sourceAddress[7]), TWO_BYTES);
	ip6.sourceAddress[7]=ntohs(ip6.sourceAddress[7]);
	
	//reading Destination IP Address of 16 bytes field
	inputFile.read((char*)&(ip6.destinAddress[0]), TWO_BYTES);
	ip6.destinAddress[0]=ntohs(ip6.destinAddress[0]);
	inputFile.read((char*)&(ip6.destinAddress[1]), TWO_BYTES);
	ip6.destinAddress[1]=ntohs(ip6.destinAddress[1]);
	inputFile.read((char*)&(ip6.destinAddress[2]), TWO_BYTES);
	ip6.destinAddress[2]=ntohs(ip6.destinAddress[2]);
	inputFile.read((char*)&(ip6.destinAddress[3]), TWO_BYTES);
	ip6.destinAddress[3]=ntohs(ip6.destinAddress[3]);
	inputFile.read((char*)&(ip6.destinAddress[4]), TWO_BYTES);
	ip6.destinAddress[4]=ntohs(ip6.destinAddress[4]);
	inputFile.read((char*)&(ip6.destinAddress[5]), TWO_BYTES);
	ip6.destinAddress[5]=ntohs(ip6.destinAddress[5]);
	inputFile.read((char*)&(ip6.destinAddress[6]), TWO_BYTES);
	ip6.destinAddress[6]=ntohs(ip6.destinAddress[6]);
	inputFile.read((char*)&(ip6.destinAddress[7]), TWO_BYTES);
	ip6.destinAddress[7]=ntohs(ip6.destinAddress[7]);
	
	return ip6;
}

//defining the function to read UDP header
protocolUdp Parser::udpProtocol()
{
	//reading source port of 2 bytes field
	inputFile.read((char*)&(udp.sourcePort), TWO_BYTES);
	udp.sourcePort=ntohs(udp.sourcePort);
	//reading Destination port of 2 bytes field
	inputFile.read((char*)&(udp.destinationPort), TWO_BYTES);
	udp.destinationPort=ntohs(udp.destinationPort);
	std::cout << udp.sourcePort <<" " <<udp.destinationPort <<endl;
	
	return udp;
}

//defining the function to read TCP header
protocolTcp Parser::tcpProtocol()
{
	//reading source port of 2 bytes field
	inputFile.read((char*)&(tcp.sourcePort), TWO_BYTES);
	tcp.sourcePort=ntohs(tcp.sourcePort);
	inputFile.read((char*)&(tcp.destinationPort), TWO_BYTES);
	//reading Destination port of 2 bytes field
	tcp.destinationPort=ntohs(tcp.destinationPort);
	return tcp;
}
