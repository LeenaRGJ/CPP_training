/*
Headerfile including declaration of all the header structures to be read for Pcap file parser
*/


struct globalHeader
{
    
    unsigned int magicNumber=0; 
    unsigned short versionMajor=0;
    unsigned short versionMinor=0;
    unsigned int thiszone=0;
	unsigned int sigfigs=0;
	unsigned int MaxLengthCapturedPacket=0;
    unsigned int network=0;     
    
};

struct packetHeader
{
    //16 bytes
    unsigned int timeStampsec=0;
    unsigned int timeStampMicrosec=0;
    unsigned int inclLengthOfPacket=0;
    unsigned int originalLen=0;
};

struct ethernetHeader
{
    unsigned short int sourceMacAddress[6]={0};
    unsigned short int destinationMacAddress[6]={0};
    unsigned short typeOfIp=0;
};

struct ipv4
{
	unsigned short totalLength=0;
	unsigned short identification=0;
	unsigned short fragmentOffset=0;
	unsigned short timetoLive=0;
	unsigned short protocol=0;
	unsigned short headerChecksum=0;
	unsigned short sourceAddress[4]={0};
	unsigned short destinationAddress[4]={0};
    
};

struct ipv6
{
    unsigned short payload=0;
    unsigned short int nextHeader=0;
    unsigned short int hopLimit=0;
    unsigned short sourceAddress[8]={0};
	unsigned short destinAddress[8]={0};
};

struct protocolUdp
{
	unsigned short sourcePort=0;
	unsigned short destinationPort=0;
};

struct protocolTcp
{
	unsigned short sourcePort=0;
	unsigned short destinationPort=0;
};


