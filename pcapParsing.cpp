/*
This file calls the Parser class functions of reading the perticular header function after checking if it is ipv4 or ipv6, tcp or udp and reads only that packets othervise jump the pointer to next Packet.
And writes the details of Packets in CSV file.
Also maintains the map for storing count of packets.
*/

#include <iostream>
#include <cstdlib>
#include <queue>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <dirent.h>
#include <unordered_map>
#include <iterator>
#include "pcapParsing.h"

#define Ipv4 2048  //decimal value of ipv4 type 0x0800
#define Ipv6 34525 //decimal value of ipv6 type 0x86dd
#define UDP 17     //decimal value of udp protocol 
#define TCP 6		//decimal value of tcp protocol

using namespace std;

//defining the multipurpose function to list the files and call parser 
void PcapParsing::openFolder(const char *foldername,const char *csvfolder)
{
	DIR *dir;
	struct dirent *inDir;
	
	//check if dir is not or not
	if((dir=opendir(foldername)) != NULL) 
	{
	  //Iterating all the files and directories
	  while((inDir= readdir(dir))!= NULL) 
		{
			if(inDir->d_type==DT_DIR)
				continue;
			else
			{
				//calling function to open pcap and csv file 
				openfile(inDir->d_name,foldername,csvfolder);
				//calling function to start parsing of file
				startParsing();
			}
	  }
	 
	  //closedir(dir);
	} else 
	{
	  //could not open directory 
	  perror ("");
	}
	
}

//defining function to open the file by user
void PcapParsing::openfile(char *fileName,const char *foldername,const char *csvfolder)
{
	
	char filePath[70];
	strcpy(filePath,foldername);
	strcat(filePath,"/");
	strcat(filePath,fileName);
	
	cout << filePath <<endl;
	parse.inputFile.open(filePath, ios::binary | ios::in);
	if(parse.inputFile.is_open())
		cout << "pcap open1" << endl;
	else
		cout << "can't open1" << endl;
		
		
	//Naming the csv file as "filename.csv" 
	char csvFilepath[70];
	strcpy(csvFilepath,csvfolder);
	strcat(csvFilepath,"/");
	string s(csvFilepath);
	
	string csvFile(fileName);
	int pos=csvFile.find(".");
	csvFile=csvFile.substr(0,pos);
	csvFile=csvFile+".csv";
	
	csvFile=s+csvFile;

	//Open CSV file corresponding to current pcap file
	fout.open(csvFile);

	if(fout.is_open())
	cout<<"File open"<<endl;
	else
	cout<<"File cant be opened"<<endl;
	
}


/*This function is reponsible for reading pcap file by headers vise and calls the header function after a check is true*/
void PcapParsing::startParsing()
{
	int TCPcount=0,UDPcount=0;
	unordered_map<string,int> uniqueIPmap;
	
	//To Read the global header
	global = parse.globalHead();
	
		//Check if the file is a Pcap file and the networ is ethernet, if true 			then reads next packets othervise return to the function call
		if(parse.flag==1 && global.network==1)
		{
			std::cout<<"Inside\n";
			//For reading file untill end of the file 
			while(!parse.inputFile.eof())
			{
				//To set the pointer at the starting of next packet 
				parse.nextPacket();
				
				//To read packet header	
				packet = parse.packHeader();
				
				//To read ethernet header
				ethernet = parse.etherHeader();
				
				//Check if ip type is IPv4
				if(ethernet.typeOfIp==Ipv4)
				{
					//Then reads ipv4 header
					ip4 = parse.ipvFour();
					if(ip4.protocol==UDP)//Check if protocol is upd
					{
						//then reads udp header
						udp = parse.udpProtocol();	
						//Increasing count of UDP pct
						UDPcount++;
					}
					else if(ip4.protocol==TCP)//Check if protocol is tcp
					{
						//Then reads tcp header
						tcp = parse.tcpProtocol();
						//Increasing count of TCP pct
						TCPcount++;
					}
				}
				//Check else if ip type is IPv4
				else if(ethernet.typeOfIp==Ipv6)
				{
					//Then reads ipv4 header
					ip6 = parse.ipvSix();
					if(ip6.nextHeader==UDP)//Check if protocol is upd
					{
						//then reads udp header
						udp = parse.udpProtocol();
						//Increasing count of UDP pct
						UDPcount++;
					}
					else if(ip6.nextHeader==TCP)//Check if protocol is tcp
					{
						//Then reads tcp header
						tcp = parse.tcpProtocol();
						//Increasing count of TCP pct
						TCPcount++;
					}
				}
				else
				{		//Neither ipv4 nor ipv6
						cout << "Dont read this packet " <<endl;
				}
				
				//To write current packet information in CSV 
				writeCSV();
				
				//Enters unique ip and counts in map
				uniqueIP(uniqueIPmap);
				
				//Reads 1 byte to check for end of file 
				parse.checkeof();
			}
		}
		else
		{
			cout <<"Can't read this file" <<endl;
		}
		
		//To print the map of unique IP packet count for the current file
		showMap(uniqueIPmap);
		
		cout <<"TCP packets :: in file "<<TCPcount <<endl;
		cout <<"UDP packets :: in file "<<UDPcount <<endl;
		
		//close the file after complete reading
		parse.inputFile.close();
		//close the CSV file pointer
		fout.close();
}


//It writes the information of Packets in csv
void PcapParsing::writeCSV()
{
	std::cout << " Start CSV" <<endl;
	if(ethernet.typeOfIp==Ipv4)
	{
		fout << packet.timeStampsec <<",";
		fout << "IPv4"<<",";
		fout << ipv4Address(ip4.sourceAddress)<<",";
		fout << ipv4Address(ip4.destinationAddress)<<",";
		if(ip4.protocol==UDP)
		{
			fout << "UDP"<<",";
			fout << udp.sourcePort<<",";
			fout << udp.destinationPort<<",";
		}	
		else if(ip4.protocol==TCP)
		{	fout << "TCP"<<",";
			fout << tcp.sourcePort<<",";
			fout << tcp.destinationPort<<",";
		}				
	}
	else if(ethernet.typeOfIp==Ipv6)
	{
		fout << packet.timeStampsec <<",";
		fout << "IPv6"<<",";
		fout << ipv6Address(ip6.sourceAddress)<<",";
		fout << ipv6Address(ip6.destinAddress)<<",";
		if(ip6.nextHeader==UDP)
		{	fout << "UDP"<<",";
			fout << udp.sourcePort<<",";
			fout << udp.destinationPort<<",";
		}
		else if(ip6.nextHeader==TCP)
		{	fout << "TCP"<<",";
			fout << tcp.sourcePort<<",";
			fout << tcp.destinationPort<<",";
		}
	}
	fout <<"\n";
	
}


//It will maintain a map for unique ip and it's packet counts
void PcapParsing::uniqueIP(unordered_map<string,int> &uniqueIPmap)
{
	std::cout<< " 123 "<<endl;
	string sourceIP="";
	string destinIP="";
	
	if(ethernet.typeOfIp==Ipv4)
	{
		cout<<"//Stores Source Ip address";
		sourceIP=ipv4Address(ip4.sourceAddress);
		//Stores Destination Ip address
		destinIP=ipv4Address(ip4.destinationAddress);
		
		if(uniqueIPmap.find(sourceIP)!=uniqueIPmap.end())
		{
			auto add=uniqueIPmap.find(sourceIP);
			add->second++;
		}
		else
			uniqueIPmap.insert({sourceIP,1});
			
		if(uniqueIPmap.find(destinIP)!=uniqueIPmap.end())
		{
			auto add=uniqueIPmap.find(destinIP);
			add->second++;
		}
		else
			uniqueIPmap.insert({destinIP,1});
	}
	else if(ethernet.typeOfIp==Ipv6)
	{
		//Stores Source Ip address
		sourceIP=ipv6Address(ip6.sourceAddress);
		//Stores Destination Ip address
		destinIP=ipv6Address(ip6.destinAddress);
		
		if(uniqueIPmap.find(sourceIP)!=uniqueIPmap.end())
		{
			auto add=uniqueIPmap.find(sourceIP);
			add->second++;
		}
		else
			uniqueIPmap.insert({sourceIP,1});
			
		if(uniqueIPmap.find(destinIP)!=uniqueIPmap.end())
		{	
			auto add=uniqueIPmap.find(destinIP);
			add->second++;
		}
		else
			uniqueIPmap.insert({destinIP,1});
	}
	
}

//defining the function to show map for unique IP packet count 
void PcapParsing::showMap(unordered_map<string,int> &uniqueIPmap)
{
	std::cout<< "MAP 123456 "<<endl;
	//using iterator 
	unordered_map<string,int>::iterator itr=uniqueIPmap.begin();
	
	cout<< "Map having key as Unique IP and value as Packet count" <<endl;
	while(itr!=uniqueIPmap.end())
	{	
		cout << itr->first <<" : "<<itr->second << endl;
		
		//increase pointer
		itr++;
	}
	
}

//It converts ipv4 formate and returns string to write in csv
string PcapParsing::ipv4Address(unsigned short *ip)
{
	stringstream stream1;
	for(int i =0 ; i<4 ; i++)
	{
		string string1;
		string1=to_string(ip[i]);
		stream1 << string1;
		stream1 << ".";
	}
	return stream1.str();
}

//It converts ipv6 formate and returns string to write in csv
string PcapParsing::ipv6Address(unsigned short *ip)
{
	stringstream stream1;
	for(int i=0;i<8;i++)
	{
		stream1 << hex << ip[i];

		stream1 << ":";
	}
	return stream1.str();
}

