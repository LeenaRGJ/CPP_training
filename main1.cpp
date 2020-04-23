/*
This is the main file in which the main thread calls ths PcapParsing class functions for parsing the files given in folder.
And another thread is created for watching the given Folder continuously.
*/

#include <iostream>
#include <pthread.h>
#include <cstdlib>
#include <fstream>
#include <string>
#include <dirent.h>
#include "watcher1.h"

using namespace std;

//defining function to start Watcher
void* func(void *folder)
{
    int fd=open_inotify_fd();
    events(fd,(const char*)folder);
}

int main()
{ 
	//thread object
	pthread_t t;
	//PcapParsing class object
	PcapParsing startparse;
	//const char *folder;
	//const char *csvfolder;
	string foldername;
	string csvFoldername;
	int choice=0,flag=1;
	
	//A do-while loop so user can parse multiple files of different folder
	do{
		cout <<"Enter folder Path where you want to keep CSV files \n";
		cin >> csvFoldername;			
		cout << "Enter 1 for folder Path of pcap files\nEnter 2 to exit \n" ;
		
		//Taking choice from user
		cin >>choice;
		
		switch(choice)
		{
			case 1:{
					cout << "Enter Folder Path\n";
					cin >> foldername;
					startparse.openFolder(foldername.c_str(),csvFoldername.c_str());

					cout <<"*******COMPLETE********"<<endl;

					pthread_create(&t, NULL, &func, (void*)(foldername.c_str())); 
			}break;
			case 2: flag=0;
					break;
			default: cout <<"Enter correct input \n";break;
		}
	}while(flag);
		
	//To Terminate the program 
	 exit(EXIT_SUCCESS);
    return 0;
}
