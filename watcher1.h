/*
Runtime Monitoring of directory for events and handles the occurance of events
like file or directory creation, modification, deletion
*/

#include<sys/inotify.h>
#include<iostream>
#include<cstring>
#include<string>
#include<fstream>
#include<sstream>
#include<unistd.h>
#include<errno.h>
#include<sys/types.h>
#include<sys/inotify.h>
#include<limits.h> 
#include"pcapParsing.h"

#define MAX_EVENTS 1024 //Number of events to process
#define LEN_NAME 30 //For Length of file name
#define EVENT_SIZE  ( sizeof ( struct inotify_event )) //size of an event
#define BUF_LEN  (MAX_EVENTS * ( EVENT_SIZE + LEN_NAME ) ) /*buffer for event data*/

using namespace std;

PcapParsing pcapWatch;


int open_inotify_fd()
{
	
  	int fd=inotify_init();  //Initialize Inotify

  	if(fd<0) 
	 	cout<<"error in file descriptor"; 
 	else 
  		return fd;			//return file descriptor to watch
}

int events(int fd, const char *folder) 
{
  int length=0, i = 0, wd=0;
  
  char buffer[BUF_LEN];
  	char fileName[80];
  	string folderForcsv;
  
  //Adding watch for the given directory
  wd = inotify_add_watch(fd, folder, IN_CREATE | IN_MODIFY | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO); 
  
  
  //check if the watch is added successfully
  if (wd == -1)
    {
      cout <<"Couldn't add watch to \n"<<folder<<endl;
    }
  else
    {
      cout <<"Watching:\n"<<folder <<endl;
    }
 
  //Infinitely running loop for runtime watching
  while(1)
    {
      i = 0;
      //To read all bytes returned by read()
      
      length = read( fd, buffer, BUF_LEN );  
      //length  holds the no. of bytes read
	// To determine what events have occurred, reads from inotify file descriptor.
 folderForcsv="/home/leena";
 
      if ( length < 0 ) 
      {
        perror( "read" );
      }  
 
      while ( i < length ) 
      {
      	
        struct inotify_event *event = (struct inotify_event *) &buffer[i];
        if (event->len!=0) 
        {
        	//Event when folder and files created
          if ( event->mask & IN_CREATE) 
          {
            if (event->mask & IN_ISDIR)
              {
              	cout <<"The directory\n"<< event->name;
              	}      
            else
              {
  cout <<"The file" << event->name <<"was Created with WD\n" <<event->wd;
  				
  			pcapWatch.openfile(event->name,folder,folderForcsv.c_str());
  			pcapWatch.startParsing(); 
               }  
          }
          	//Event for folder and files if modified
           else if ( event->mask & IN_MODIFY) 
          {
            if (event->mask & IN_ISDIR)
              cout<<"The Folder was modified.\n" << event->name <<endl;       
            else
              cout <<"The file" << event->name <<"was modified with WD\n" <<event->wd;  
          }
          
		 	//Event when folder and files deleted and moved to trash
		 	else if(event->mask == IN_MOVED_FROM)
		 	{
		 		// no processing for directory events
			 	if(event->mask & IN_ISDIR)
			 	{   	
			 		cout<<"\n Folder was deleted "<<event->name<<IN_MOVED_FROM;  
			 	}
			 	else
			 	{	
			 		cout<<"\nFILE DELETED/FILE IS MOVED FROM WATCH DIR"
			 		<<event->name<<" "<<event->wd<< " "<<IN_MOVED_FROM; 
			 		  
			 	}
		 	}
		 	//Event when file or folder moved in the Watch directory
			else if(event->mask == IN_MOVED_TO )
			{
				// no processing for directory events
			 	if(event->mask & IN_ISDIR)
			 	{   	
			 		cout<<"\n Folder renamed or existing Folder copied"<<event->name<<IN_MOVED_TO;  
			 	}
			 	
			 	else
			 	{	
				 	cout<<"\n FILE RENAMED/FILE MOVED IN "<<event->name<<" "<<event->wd<< " "<<IN_MOVED_TO; 
				 		pcapWatch.openfile(event->name,folder,folderForcsv.c_str());
  					pcapWatch.startParsing(); 
			 	}
		 	}
		 	//Event for folder or file renamed
			else if(event->mask == IN_MOVE_SELF )
			{
			 	if(event->mask & IN_ISDIR)
			 	{   	
			 		cout<<"\n Folder renamed "<<event->name<<IN_MOVE_SELF;  
			 	}
			 	else
			 	{	
			 		cout<<"\n FILE RENAMED(IN_MOVE_SELF) "<<event->name<<" "<<event->wd<< " "<<IN_MOVE_SELF;  
			 	}
		 	}
		 	
		 	//display message for events not handled
			else 
			{
			 	cout<<"\n Event not matched!!"; 
			}
 			}
          i += EVENT_SIZE + event->len ;
        
      }
    }
 
  /* Clean up*/
  /*inotify_rm_watch( fd, wd );
  close( fd );*/
   
  return 0;
}
