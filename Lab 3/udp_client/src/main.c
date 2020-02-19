// Client-side UDP Code 
// Written by Sarvesh Kulkarni <sarvesh.kulkarni@villanova.edu>
// Modified by Chris Auslander
// Adapted for use from "Beej's Guide to Network Programming" (C) 2017


#include <stdio.h>		// Std i/o libraries - obviously
#include <stdlib.h>		// Std C library for utility fns & NULL defn
#include <unistd.h>		// System calls, also declares STDOUT_FILENO
#include <errno.h>	    // Pre-defined C error codes (in Linux)
#include <string.h>		// String operations - surely, you know this!
#include <sys/types.h>  // Defns of system data types
#include <sys/socket.h> // Unix Socket libraries for TCP, UDP, etc.
#include <netinet/in.h> // INET constants
#include <arpa/inet.h>  // Conversion of IP addresses, etc.
#include <netdb.h>		// Network database operations, incl. getaddrinfo

// Our constants ..
#define MAXBUF 10000      // 4K max buffer size for i/o over nwk
#define SRVR_PORT "5555"  // the server's port# to which we send data
						  // NOTE: ports 0 -1023 are reserved for superuser!

// Structure of first packet received.
typedef struct fPacket {
	char fileSize[4];
	char chkSum[4];
	char fileName[92];
} fPacket;

// Structure of second and beyond packets received.
typedef struct genPacket {
	char packetNum[2];
	char lpFlag;
	char payloadSize[3];
	char dataPayload[100];
} genPacket;

// Convert the data received in packet to a usable form
// Returns the data at a given location as an integer value
int data_to_num(char* start, int len){
	char temp[len];
	memcpy(temp, start, len);
	temp[len] = '\0';
	int num = atoi(temp);
	return num;
}

genPacket* inc_packet_space(genPacket* oldStorage, int prevSize, int incr){
	genPacket* newStorage = malloc(sizeof(genPacket) * (prevSize+incr));
	memcpy(newStorage, oldStorage, sizeof(genPacket) * prevSize);
	free(oldStorage);
	return newStorage;
}


int main(int argc, char *argv[]) {
	
    int sockfd;			 // Socket file descriptor; much like a file descriptor
    struct addrinfo hints, *servinfo, *p; // Address structure and ptrs to them
    int rv, nbytes, nread;

    if (argc != 3) {
        fprintf(stderr,"ERROR! Correct Usage is: ./program_name server userid\n"
		        "Where,\n    server = server_name or ip_address, and\n"
		        "    userid = your LDAP (VU) userid\n");
        exit(1);
    }

	// First, we need to fill out some fields of the 'hints' struct
    memset(&hints, 0, sizeof hints); // fill zeroes in the hints struc
    hints.ai_family = AF_UNSPEC;     // AF_UNSPEC means IPv4 or IPv6; don't care
    hints.ai_socktype = SOCK_DGRAM;  // SOCK_DGRAM means UDP

	// Then, we call getaddrinfo() to fill out other fields of the struct 'hints
	// automagically for us; servinfo will now point to the addrinfo structure
	// of course, if getaddrinfo() fails to execute correctly, it will report an
	// error in the return value (rv). rv=0 implies no error. If we do get an
	// error, then the function gai_strerror() will print it out for us
    if ((rv = getaddrinfo(argv[1], SRVR_PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // We start by pointing p to wherever servinfo is pointing; this could be
	// the very start of a linked list of addrinfo structs. So, try every one of
	// them, and open a socket with the very first one that allows us to
	// Note that if a socket() call fails (i.e. if it returns -1), we continue
	// to try opening a socket by advancing to the next node of the list
	// by means of the stmt: p = p->ai_next (ai_next is the next ptr, defined in
	// struct addrinfo).
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("CLIENT: socket");
            continue;
        }

        break;
    }

	// OK, keep calm - if p==NULL, then it means that we cycled through whole
	// linked list, but did not manage to open a socket! We have failed, and
	// with a deep hearted sigh, accept defeat; with our tail between our legs,
	// we terminate our program here with error code 2 (from main).
    if (p == NULL) {
        fprintf(stderr, "CLIENT: failed to create socket\n");
        return 2;
    }

	// If p!=NULL, then things are looking up; the OS has opened a socket for
	// us and given us a socket descriptor. We are cleared to send! Hurray!
	// The sendto() function will report how many bytes (nbytes) it sent; but a
	// negative value (-1) means failure. Sighhh. 
    if ((nbytes = sendto(sockfd, argv[2], strlen(argv[2]), 0,
             p->ai_addr, p->ai_addrlen)) == -1) {
        perror("CLIENT: sendto");
        exit(1);
    }

	// Recv packet from server. YOu should modify this part of the program so that
	// you can receive more than 1 packet from the server. In fact, you should
	// call recvfrom() repeatedly till all parts of the file have been received.

	//Create structure locations to store data into.
	fPacket fp;
	genPacket gp;
	genPacket *packetArr = malloc(sizeof(genPacket)*10);
	int packetCount = 0;
	int arrSize = 10;
	
	//Read the first packet and store in first packet structure.
	nread = recvfrom(sockfd,&fp,sizeof(fPacket),0,NULL,NULL);
	if (nread<0) {
		perror("CLIENT: Problem in recvfrom");
		exit(1);
	}

	//Get total size of file
	int fileSize = data_to_num(fp.fileSize, sizeof(fp.fileSize));

	//Initialize counter of bytes received
	int byteCount = 0;

	//Read packets into general packet structure until the final packet field is '1'.
	//Stream the payloads into the buffer to build the correct output.
	do{
		nread = recvfrom(sockfd,&gp,sizeof(genPacket),0,NULL,NULL);
		if (nread<0) {
			perror("CLIENT: Problem in recvfrom");
			exit(1);
		}

		//Get size of the payload
		int size = data_to_num(gp.payloadSize, sizeof(gp.payloadSize));
		
		//Get packet number
		int packetNum = data_to_num(gp.packetNum, sizeof(gp.packetNum));
		++packetCount;
		if(packetCount % 10 == 0){
			inc_packet_space(packetArr, arrSize, 10);
			arrSize += 10;
		}

		//Copy the packet to its new location and clear the packet buffer
		memcpy(&packetArr[packetNum], &gp, sizeof(genPacket));
		memset(&gp, 0, sizeof(genPacket));

		byteCount += size;
	}
	while(byteCount < fileSize);

	//Create a writeable buffer of the data
	char buf[fileSize];
	int bufloc = 0;
	for(int i=0;i<packetCount;++i){
		int size = data_to_num(packetArr[i].payloadSize, sizeof(gp.payloadSize));
		memcpy(buf+bufloc, packetArr[i].dataPayload, size);
		bufloc += size;
	}
	
	//Write the output to a new file based on the name received.
	FILE* fPtr;
	char fn[sizeof(fp.fileName)] = "data_files/";
	strcat(fn, fp.fileName);
    fPtr = fopen(fn, "w");
	if(fPtr == NULL)
    {
        //File not created
		printf("Unable to create file\n");
        exit(1);
    }
	fputs(buf, fPtr);
    fclose(fPtr);

	free(packetArr);

	// AFTER all packets have been received ....
	// free up the linked-list memory that was allocated for us so graciously
	// getaddrinfo() above; and close the socket as well - otherwise, bad things
	// could happen
    freeaddrinfo(servinfo);
    close(sockfd);

	printf("\n\n"); // So that the new terminal prompt starts two lines below
	
    return 0;
}