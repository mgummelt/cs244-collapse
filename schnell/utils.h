#ifndef UTILS_H
#define UTILS_H

#include <arpa/inet.h>
extern char SLURPIE_TOKEN_SEPARATOR[]; 
#define EOLN    "\n\r"
#define FIELDSEPERATOR ", "

#ifndef BUFLEN
#define BUFLEN 4096
#endif

#ifndef HBUFLEN
#define HBUFLEN	BUFLEN
#endif

#define DEFAULTBACKLOG 100

#ifdef DEBUG
#define DEFAULTDEBUGLEVEL 1
#else
#define DEFAULTDEBUGLEVEL 0
#endif
extern short DEBUGLEVEL;

#ifndef CONNECT_TIMEOUT
#define CONNECT_TIMEOUT 5000
#endif

#ifndef MAX
#define MAX(x,y) ((x)>(y)?(x):(y))
#endif
#ifndef MIN
#define MIN(x,y) ((x)>(y)?(y):(x))
#endif


// Skips the ws on the char* 
const char* skip_ws(const char*);
const char* skip_nws(const char*);
int timeout_connect(int fd, struct sockaddr* addr, int mstimeout);
// returns non-zero if select failed/timed out, otherwise returns zero and
// *status is the return from read()
int timeout_read(int * status, int fd, void *buf , int len , int mstimeout);

int timeout_readall(int * status, int fd, void *buf , int len , int mstimeout);

// same as timeout_read, but only reads up until NICE_TOKEN_SEPARATOR
int timeout_read_token(int * status, int fd, void *buf , int len , int mstimeout);

// returns non-zero if select failed/timed out, otherwise returns zero and
// *status is the return from write()
int timeout_write(int * status, int fd, const void *buf , int len , int mstimeout);

// iterate over timeout_write until everything is written
int timeout_writeall(int * status, int fd, const void *buf , int len , int mstimeout);

int timeout_read_line(int * status, int fd, void * vbuf, int len , int mstimeout);
int skip_to_eoln(int fd,int mstimeout);

// make a tcp server at port. If port is 0 then upon a valid return it will containg
// the port that the server is listening at
//  if return <=0, it's an error, else it is a valid fd
int make_tcp_server(unsigned short* port);

// make a tcp connection to hostname:port
// 	if return <=0, it's an error, else it is a valid fd
int make_tcp_connection(const char * hostname, unsigned short port);
int make_tcp_connection_from_port(const char * hostname, unsigned short port, unsigned short sport);
int make_tcp_connection_from_port_with_options(const char * hostname, unsigned short port,unsigned short sport,
		int mss, int bufsize);

// Get My addrs
char** my_addrs(int *addrtype);

unsigned int getLocalHostIP();

int do_utils_tests();


#define Dprintf(x...) Dprintf2(1,x)
#define Dprintf2(n,x...) do { if(DEBUGLEVEL>=n){ fprintf(stderr,"DEBUG: ");fprintf(stderr,x);} } while(0)

#endif
