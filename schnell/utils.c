
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/file.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <sys/utsname.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "utils.h"

short DEBUGLEVEL=0;

char SLURPIE_TOKEN_SEPARATOR[]=" \n\r";
int char_is_token_separator(char ch);

const char* skip_ws(const char* rv) {
	while(char_is_token_separator(*rv))
		rv++;
	return rv;
}
const char* skip_nws(const char* rv) {
	while(*rv && !char_is_token_separator(*rv))
		rv++;
	return rv;
}

int timeout_connect(int fd, struct sockaddr* addr, int mstimeout) {
  int ret;
  int flags;
  fd_set fds;
  struct timeval tv;


  if(mstimeout < 0)
    return -1;

  if((flags = fcntl(fd, F_GETFL)) < 0) {
    Dprintf("timeout_connect: unable to get socket flags\n");
    return -1;
  }
  if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    Dprintf("timeout_connect: unable to put the socket in non-blocking mode\n");
    return -1;
  }
  FD_ZERO(&fds);
  FD_SET(fd, &fds);

  if(mstimeout >= 0) {
    tv.tv_sec = mstimeout / 1000;
    tv.tv_usec = (mstimeout % 1000) * 1000;
    
    errno = 0;
    
    if(connect(fd, addr, sizeof(struct sockaddr)) < 0) {
      if((errno != EWOULDBLOCK) && (errno != EINPROGRESS)){
	Dprintf("timeout_connect: error connecting: %d\n", errno);
	return -1;
      }
    }
#ifdef NOTIMEOUTS
    ret = select(fd+1, NULL, &fds, NULL, NULL);
#else
    ret = select(fd+1, NULL, &fds, NULL, &tv);
#endif
  }
  // Restore the socket's original flags (back to blocking mode)
  fcntl(fd, F_SETFL, flags);

  if(ret != 1) {
    if(ret == 0)
      return -1;
    else
      return ret;
  }
  return 0;
}

int timeout_read(int * status, int fd, void *buf , int len , int mstimeout){
	int ret;
	fd_set fds;
	struct timeval tv;

	FD_ZERO(&fds);
	FD_SET(fd,&fds);
	*status=0;

	if(mstimeout>=0){
		tv.tv_sec = mstimeout/1000;;
		tv.tv_usec = (mstimeout%1000)*1000;

#ifdef NOTIMEOUTS
		ret = select(fd+1, &fds,NULL,NULL,NULL);
#else
		ret = select(fd+1, &fds,NULL,NULL,&tv);
#endif
		if(ret!=1){
			if(ret==0)
		       		return -1;
			else 
		 		return ret;	// catches timeouts and errs
		}
	}

	*status=read(fd,buf,len);
	return 0;
}

/* timeout_readall():
 * 	keep read()'ing until 'len' amount of data is read
 */

int timeout_readall(int * status, int fd, void *buf , int len , int mstimeout){
	int count=0;
	int err;

	while(count< len){
		err = timeout_read(status,fd,buf+count,len-count,mstimeout);
		if(err!=0)
			return err;
		if(*status<=0)
			return 0;
		count+=*status;
	}

	*status=count;  // make it look like we read it all at once
	return 0;
}

int char_is_eoln(char ch){
	/* 	CHANGING this so that HTTP stuff will work better
	int i;
	for(i=0;i<strlen(EOLN);i++)
		if(ch == EOLN[i])
	*/
	if(ch == '\n')
			return 1;
	else 
		return 0;
}

int char_is_token_separator(char ch){
	int i;
	for(i=0;i<strlen(SLURPIE_TOKEN_SEPARATOR);i++)
		if(ch == SLURPIE_TOKEN_SEPARATOR[i])
			return 1;
	return 0;
}

int timeout_read_token(int * status, int fd, void *vbuf , int len , int mstimeout){
	int ret;
	fd_set fds;
	struct timeval tv;
	int i;
	char * buf;

	FD_ZERO(&fds);
	FD_SET(fd,&fds);
	*status=0;
	buf=vbuf;

	if(mstimeout>=0){
		tv.tv_sec = mstimeout/1000;;
		tv.tv_usec = (mstimeout%1000)*1000;
#ifdef NOTIMEOUTS
		ret = select(fd+1, &fds,NULL,NULL,NULL);
#else
		ret = select(fd+1, &fds,NULL,NULL,&tv);
#endif
		if(ret!=1){
			if(ret==0)
		       		return -1;
			else 
		 		return ret;	// catches timeouts and errs
		}
	}

	for(i=0;i<len;i++){
		*status=read(fd,&buf[i],1);
		if(*status<=0){
			buf[i]='\0';
			return 0;
		}
		if(char_is_token_separator(buf[i])){
			if(i == 0){	// skip leading token separators
				i--;
				continue;
			}
			buf[i]='\0';
			return 0;
		}
	}
	*status=i;	// to emulate this as if it were one read()
	return 0;
}


int timeout_write(int * status, int fd, const void *buf , int len , int mstimeout){
	int ret;
	fd_set fds;
	struct timeval tv;

	FD_ZERO(&fds);
	FD_SET(fd,&fds);
	*status=0;

	if(mstimeout>=0){
		tv.tv_sec = mstimeout/1000;;
		tv.tv_usec = (mstimeout%1000)*1000;

#ifdef NOTIMEOUTS
		ret = select(fd+1, NULL,&fds,NULL,NULL);
#else
		ret = select(fd+1, NULL,&fds,NULL,&tv);
#endif
		if(ret!=1) { 	// catches timeouts and errs
			if(ret==0) 
				return -1;
			else 
				return ret;	
		}
	}

	*status=write(fd,buf,len);
	return 0;
}

int timeout_writeall(int * status, int fd, const void *buf , int len , int mstimeout){
	int count=0;
	int err;

	while(count< len){
		err = timeout_write(status,fd,buf+count,len-count,mstimeout);
		if(err!=0)
			return err;
		if(*status<=0)
			return 0;
		count+=*status;
	}

	*status=count;	// make it look like we wrote it all at once
	return 0;
}
		

	


int timeout_read_line(int * status, int fd, void * vbuf, int len , int mstimeout){
	int ret;
	fd_set fds;
	struct timeval tv;
	int i;
	char * buf;

	FD_ZERO(&fds);
	FD_SET(fd,&fds);
	*status=0;
	buf=vbuf;

	if(mstimeout>=0){
		tv.tv_sec = mstimeout/1000;;
		tv.tv_usec = (mstimeout%1000)*1000;

#ifdef NOTIMEOUTS
		ret = select(fd+1, &fds,NULL,NULL,NULL);
#else
		ret = select(fd+1, &fds,NULL,NULL,&tv);
#endif
		if(ret!=1){
			if(ret==0)
		       		return -1;
			else 
		 		return ret;	// catches timeouts and errs
		}
	}

	for(i=0;i<len;i++){
		*status=read(fd,&buf[i],1);
		if(*status<=0){
			buf[i]='\0';
			return 0;
		}
		if(buf[i]=='\r')	// horrible hack :( :(
			buf[i]='\0';
		if(char_is_eoln(buf[i])){
			if(i == 0){	// skip leading token separators
				i--;
				continue;
			}
			buf[i]='\0';
			return 0;
		}
	}
	*status=i;	// to emulate this as if it were one read()
	return 0;
}

/* skip_to_eoln(fd,mstimeout):
 * 	just throw away all of the chars from the passed fd until EOLN
 * 	is hit
 */

int skip_to_eoln(int fd,int mstimeout){
	char buf[BUFLEN];
	int status;

	return timeout_read_line(&status, fd, buf, BUFLEN , mstimeout);
}


/* int fdgets(int fd, char *buf, int len);
 * 	like fgets(), but on fd's instead of FILE *'s
int fdgets(int fd, char *buf, int len){
	int i,err;
	char ch;
	for(i=0;i<len;i++){
		err = read(fd,&ch,1);
		if(err!=1){
			buf[i]=0;	// terminate, and return
			return err;
		}
		if((buf[i]=ch) == '\n')
	UNFINISHED!
 */

/* int make_tcp_server(unsigned short port)
 * opens a listening server on port 'port'
 * return <=0 on error
 */
int make_tcp_server(unsigned short* port) {
	int s;
	struct sockaddr_in sin;
	unsigned int val;
	int ret;

	s = socket(PF_INET,SOCK_STREAM,0);
	if(s<=0){
		perror("bindsock: socket");
		return s;
	}
	sin.sin_addr.s_addr=INADDR_ANY;
	sin.sin_family=AF_INET;
	sin.sin_port=htons(*port);

	val=1;

	ret=setsockopt(s,SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	if(ret){
		perror("bindsock: setsockopt");
		close(s);
		return ret;
	}

	ret=bind(s,(struct sockaddr *)&sin, sizeof(sin));
	if(ret<0){
		perror("bindsock: bind");
		close(s);
		return ret;
	}
	if((ret=listen(s,DEFAULTBACKLOG))){
		perror("bindsock: listen");
		close(s);
		return -1;
	}

	val = sizeof(sin);
	if ((ret=getsockname(s, (struct sockaddr *)&sin, &val))) {
		perror("bindsock: getsockname");
		close(s);
		return -1;
	}
	*port = ntohs(sin.sin_port);

	return s;
}

/* int make_tcp_connection(char * hostname, unsigned short port)
 * 	make a tcp connection to hostname:port
 *	returns <=0 on error
 */
int make_tcp_connection(const char * hostname, unsigned short port) {
	return make_tcp_connection_from_port_with_options(hostname,port,0,-1,-1);
}
int make_tcp_connection_with_port(const char * hostname, unsigned short port,unsigned short sport) {
	return make_tcp_connection_from_port_with_options(hostname,port,sport,-1,-1);
}
int make_tcp_connection_from_port_with_options(const char * hostname, unsigned short port,unsigned short sport,
		int mss, int bufsize) {

	struct hostent h, *res;
	struct sockaddr_in sin,local;
	int s;
	int err;
	char tmpbuf[HBUFLEN];
	int zero = 0;

	if (gethostbyname_r(hostname, &h, tmpbuf, HBUFLEN, &res, &err)) {
		return -1;	// bad host
	}
	memcpy(&sin.sin_addr, res->h_addr, sizeof(sin.sin_addr));	
	sin.sin_family=PF_INET;
	sin.sin_port=htons(port);

	s = socket(AF_INET,SOCK_STREAM,0);
	if(s<0){
		perror("make_tcp_connection: socket");
		return -2;	// bad socket
	}
	if(setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &zero, sizeof(zero)) < 0)
	  Dprintf("make_tcp_connection::Unable to disable Nagle's algorithm\n");
	if(mss>0){
		if(setsockopt(s, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss)) < 0)
			  fprintf(stderr,"make_tcp_connection::Unable to set MSS to %d\n",mss);
	}
	if(bufsize>0){
		if(setsockopt(s, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize)) < 0)
		  fprintf(stderr,"make_tcp_connection::Unable to set snd buf to %d\n",bufsize);
		if(setsockopt(s, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize)) < 0)
		  fprintf(stderr,"make_tcp_connection::Unable to set snd buf to %d\n",bufsize);
	}
	local.sin_family=PF_INET;
	local.sin_addr.s_addr=INADDR_ANY;
	local.sin_port=htons(sport);

	err=bind(s,(struct sockaddr *)&local, sizeof(local));
	if(err){
		perror("make_tcp_connection_from_port::bind");
		return -4;
	}

	err = timeout_connect(s,(struct sockaddr *) & sin, CONNECT_TIMEOUT);

	if(err){
		//perror("make_tcp_connection: connect");
		close(s);
		return -3;	// bad connect
	}

	return s;		// return connected socket
}

/******* NUKED, cuz we changed gethostbyname() symantics
 *	and it is redundant with getLocalHostIP()
char** my_addrs(int* addrtype) {
	struct hostent h, *hptr;
	struct utsname myname;
	char tmpbuf[HBUFLEN];
	int err;
	if (uname(&myname) < 0)
		return NULL;

	if (gethostbyname_r(myname.nodename, &h, tmpbuf, HBUFLEN, &hptr, &err))
		return NULL;

	*addrtype = hptr->h_addrtype;
	return (hptr->h_addr_list);
}
*/

/* unsigned int getLocalHostIP();
 * 	just return the unsigned int of the ip
 */
unsigned int getLocalHostIP(){
	char buf[BUFLEN];
	struct hostent h, *hptr;
	char tmpbuf[HBUFLEN];
	int err;
	unsigned int ret;
	assert(!gethostname(buf,BUFLEN));
	gethostbyname_r(buf, &h, tmpbuf, HBUFLEN, &hptr, &err);
	assert(hptr != NULL);
	memcpy(&ret, hptr->h_addr, sizeof(ret));
	return ret;
}
	


/* unittests:
*/

int do_utils_tests(){
	int sock;
	char buf[BUFLEN];
	int err,status;
	unsigned int ip;
	char dquad[20];

	//char** myaddrs = my_addrs(&addrtype);
	ip = getLocalHostIP();
	inet_ntop(AF_INET, &ip, dquad, 20);

	printf("IPAddr %s\n", dquad);

	assert(strcmp("bleh", skip_ws("    bleh")) == 0);

	sock= make_tcp_connection("time.nist.gov",13);
	assert(sock>0);
	err=timeout_read_line(&status,sock,buf,BUFLEN,10000);
	assert(!err);
	assert(status>0);
	fprintf(stderr,"Time is: %s\n",buf);

	return 0;
}





