#ifndef MINDELAY_H
#define MINDELAY_H

// for Linux, the min realiable delay we get from nanosleep() is 20MS or 20,000 uS
#ifdef linux
#define MINDELAY 20000
#else
#error "No Min Reliable Delay Known for This OS; Set in mindelay.h"
#endif

#endif
