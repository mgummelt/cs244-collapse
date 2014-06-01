# schnell DoS; capveg 03 -- Do Not Distribute!
CFLAGS+=-Wall
CFLAGS+=-g
LDFLAGS+=-g
#CFLAGS+=-pg
#LDFLAGS+=-pg
CC=gcc
VPATH=.
TARGET=optack


SRC=$(wildcard $(VPATH)/*.c)
HDRS=$(wildcard include/*.h)
OBJS=$(subst $(VPATH)/,,$(subst .c,.o,$(SRC)))
LIBS+=-lm
LIBS+=-lpthread 
LIBS+=-lpcap
#LIBS+=$(TOP)/libNice/libNice.a



all: .depend tags $(TARGET)

ifeq (.depend,$(wildcard .depend))
include .depend
endif


$(TARGET): $(OBJS) 
	$(CC) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean: 
	@rm -f $(OBJS) core core.* $(TARGET) .depend tags
sclean: clean 
	@rm -rf outdir-*
crap: sclean cvs all
	

count:
	@wc -l $(SRC) $(HDRS) Makefile 

.depend: $(SRC) $(HDRS)
	@$(CC) -M $(CFLAGS) $(SRC)  > .depend

tags: $(SRC) $(HDRS)
	@ctags $(SRC) $(HDRS)

cvs: 
	cvs update

debug: 
	@echo OBJ=$(OBJS)
