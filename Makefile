CPP=g++
CFLAGS=-Wall -g
OBJFLAGS=-c
OSNAME := $(shell uname -s)

ifeq ($(OSNAME),Darwin)
	LIBS=-L/opt/local/lib -lboost_program_options-mt -lpcap
else
	LIBS=-lboost_program_options-mt -lpcap
endif

PCAPOBJECTS=./pcap_parser/PacketHandler.o ./pcap_parser/SessionFinder.o
FILERECONSTOBJECTS=


SUBDIRS = pcap_parser file_reconstituter
.PHONY: subdirs $(SUBDIRS) clean

all: subdirs btfinder

btfinder: driver.o
ifeq ($(OSNAME),Darwin)
	$(CPP) $(CFLAGS) -o btfinder -I/opt/local/include $(LIBS) $(PCAPOBJECTS) $(FILERECONSTOBJECTS)
else
	$(CPP) $(CFLAGS) -o btfinder $(LIBS) $(PCAPOBJECTS) $(FILERECONSTOBJECTS)
endif

driver.o: driver.cpp
ifeq ($(OSNAME),Darwin)
	$(CPP) $(CFLAGS) $(OBJFLAGS) -I/opt/local/include $(LIBS) driver.cpp
else
	$(CPP) $(CFLAGS) $(OBJFLAGS) $(LIBS) driver.cpp
endif

subdirs: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

tags:
	ctags `find . -iname '*.[c,h]pp'`

apidocs:
	doxygen
clean:
	find . -iname '*.o' -print0 | xargs -0 rm -f
	rm -f btfinder
