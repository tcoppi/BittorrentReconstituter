CPP=g++
CFLAGS=-Wall -g
OBJFLAGS=-c
LIBS=-lpcap

PCAPOBJECTS = ./pcap_parser/PacketHandler.o ./pcap_parser/SessionFinder.o
FILERECONSTOBJECTS =

SUBDIRS = pcap_parser file_reconstituter
.PHONY: subdirs $(SUBDIRS) clean

all: subdirs btfinder

btfinder: driver.o
	$(CPP) $(CFLAGS) -o btfinder $(PCAPOBJECTS) $(FILERECONSTOBJECTS) $(LIBS)

driver.o: driver.cpp
	$(CPP) $(CFLAGS) $(OBJFLAGS) driver.cpp

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
