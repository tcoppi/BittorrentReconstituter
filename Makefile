CPP=g++
CXX=g++
CXXFLAGS=-Wall -g
OBJFLAGS=-c
OSNAME := $(shell uname -s)
ifeq ($(OSNAME),Darwin)
	LIBS=-L/opt/local/lib -lboost_program_options-mt -lboost_serialization-mt -lpcap -lcrypto
else
	LIBS=-lboost_program_options-mt -lboost_serialization-mt -lpcap -lcrypto
endif
PCAPOBJECTS=./pcap_parser/PacketHandler.o ./pcap_parser/SessionFinder.o \
  ./pcap_parser/Session.o ./pcap_parser/Piece.o
FILERECONSTOBJECTS=./file_reconstituter/Reconstructor.o
SUBDIRS = pcap_parser file_reconstituter
.PHONY: subdirs $(SUBDIRS) clean

all: subdirs btfinder

btfinder: driver.o $(PCAPOBJECTS) $(FILERECONSTOBJECTS)
ifeq ($(OSNAME),Darwin)
	$(CPP) $(CXXFLAGS) -o btfinder -I/opt/local/include $(LIBS) $(PCAPOBJECTS) $(FILERECONSTOBJECTS) driver.o
else
	$(CPP) $(CXXFLAGS) -o btfinder $(LIBS) $(PCAPOBJECTS) $(FILERECONSTOBJECTS) driver.o
endif

driver.o: driver.cpp pcap_parser/SessionFinder.hpp pcap_parser/Packet.hpp \
  pcap_parser/Piece.hpp pcap_parser/Session.hpp pcap_parser/Peer.hpp \
  pcap_parser/PacketHandler.hpp

subdirs: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

# The rest of these targets are for convenience
tags:
	ctags `find . -iname '*.[c,h]pp'`

goodtags:
	etags $(find . -name "*.c" -o -name "*.cpp" -o -name "*.h")

apidocs:
	doxygen

clean:
	find . -iname '*.o' -print0 | xargs -0 rm -f
	rm -f btfinder
