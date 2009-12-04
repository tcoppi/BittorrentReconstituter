CXX:=g++
CXXFLAGS:=-Wall -g
OBJFLAGS:=-c
OSNAME:=$(shell uname -s)
LIBS:=-lboost_program_options-mt -lboost_serialization-mt -lpcap -lcrypto
ifeq ($(OSNAME),Darwin)
	LIBS += -I/opt/local/include -L/opt/local/lib
endif
PCAPOBJECTS=./pcap_parser/PacketHandler.o ./pcap_parser/SessionFinder.o \
  ./pcap_parser/Session.o ./pcap_parser/Piece.o
FILERECONSTOBJECTS=./file_reconstituter/Reconstructor.o
SUBDIRS = pcap_parser file_reconstituter
.PHONY: subdirs $(SUBDIRS) tags goodtags apidocs clean

all: subdirs btfinder

btfinder: driver.o $(PCAPOBJECTS) $(FILERECONSTOBJECTS)
	$(CXX) $(CXXFLAGS) -o btfinder $(LIBS) $(PCAPOBJECTS) $(FILERECONSTOBJECTS) driver.o

driver.o: driver.cpp pcap_parser/SessionFinder.hpp pcap_parser/Packet.hpp \
  pcap_parser/Piece.hpp pcap_parser/Session.hpp pcap_parser/Peer.hpp \
  pcap_parser/PacketHandler.hpp file_reconstituter/Reconstructor.hpp \
  file_reconstituter/../pcap_parser/Session.hpp

subdirs: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@

# The rest of these targets are for convenience
tags:
	ctags `find . -iname '*.[c,h]pp'`
goodtags:
	etags $(find . -name "*.[c,h]pp")
apidocs:
	doxygen
clean:
	find . -iname '*.o' -print0 | xargs -0 rm -f
	rm -f btfinder
