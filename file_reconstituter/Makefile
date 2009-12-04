CXX=g++
CXXFLAGS=-Wall -g
OBJFLAGS=-c

OBJS=Reconstructor.o Torrent.o
all: $(OBJS)

Reconstructor.o: Reconstructor.cpp Reconstructor.hpp \
  ../pcap_parser/Session.hpp ../pcap_parser/Piece.hpp \
  ../pcap_parser/Peer.hpp ../pcap_parser/Piece.hpp \
  ../pcap_parser/Peer.hpp
Torrent.o: Torrent.cpp Torrent.hpp 

clean:
	rm -rf *.o
