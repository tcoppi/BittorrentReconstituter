CPP=g++
CFLAGS=-Wall -g
OBJFLAGS=-c

OBJS=Session.o SessionFinder.o PacketHandler.o
all: $(OBJS)

SessionFinder.o: SessionFinder.cpp SessionFinder.hpp Packet.hpp Piece.hpp \
  Session.hpp Peer.hpp headers.hpp
PacketHandler.o: PacketHandler.cpp PacketHandler.hpp headers.hpp \
  Packet.hpp Piece.hpp
Session.o: Session.cpp Session.hpp Piece.hpp Peer.hpp

clean:
	rm -rf *.o
