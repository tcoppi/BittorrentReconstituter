CPP=g++
CFLAGS=-Wall -g
OBJFLAGS=-c

OBJS=Session.o SessionFinder.o PacketHandler.o Piece.o
all: $(OBJS)

PacketHandler.o: PacketHandler.cpp PacketHandler.hpp headers.hpp \
  Packet.hpp Piece.hpp
Piece.o: Piece.cpp Piece.hpp
Session.o: Session.cpp Session.hpp Piece.hpp Peer.hpp
SessionFinder.o: SessionFinder.cpp SessionFinder.hpp Packet.hpp Piece.hpp \
  Session.hpp Peer.hpp headers.hpp

clean:
	rm -rf *.o
