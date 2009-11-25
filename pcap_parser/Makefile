CPP=g++
CFLAGS=-Wall -g
OBJFLAGS=-c

OBJS=Session.o SessionFinder.o PacketHandler.o
all: $(OBJS)

SessionFinder.o: SessionFinder.cpp SessionFinder.hpp headers.hpp
PacketHandler.o: PacketHandler.cpp PacketHandler.hpp headers.hpp
Session.o: Session.cpp Session.hpp

clean:
	rm -rf *.o
