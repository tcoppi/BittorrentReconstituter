CPP=g++
CFLAGS=-Wall -g
OBJFLAGS=-c

OBJS=SessionFinder.o PacketHandler.o
all: $(OBJS)

SessionFinder.o: SessionFinder.cpp SessionFinder.hpp headers.hpp
PacketHandler.o: PacketHandler.cpp PacketHandler.hpp headers.hpp

clean:
	rm -rf *.o