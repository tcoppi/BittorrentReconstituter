CXX=g++
CXXFLAGS=-Wall -g
OBJFLAGS=-c

OBJS=Reconstructor.o
all: $(OBJS)

Reconstructor.o: Reconstructor.cpp Reconstructor.hpp ../pcap_parser/Session.o

clean:
	rm -rf *.o
