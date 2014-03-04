CC=g++
CFLAGS=-c -Wall
LDFLAGS=-lpcap
SOURCES=sniffer.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=sniffer
BUILDDIR=build/
SRCDIR=src/

all: a

a: $(SOURCES) $(EXECUTABLE) clean
	
$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm *.o

