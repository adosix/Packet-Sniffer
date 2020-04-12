
SNIFFER          = sniffer
SNIFFER_SOURCES  = sniffer.cpp

DEFINES         =
CFLAGS         = -g
LIBRARIES       = #-library_name

CC              = g++
SNIFFER_OBJECTS  = $(SNIFFER_SOURCES:.cpp=.o)
INCLUDES        = #-I.
LIBDIRS         =
LDFLAGS         = $(LIBDIRS) $(LIBRARIES)


.SUFFIXES: .cpp .o

.cpp.o:
		$(CC) $(CFLAGS) -c $<

all:		$(SNIFFER) 

rebuild:	clean all

$(SNIFFER):	$(SNIFFER_OBJECTS)
		$(CC) -g $(SNIFFER_OBJECTS) $(LDFLAGS) -o $@

clean:
	rm -fr core* *~ $(SNIFFER_OBJECTS) $(SNIFFER) .make.state .sb