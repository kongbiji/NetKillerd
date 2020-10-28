TARGET=netkillerd
SRCS	=$(wildcard *.cpp)
OBJECTS	=$(SRCS:.cpp=.o)

CXXFLAGS+=-I/root/android/sysroot/include
LDFLAGS+=-L/root/android/sysroot/lib

LDLIBS+=-lpcap

all: $(TARGET)

$(TARGET) : $(OBJECTS)
	$(CXX) $(LDFLAGS) $(TARGET_ARCH) $(OBJECTS) $(LDLIBS) -o $(TARGET)

main.o: main.cpp
socket.o: socket.cpp socket.h
get_info.o: get_info.cpp get_info.h
arp_spoof.o: arp_spoof.cpp arp_spoof.h

clean:
	rm -f $(TARGET)
	rm -f *.o