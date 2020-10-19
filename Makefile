TARGET=netkillerd
OBJS=main.o socket.o get_info.o arp_spoof.o
CXXFLAGS+=-I../../android/sysroot/include
LDFLAGS+=-L../../android/sysroot/lib
LDLIBS+=-lpcap

all: $(TARGET)

$(TARGET) : $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

main.o: main.cpp
socket.o: socket.cpp
get_info.o: get_info.cpp
arp_spoof.o: arp_spoof.cpp

clean:
	rm -f $(TARGET)
	rm -f *.o
