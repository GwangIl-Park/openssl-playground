CXX = g++
CXXFLAGS = -std=c++11 -Wall

all: server client

server: server.cpp 
	$(CXX) $(CFLAGS) -o server server.cpp -lssl -lcrypto

client: client.cpp 
	$(CXX) $(CFLAGS) -o client client.cpp -lssl -lcrypto

clean:
	rm -f server client