CXX = g++
CXXFLAGS = -std=c++11 -Wall

all: server client

server: server.cpp 
	$(CXX) $(CFLAGS) -o server server.cpp -lssl -lcrypto -g

client: client.cpp 
	$(CXX) $(CFLAGS) -o client client.cpp -lssl -lcrypto -g

clean:
	rm -f server client