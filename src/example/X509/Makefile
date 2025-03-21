CXX = g++
CXXFLAGS = -std=c++11 -Wall

all: main

main: main.cpp 
	$(CXX) $(CFLAGS) -I/functions -o main main.cpp -lssl -lcrypto -g

clean:
	rm -f main