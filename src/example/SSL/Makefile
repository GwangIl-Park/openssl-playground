CXX = g++
CXXFLAGS = -std=c++11 -Wall

all: error

error: error.cpp 
	$(CXX) $(CFLAGS) -o error error.cpp -lssl -lcrypto -g

clean:
	rm -f error