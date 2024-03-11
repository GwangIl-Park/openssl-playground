CXX = g++
CXXFLAGS = -std=c++11 -Wall

all: req

req: req.cpp 
	$(CXX) $(CFLAGS) -o req req.cpp -lssl -lcrypto -g

clean:
	rm -f req