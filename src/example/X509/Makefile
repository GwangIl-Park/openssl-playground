CXX = g++
CXXFLAGS = -std=c++11 -Wall

all: x509

x509: x509.cpp 
	$(CXX) $(CFLAGS) -o x509 x509.cpp -lssl -lcrypto -g

clean:
	rm -f x509