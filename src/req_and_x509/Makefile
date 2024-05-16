CXX = g++
CXXFLAGS = -std=c++11 -Wall

all: req_and_x509

req_and_x509: req_and_x509.cpp 
	$(CXX) $(CFLAGS) -o req_and_x509 req_and_x509.cpp -lssl -lcrypto -g

clean:
	rm -f req_and_x509