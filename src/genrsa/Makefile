CXX = g++
CXXFLAGS = -std=c++11 -Wall

all: genrsa

genrsa: genrsa.cpp 
	$(CXX) $(CFLAGS) -o genrsa genrsa.cpp -lssl -lcrypto -g

clean:
	rm -f genrsa