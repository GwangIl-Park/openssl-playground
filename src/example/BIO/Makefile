CXX = g++
CXXFLAGS = -std=c++11 -Wall

all: bio

bio: bio.cpp 
	$(CXX) $(CFLAGS) -o bio bio.cpp -lssl -lcrypto -g

clean:
	rm -f bio