CXX = g++
CXXFLAGS = -std=c++11 -Wall

all: ssl_ctx

ssl_ctx: ssl_ctx.cpp 
	$(CXX) $(CFLAGS) -o ssl_ctx ssl_ctx.cpp -lssl -lcrypto -g

clean:
	rm -f ssl_ctx