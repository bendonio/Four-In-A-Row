CC     = g++
CFLAGS = -std=c++11
LDLIBS = -lcrypto

server: server-main.cpp ./utils/shared-functions.cpp ./utils/server-class.cpp ./utils/crypto.cpp
	$(CC) $(CFLAGS) -o server ./utils/crypto.cpp ./utils/shared-functions.cpp ./utils/server-class.cpp server-main.cpp $(LDLIBS) -I.

client: client-main.cpp ./utils/shared-functions.cpp ./utils/client-class.cpp ./utils/crypto.cpp ./game/FourInARow.cpp 
	$(CC) $(CFLAGS) -o client ./game/FourInARow.cpp ./utils/crypto.cpp  ./utils/shared-functions.cpp ./utils/client-class.cpp client-main.cpp $(LDLIBS) -I.

serv: serv.cpp ./utils/shared-functions.cpp
	$(CC) $(CFLAGS) -o serv serv.cpp ./utils/shared-functions.cpp  $(LDLIBS) -I.

all: server.cpp client-main.cpp ./utils/shared-functions.cpp
	$(CC) $(CFLAGS)  -o server server.cpp ./utils/shared-functions.cpp $(LDLIBS)
	$(CC) $(CFLAGS)  -o client client-main.cpp ./utils/shared-functions.cpp $(LDLIBS) -I.

clean:
	rm server client