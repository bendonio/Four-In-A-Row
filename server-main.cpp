#include <iostream>
#include <algorithm>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <map>
#include <stdlib.h>
#include <unistd.h>
#include "utils/shared-constants.h"
#include "utils/shared-functions.h"
#include "utils/crypto.h"
#include "utils/server-class.h"
using namespace std;

int main(int argc, char* argv[]){

	RAND_poll();

    unsigned char buffer_in[MAX_PACKET_SIZE];

    int ret;

    Server *server = new Server(); // This makes also the connection

    while(1){
        // Receiving the hello_c message
		cout<<"<DBG>  Waiting connections...\n";

        server->serverSelect();

        for(int i = 0; i <= server->getFdmax(); i++) {

            if(server->fdIsSet(i)) {

                //cout << "Listener is: " << server->getListener() << ".\n i = " << i << endl;
                
                if(i == server->getListener()) {
                    // First msg from this client

                    server->acceptConnection();

                } else {
                    // Msg from a client already connected

                    int client = i;

                    memset(buffer_in, 0, MAX_PACKET_SIZE); // Cleaning the buffer

                    ret = recv(client, buffer_in, MAX_PACKET_SIZE, 0);
                    if(ret <= 0){

                        cerr<<"<ERR> Error receiving packet\n";
                        exit(1);

                    } else {

                        cout << "<OK>   Packet received.\n\n";

                        // First check the opcode

                        uint16_t opcode = get_opcode(buffer_in);

                        if(!server->clientAllowedOpcode(client, opcode)){

                            continue;

                        }

                        switch(opcode){
                        
                            case LOG_OUT_C_PKT:
                        
                            {
                                // The client wants to disconnect
                                server->clientLogOut(client);

                                break;
                            }

                            case HELLO_DONE_C_PKT:
                            { 
                                // End of authentication phase 
                                server->completeAuthentication(client, buffer_in);

                                break;
                            }

                            case REQ_PLAYERS_LIST_C_PKT:
                            {

                                cout << "<DBG>  Packet REQ_PLAYERS_LIST_C received\n\n";

                                server->sendOnlinePlayersList(client, buffer_in, opcode);

                                break;
                            }

                            case REQ_CHALLENGE_C_PKT:
                            {
                                cout << "<DBG>  Arrived REQ_CHALLENGE_C_PKT\n\n";

                                // Forward CHALLENGE request to the user
                                server->forwardChallengeRequest(client, buffer_in, opcode);

                                break;
                            }

                            case ACCEPT_CHALLENGE_C_PKT:
                            {
                                cout << "<DBG>  Arrived ACCEPT_CHALLENGE_C_PKT\n\n";

                                server->recvReplyToChallenge(client, buffer_in, opcode);
                                //server->handleAcceptedChallenge(client, buffer_in, opcode);

                                break;
                            }

                            case REFUSE_CHALLENGE_C_PKT:
                            {
                                cout << "<DBG>  Arrived REFUSE_CHALLENGE_C_PKT\n\n";

                                server->recvReplyToChallenge(client, buffer_in, opcode);
                                //server->handleRefusedChallenge(client, buffer_in, opcode);
                                break;
                            }

                            case P2P_MATCH_FINISHED_C_PKT:
                            {
                                cout << "<DBG>  Arrived P2P_MATCH_FINISHED_C_PKT\n\n";

                                server->handleMatchFinished(client, buffer_in, opcode); 
                                break;

                            }
                            
                        }
                        // ------------------------
                    }

                }
            }

        }
    
    
    }
	return 0;
}

