#include <iostream>
#include <vector>
#include <map>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <stdexcept>
#include "utils/shared-constants.h"
#include "utils/shared-functions.h"
#include "utils/client-constants.h"
#include "utils/client-class.h"
using namespace std;

void show_menu(){

	cout << "\n---------------------------------\n";
	cout << "              MENU\n";
	cout << "---------------------------------\n";
	cout << "What do you want to do ?\n\n";

	cout << "1. See list of online players\n";
	cout << "2. Challenge a player\n";
	cout << "0. Log-out\n\n";
	cout << "---------------------------------\n";
	cout << "Please, insert your choice > ";
	cout.flush();
}

Client *client;

void signal_callback_handler(int signum) {

	client->logout();

	exit(signum);
}

int main(int argc, char* argv[]){

	
	fd_set fds;
	string choice;
	map<string, string> list_of_online_players_menu;
	unsigned char buffer_in[MAX_PACKET_SIZE];

	cout<<"<------------- 4-IN-A-ROW --------------->\n\n";
	cout<<"Welcome! Please, insert your username > ";
	
	//Retrieve login credentials (username)
	string username, password;
	getline(cin, username);
	if(!cin){ 
		
		cerr<<"<ERR>  Error during input\n"; 
		exit(1);

	}
	if(username.length() > MAX_USERNAME_LEN-1){

		cerr << "<ERR> Too long username (max length is 16 characters)\n";
		exit(1);

	}
	cout<< endl;

	setStdinEcho(false);
	cout<<"Welcome " << username <<"! Please, insert your password > ";
	getline(cin, password);
	if(!cin){ 
		
		cerr<<"<ERR>  Error during input\n"; 
		exit(1);

	}
    setStdinEcho(true);

	cout<< endl << endl;

	client = new Client(username);

	if(!client->authentication(password)){

		cout << "Authentication failed, disconnecting" << endl;

		exit(1);

	}

	signal(SIGINT, signal_callback_handler);

	while(true){

		show_menu();

		memset(buffer_in, 0, MAX_PACKET_SIZE);
		choice = to_string(-1);

		int master_fd = client->getMasterFd();

		int maxfd = (master_fd > STDIN_FILENO) ? master_fd : STDIN_FILENO;

		FD_ZERO(&fds);
        FD_SET(master_fd, &fds); 
        FD_SET(STDIN_FILENO, &fds);

		select(maxfd + 1, &fds, NULL, NULL, NULL);

		if(FD_ISSET(STDIN_FILENO, &fds)) { 
			// Enter here if user type something
            getline(cin, choice);
			if(!cin){ 
		
				cerr<<"Error during input\n"; 
				exit(1);

			}

			cout << endl;
        }

		if(FD_ISSET(master_fd, &fds)) {
			// Enter here if a message arrives (a challenge request) 

			//cout << "\n<INFO> Packet arrived!\n\n";

			unsigned char *buffer_in = (unsigned char*)malloc(MAX_PACKET_SIZE);
			if(!buffer_in){

				cerr << "<ERR>  malloc() returned NULL, disconnecting!\n\n";
				client->logout();
				exit(1);

			}
			memset(buffer_in, 0, MAX_PACKET_SIZE);
			int responseCode = client->recvMessage(master_fd, buffer_in);

			switch (responseCode){
				case ERR_SEND_S_PKT: 

					cout << "Server SEND error\n";
					break;

				case ERR_INTERNAL_S_PKT: 

				cout << "Server internal error, disconnecting\n";
				exit(1);

				case ERR_AUTHENTICATION_S_PKT:

					cout << "Server error during authentication, disconnecting\n";
					exit(1);

				case FWD_REQ_CHALLENGE_S_PKT:

					client->handleChallengeRequest(buffer_in);

					break;
				
				case FWD_ACC_CHALLENGE_S_PKT:
					// Response coming to the challenged player from the server

					client->handleAcceptedChallenge(buffer_in);
					
					break;

				case PLAYER1_HELLO_P_PKT:
				{
					cout << "Arrived PLAYER1_HELLO_P packet from the opponent player\n\n";

					if(!client->player2P2PAuthentication(buffer_in)){

						cerr << "Error during P2P authentication, back to main menu\n\n";
						break;

					}

					bool firstToPlay = false;
					client->playP2PMatch(firstToPlay);

					client->sendP2PMatchFinished();

					break;
				}
				
				default:
					break;
			}
		#pragma optimize("", off)
			memset(buffer_in, 0, MAX_PACKET_SIZE);
		#pragma optimize("", on)
			free(buffer_in);
			continue;
		}

		int choice_int;

		try{
			choice_int = stoi(choice);
		} catch (std::invalid_argument const& ex){

			cout << "Choice is invalid, retry.\n\n";
			continue;
		}

		switch (choice_int){
			case 0: // Log-out
			{
				if(client->logout()){

					exit(0);
				}

				break;
			}
			case 1: // See online players
			{
				if(!client->sendRequestListOnlinePlayers()){
					cerr << "<ERR>  Error sending the request for the list of online players!\n";
					continue;
				}

				// Receive the list
				map<string, string> list_of_online_players_menu = client->recvListOnlinePlayers();
				if(list_of_online_players_menu.empty()){
				
					cout << "No online players to play with :(\n\n";

				}

				break;

			}
			case 2: // Challenge a player
			{
				if(!client->sendRequestListOnlinePlayers()){

					cerr << "<ERR>  Error sending the request for the list of online players!\n";
					continue;
				}
				// First, retrieve the list of online players

				// Receive the list
				map<string, string> list_of_online_players_menu = client->recvListOnlinePlayers();
				if(list_of_online_players_menu.empty()){
				
					cout << "No online players to play with :(\n\n";
					continue;

				}

				cout << "Type the number of the player you wish to challenge > ";
				getline(cin, choice);
				if(!cin){ 
		
					cerr<<"Error during input\n"; 
					exit(1);

				}
				if (list_of_online_players_menu.find(choice) == list_of_online_players_menu.end()) {
					
					cout << "\nChoice not allowed!\n\n";
					continue;

				}

				if(!client->sendChallengeRequest(list_of_online_players_menu[choice].c_str())){

					continue;

				}
					
				cout << "Waiting for the peer to accept/refuse the challenge...\n";

				int responseCode = client->recvChallengeResponse();
				if (responseCode == FWD_REF_CHALLENGE_S_PKT){

					cout << "The challenge was refused by '"<< list_of_online_players_menu[choice] <<"'\n\n";
					continue;

				} 
				if(responseCode == FWD_ACC_CHALLENGE_S_PKT){
					
					cout << "The challenge was accepted by '"<< list_of_online_players_menu[choice] <<"'\n\n";
					
					if(!client->player1P2PAuthentication()){

						cerr << "Error during P2P authentication, back to main menu!\n\n";
						break;
						
					}

					bool firstToPlay = true;
					client->playP2PMatch(firstToPlay);

					client->sendP2PMatchFinished();
					
					continue;

				}

				if (responseCode == PLAYER_NOT_AVAILABLE_S_PKT){

					cout << "Challenged player replying to another request, please try again later.\n\n";

					break;
				}

				if (responseCode == -1)
					break;
				
			}
		}

	}
	return 0;	

}
