#ifndef PTP_CPP
#define PTP_CPP

#define IV64_LEN 24											//The max length an IV for AES could be (in base64)
#define FILE_PIECE_LEN 2048									//The size in bytes of the blocks used for file sending
#define RECV_SIZE (1 + IV64_LEN + 4 + FILE_PIECE_LEN + 16)	//Max size that a message could possibly be in bytes after initial setup
#define MAX_RSA_SIZE 2048
#define RSA_RECV_SIZE (16 + (MAX_RSA_SIZE + MAX_RSA_SIZE) + \
					   MAX_RSA_SIZE + (MAX_RSA_SIZE + MAX_RSA_SIZE))//Max size of RSA public key exchange (16384 bit RSA).
																	//Salt, ephemeral key (2048 byte Mod, 2048 byte e value), 2048 byte signature, static key
#include "PeerToPeer.h"
#include "KeyManager.h"
#include "base64.h"
#include "PeerIO.cpp"

int PeerToPeer::StartServer(const int MAX_CLIENTS, bool SendPublic, string SavePublic)
{
	//		**-SERVER-**
	if((Serv = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) < 0)		//assign Serv to a file descriptor (socket) that uses IP addresses, TCP
	{
		close(Serv);
		Serv = 0;
		return -1;
	}

	memset(&socketInfo, 0, sizeof(socketInfo));						//Clear data inside socketInfo to be filled with server stuff
	socketInfo.sin_family = AF_INET;								//Use IP addresses
	socketInfo.sin_addr.s_addr = htonl(INADDR_ANY);					//Allow connection from anybody
	socketInfo.sin_port = htons(BindPort);								//Use port BindPort
	
	int optval = 1;
	setsockopt(Serv, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);		//Remove Bind already used error
	if(bind(Serv, (struct sockaddr*)&socketInfo, sizeof(socketInfo)) < 0)	//Bind socketInfo to Serv
	{
		close(Serv);
		Serv = 0;
		return -2;
	}
	listen(Serv, MAX_CLIENTS);			//Listen for connections on Serv

	//		**-FILE DESCRIPTORS-**
	FD_ZERO(&master);											//clear data in master
	FD_SET(Serv, &master);										//set master to check file descriptor Serv
	read_fds = master;											//the read_fds will check the same FDs as master

	MySocks = new int[MAX_CLIENTS + 1];							//MySocks is a new array of sockets (ints) as long the max connections + 1
	MySocks[0] = Serv;											//first socket is the server FD
    for(int i = 1; i < MAX_CLIENTS + 1; i++)					//assign all the empty ones to -1 (so we know they haven't been assigned a socket)
		MySocks[i] = -1;
    zero.tv_sec = 0;
    zero.tv_usec = 50;											//called zero for legacy reasons... assign timeval 50 milliseconds
	fdmax = Serv;												//fdmax is the highest file descriptor to check (because they are just ints)
	
	//		**-CLIENT-**	
	Client = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);			//assign Client to a file descriptor (socket) that uses IP addresses, TCP
	memset(&socketInfo, 0, sizeof(socketInfo));					//Clear socketInfo to be filled with client stuff
	socketInfo.sin_family = AF_INET;							//uses IP addresses
	if(!ProxyAddr.empty())
	{
		if(IsIP(ProxyAddr))
			socketInfo.sin_addr.s_addr = inet_addr(ProxyAddr.c_str());
		else
		{
			socketInfo.sin_addr.s_addr = Resolve(ProxyAddr);
			if(socketInfo.sin_addr.s_addr == 0)
			{
				ui->StatusLabel->setText(QString("Couldn't resolve proxy address"));
				close(Client);
				Client = 0;
				close(Serv);
				Serv = 0;
				return -4;
			}
		}
		socketInfo.sin_port = htons(ProxyPort);

		if(connect(Client, (struct sockaddr*)&socketInfo, sizeof(struct sockaddr_in)) < 0)
		{
			ui->StatusLabel->setText(QString("Could not connect to proxy"));
			close(Client);
			Client = 0;
			close(Serv);
			Serv = 0;
			return -3;
		}
		FD_SET(Client, &master);
		if(Client > fdmax)
			fdmax = Client;
	}
	else
	{
		if(IsIP(ClntAddr))
			socketInfo.sin_addr.s_addr = inet_addr(ClntAddr.c_str());
		else
		{
			socketInfo.sin_addr.s_addr = Resolve(ClntAddr);
			if(socketInfo.sin_addr.s_addr == 0)
			{
				ui->StatusLabel->setText(QString("Couldn't resolve peer address"));
				close(Client);
				Client = 0;
				close(Serv);
				Serv = 0;
				return -4;
			}
		}
		socketInfo.sin_port = htons(PeerPort);					//uses port PeerPort
	}

	if(!HasStaticPub && CanOpenFile(ClntAddr + ".pub", ios_base::in))
	{
		if(UseRSA)
		{
			if(!LoadRSAPublicKey(ClntAddr + ".pub", StcClientMod, StcClientE))
			{
				StcClientMod = 0;
				StcClientE = 0;
			}
			else
				HasStaticPub = true;
		}
		else
		{
			if(!LoadCurvePublicKey(ClntAddr + ".pub", StcCurvePPeer))
				memset((char*)StcCurvePPeer, 0, 32);
			else
				HasStaticPub = true;
		}
	}
	
	//Progress checks
	SentStuff = 0;
	GConnected = false;											//GConnected allows us to tell if we have set all the initial values, but haven't begun the chat
	ConnectedClnt = false;
	ConnectedSrvr = false;
	ContinueLoop = true;

    MaxClients = MAX_CLIENTS;
    SendPub = SendPublic;
    SavePub = SavePublic;

    ui->ReceiveText->clear();
    return 0;
}

int PeerToPeer::Update()
{
    read_fds = master;											//assign read_fds back to the unchanged master
    if(select(fdmax+1, &read_fds, NULL, NULL, &zero) == -1)		//Check for stuff to read on sockets, up to fdmax+1.. stop check after timeval zero (50ms)
    {
        return -3;
    }
    for(unsigned int i = 0; i < MaxClients + 1; i++)				//Look through all sockets
    {
        if(MySocks[i] == -1)										//if MySocks[i] == -1 then go just continue the for loop, this part of the array hasn't been assigned a socket
            continue;
        if(FD_ISSET(MySocks[i], &read_fds))							//check read_fds to see if there is unread data in MySocks[i]
        {
            if(i == 0)												//if i = 0, then based on line 52, we know that we are looking at data on the Serv socket... This means new connection!!
            {
                if((newSocket = accept(Serv, NULL, NULL)) < 0)		//assign socket newSocket to the person we are accepting on Serv
                {													//unless it errors
					if(ConnectedClnt)
						close(Client);
					Client = 0;
					close(Serv);
					Serv = 0;
					ui->StatusLabel->setText(QString("Error accepting connection"));
                    return -4;
                }

                for(unsigned int j = 1; j < MaxClients + 1; j++)	//assign an unassigned MySocks to newSocket
                {
                    if(MySocks[j] == -1)							//Not in use
                    {
						FD_SET(newSocket, &master);					//Add the newSocket FD to master set
                        MySocks[j] = newSocket;
                        if(newSocket > fdmax)						//if the new file descriptor is greater than fdmax..
                            fdmax = newSocket;						//Change fdmax to newSocket
                        break;
                    }
					if(j == MaxClients)
					{
						close(newSocket);
						newSocket = -1;
					}
                }
				if(newSocket != -1)
				{
					ConnectedSrvr = true;							//Passed All Tests, We Can Safely Say We Connected
					ui->StatusLabel->setText(QString("Peer connected"));
				}
            }
			else if(!HasEphemeralPub)
			{
				if(UseRSA)
				{
					char* SignedKey = new char[RSA_RECV_SIZE];
					nbytes = recvr(MySocks[i], SignedKey, RSA_RECV_SIZE, 0);
					if(HasStaticPub)
					{
						int n = 0;

						//Hash Ephemeral Public Key
						char* Hash = new char[32];
						libscrypt_scrypt((unsigned char*)&SignedKey[16], MAX_RSA_SIZE * 2, (unsigned char*)SignedKey, 16, 16384, 8, 1, (unsigned char*)Hash, 32);

						//Reverse Signing To Verify Signature
						mpz_class Sig;
						mpz_import(Sig.get_mpz_t(), MAX_RSA_SIZE, -1, 1, 0, 0, &SignedKey[16 + (MAX_RSA_SIZE * 2)]);
						Sig = MyRSA.BigDecrypt(StcClientMod, StcClientE, Sig);
						char* MyHash = new char[MAX_RSA_SIZE];
						mpz_export(MyHash, (size_t*)&n, 1, 1, 0, 0, Sig.get_mpz_t());

						int verify = memcmp(Hash, MyHash, 32);
						if(verify == 0)
							ui->ReceiveText->append(QString("Authentication: Public key verified!"));
						else
						{
							QMessageBox* msgBox = new QMessageBox;
	                        msgBox->setText(QString("Received Public Key Was Not Signed With Correct Static Key\n\
													Continue chat and save new key?"));
	                        msgBox->setIcon(QMessageBox::Warning);
	                        msgBox->setStandardButtons(QMessageBox::Yes | QMessageBox::No);
	                        if(msgBox->exec() == QMessageBox::No)
	                        {
								close(MySocks[i]); // bye!
								FD_CLR(MySocks[i], &master);
								MySocks[i] = -1;

								ContinueLoop = false;
								delete[] SignedKey;
								delete[] MyHash;
								delete[] Hash;
								break;
							}
							else
							{
								if(SavePub.empty())
									SavePub = ClntAddr + ".pub";

								mpz_import(StcClientMod.get_mpz_t(), MAX_RSA_SIZE, -1, 1, 0, 0, &SignedKey[16 + (MAX_RSA_SIZE * 3)]);
								mpz_import(StcClientE.get_mpz_t(), MAX_RSA_SIZE, -1, 1, 0, 0, &SignedKey[16 + (MAX_RSA_SIZE * 4)]);

								char* PubKey64 = Export64(StcClientMod);
								//cout << "Saving received peer static public key " << PubKey64 << " to " << SavePublic << endl;
								delete[] PubKey64;

								MakeRSAPublicKey(SavePub, StcClientMod, StcClientE);
							}
						}
						delete[] MyHash;
						delete[] Hash;
					}
					else
					{
						ui->ReceiveText->append(QString("Can't authenticate without static public key"));
						if(SavePub.empty())
							SavePub = ClntAddr + ".pub";

						mpz_import(StcClientMod.get_mpz_t(), MAX_RSA_SIZE, -1, 1, 0, 0, &SignedKey[16 + (MAX_RSA_SIZE * 3)]);
						mpz_import(StcClientE.get_mpz_t(), MAX_RSA_SIZE, -1, 1, 0, 0, &SignedKey[16 + (MAX_RSA_SIZE * 4)]);

						//Now that we have their key (which needs to be verified over a secure line [in person...]) check that the ephemeral was actually signed with it
						//Hash Ephemeral Public Key
						int n = 0;
						char* Hash = new char[32];
						libscrypt_scrypt((unsigned char*)&SignedKey[16], MAX_RSA_SIZE * 2, (unsigned char*)SignedKey, 16, 16384, 8, 1, (unsigned char*)Hash, 32);

						//Reverse Signing To Verify Signature
						mpz_class Sig;
						mpz_import(Sig.get_mpz_t(), MAX_RSA_SIZE, -1, 1, 0, 0, &SignedKey[16 + (MAX_RSA_SIZE * 2)]);
						Sig = MyRSA.BigDecrypt(StcClientMod, StcClientE, Sig);
						char* MyHash = new char[MAX_RSA_SIZE];
						mpz_export(MyHash, (size_t*)&n, 1, 1, 0, 0, Sig.get_mpz_t());

						int verify = memcmp(Hash, MyHash, 32);
						if(verify != 0)
						{
							QMessageBox* msgBox = new QMessageBox;
	                        msgBox->setText(QString("Received ephemeral key was not signed by received static key, exiting"));
	                        msgBox->setIcon(QMessageBox::Warning);
	                        msgBox->setStandardButtons(QMessageBox::Ok);
							msgBox->exec();

							close(MySocks[i]); // bye!
							FD_CLR(MySocks[i], &master);
							MySocks[i] = -1;
							ContinueLoop = false;
							delete[] SignedKey;
							delete[] MyHash;
							delete[] Hash;
							break;
						}
						else
						{
							char* PubKey64 = Export64(StcClientMod);
							//cout << "Saving received peer static public key " << PubKey64 << " to " << SavePublic << endl;
							delete[] PubKey64;

							MakeRSAPublicKey(SavePub, StcClientMod, StcClientE);
						}
					}
					mpz_import(EphClientMod.get_mpz_t(), MAX_RSA_SIZE, -1, 1, 0, 0, &SignedKey[16]);
					mpz_import(EphClientE.get_mpz_t(), MAX_RSA_SIZE, -1, 1, 0, 0, &SignedKey[16 + MAX_RSA_SIZE]);
					delete[] SignedKey;
				}
				else
				{
					char* SignedKey = new char[96];
					nbytes = recvr(MySocks[i], SignedKey, 96, 0);
					if(HasStaticPub)
					{
						int error = memcmp(&SignedKey[32], "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 32);
						if(error != 0)
						{
							char* DerivedKey = new char[32];
							char* Hash = new char[32];
							curve25519_donna((unsigned char*)DerivedKey, StcCurveK, StcCurvePPeer);
							libscrypt_scrypt((unsigned char*)DerivedKey, 32, (unsigned char*)SignedKey, 32, 16384, 8, 1, (unsigned char*)Hash, 32);

							memset(DerivedKey, 0, 32);
							delete[] DerivedKey;
							int verify = memcmp(Hash, &SignedKey[32], 32);
							if(verify == 0)
								ui->ReceiveText->append(QString("Authentication: Public key verified!"));
							else
							{
								QMessageBox* msgBox = new QMessageBox;
		                        msgBox->setText(QString("Received Public Key Was Not Signed With Correct Static Key\n\
														Continue chat and save new key?"));
		                        msgBox->setIcon(QMessageBox::Question);
		                        msgBox->setStandardButtons(QMessageBox::Yes | QMessageBox::No);
		                        if(msgBox->exec() == QMessageBox::No)
		                        {
									close(MySocks[i]); // bye!
									FD_CLR(MySocks[i], &master);
									ContinueLoop = false;
									MySocks[i] = -1;
								}
								else
								{
									if(SavePub.empty())
										SavePub = ClntAddr + ".pub";

									memcpy(StcCurvePPeer, &SignedKey[64], 32);
									char* PubKey64 = Base64Encode((char*)StcCurvePPeer, 32);
									//cout << "Saving received peer static public key " << PubKey64 << " to " << SavePublic << endl;
									delete[] PubKey64;

									MakeCurvePublicKey(SavePub, StcCurvePPeer);
								}
							}
							delete[] Hash;
						}
						else
							ui->ReceiveText->append(QString("Authentication: Peer didn't have public key to authenticate"));
					}
					else
					{
						ui->ReceiveText->append(QString("Can't authenticate without static public key"));
						if(SavePub.empty())
							SavePub = ClntAddr + ".pub";

						memcpy(StcCurvePPeer, &SignedKey[64], 32);
						char* PubKey64 = Base64Encode((char*)StcCurvePPeer, 32);
						//cout << "Saving received peer static public key " << PubKey64 << " to " << SavePublic << endl;
						delete[] PubKey64;

						MakeCurvePublicKey(SavePub, StcCurvePPeer);
					}
					memcpy(EphCurvePPeer, SignedKey, 32);
					delete[] SignedKey;

					char SaltStr[16] = {'\x1A','\x9B','\xCC','\x46','\xF7','\x67','\xDF','\x3B','\x6D','\x8A','\xDB','\xB6','\x20','\xCB','\xE8','\xD4'};		//Nothing-up-my-sleeve pseudo-random salt derived from i^i in binary converted to hex string
																																								//1A9BCC46F767DF3B6D8ADBB620CBE8D4 -> 0.0011010100110111100110001000110111101110110011111011111001110110110110110001010110110111011011000100000110010111110100011010100
																																								//								   -> 0.20787957635076190854695561983497877003
					curve25519_donna(SharedKey, EphCurveK, EphCurvePPeer);
					libscrypt_scrypt(SharedKey, 32, (unsigned char*)SaltStr, 16, 16384, 8, 1, SymKey, 32);		//Use agreed upon salt
				}
				HasEphemeralPub = true;
			}
            else
            {
				char buf[RECV_SIZE];	//RECV_SIZE is the max possible incoming data (file part with iv, leading byte, and data size)
				memset(buf, 0, RECV_SIZE);
				nbytes = recvr(MySocks[i], buf, RECV_SIZE, 0);
				if(nbytes <= 0)		//handle data from a client
                {
                    // got error or connection closed by client
                    if(nbytes == 0)
                    {
                        // connection closed
                        ui->ReceiveText->append(QString("Peer ") + QString::number(i) + QString(" disconnected"));
                        ContinueLoop = false;
                        return 0;
                    }
                    else
						ui->ReceiveText->append(QString("Disconnected from peer ") + QString::number(i) + QString(" with error ") + QString::number(nbytes));

                    close(MySocks[i]);				//bye!
                    MySocks[i] = -1;
                    FD_CLR(MySocks[i], &master);	//remove from master set
                    ContinueLoop = false;
                }
                else if(SentStuff == 2 && UseRSA)	//if SentStuff == 2, then we still need the symmetric key (should only get here if RSA)
                {
					string ClntKey = buf;
					mpz_class PeerKey;
					try
					{
						Import64(ClntKey.c_str(), PeerKey);
					}
					catch(int e)
					{
						ui->StatusLabel->setText(QString("The received symmetric key is corrupt"));
					}
					PeerKey = MyRSA.BigDecrypt(EphMyMod, EphMyD, PeerKey);						//They sent their sym. key with our public key. Decrypt it!
					uint8_t* TempSpace = new uint8_t[ClntKey.size()];							//Guarantee enough room for GMP to export into
					mpz_export(TempSpace, NULL, 1, 1, 0, 0, PeerKey.get_mpz_t());
					mpz_xor(PeerKey.get_mpz_t(), PeerKey.get_mpz_t(), PeerKey.get_mpz_t());

					for(int i = 0; i < 32; i++)
						SymKey[i] ^= TempSpace[i];

					SentStuff = 3;
                }
				else
                {
					string Msg = "";	//lead byte for data id | varying extension info		| data length identifier	| main data
										//-------------------------------------------------------------------------------------------------------------------------------------
										//0 = msg				| IV64_LEN chars for encoded IV	| uint32 message length		| Enc. message
										//1 = file request		| IV64_LEN chars for encoded IV | uint32 information length	| Enc. uint64 file length & file name
										//2 = request answer 	|								| (none, always 1 byte)		| response (not encrypted because a MitM would know anyway)
										//3 = file piece		| IV64_LEN chars for encoded IV	| uint32 file piece length	| Enc. file piece

					if(buf[0] == 0)																//Message
					{
						nbytes = ntohl(*((uint32_t*)&buf[1 + IV64_LEN]));
						for(unsigned int i = 0; i < 1 + IV64_LEN + 4 + (unsigned int)nbytes; i++)	//If we do a simple assign, the string will stop reading at a null terminator ('\0')
	                        Msg.push_back(buf[i]);													//so manually push back values in array buf...

						try
						{
							Base64Decode(Msg.substr(1, IV64_LEN).c_str(), (char*)PeerIV, 16);
							Msg = Msg.substr(1 + IV64_LEN + 4);
						}
						catch(int e)
						{
							ui->StatusLabel->setText(QString("The received message is corrupt"));
							continue;
						}

						DropLine(Msg);
                    }
                    else if(buf[0] == 1)										//File Request
                    {
						if(Sending & 128)			//Can't receive two files simultaneously
						{
							char* Reject = new char[RECV_SIZE];
							memset(Reject, 0, RECV_SIZE);				//Don't send over 1KB of recently freed memory over network...
							Reject[0] = 2;
							Reject[1] = 'n';
							send(Client, Reject, RECV_SIZE, 0);
							delete[] Reject;
							continue;
						}
						nbytes = ntohl(*((uint32_t*)&buf[1 + IV64_LEN]));
						for(unsigned int i = 0; i < 1 + IV64_LEN + 4 + (unsigned int)nbytes; i++)
							Msg.push_back(buf[i]);

						try
						{
							Base64Decode(Msg.substr(1, IV64_LEN).c_str(), (char*)PeerIV, 16);
							Msg = Msg.substr(1 + IV64_LEN + 4);
						}
						catch(int e)
						{
							ui->StatusLabel->setText(QString("The received file request is corrupt"));
							continue;
						}

						char* PlainText = new char[Msg.size() + 1];
						PlainText[Msg.size()] = 0;
						int PlainSize = MyAES.Decrypt(Msg.c_str(), Msg.size(), PeerIV, SymKey, PlainText);
						if(PlainSize == -1)
						{
							ui->StatusLabel->setText(QString("The received file request is corrupt"));
							continue;
						}

						FileLength = __bswap_64(*((uint64_t*)PlainText));
						FileLoc = &PlainText[8];

                        char c;
                        QMessageBox* msgBox = new QMessageBox;
                        msgBox->setText(QString("Save ") + QString(FileLoc.c_str()) + QString(", ") + QString::number(FileLength) + QString(" bytes"));
                        msgBox->setIcon(QMessageBox::Question);
                        msgBox->setStandardButtons(QMessageBox::Yes | QMessageBox::No);
                        if(msgBox->exec() == QMessageBox::Yes)
                        {
                            c = 'y';
                            BytesRead = 0;
							Sending |= 128;							//Receive file mode
                        }
                        else
                            c = 'n';

                        char* Accept = new char[RECV_SIZE];
						memset(Accept, 0, RECV_SIZE);				//Don't send over 1KB of recently freed memory over network...
                        Accept[0] = 2;
                        Accept[1] = c;
                        send(Client, Accept, RECV_SIZE, 0);

						memset(PlainText, 0, nbytes);
						delete[] PlainText;
						delete[] Accept;
                    }
                    else if(buf[0] == 2 && (Sending & 2))
                    {
                        if(buf[1] == 'y')
                        {
							Sending &= 128;
							Sending |= 4;
                            FilePos = 0;
							ui->StatusLabel->setText(QString("Peer accepted file"));
                        }
                        else
                        {
                            Sending &= 128;
                            ui->StatusLabel->setText(QString("Peer rejected file. The transfer was cancelled"));
                        }
                    }
                    else if(buf[0] == 3 && (Sending & 128))
                    {
						nbytes = ntohl(*((uint32_t*)&buf[1 + IV64_LEN]));
						for(unsigned int i = 0; i < 1 + IV64_LEN + 4 + (unsigned int)nbytes; i++)
							Msg.push_back(buf[i]);

						try
						{
							Base64Decode(Msg.substr(1, IV64_LEN).c_str(), (char*)FileIV, 16);
							Msg = Msg.substr(1 + IV64_LEN + 4);
						}
						catch(int e)
						{
							ui->StatusLabel->setText(QString("The received file piece is corrupt"));
							Sending &= 127;
							continue;
						}
						ReceiveFile(Msg);
                    }
                }
            }
        }//End FD_ISSET
    }//End For Loop for sockets
    if(Sending & 4)
        SendFilePt2();
    if(!ConnectedClnt)															//Not connected yet?!?
    {
		TryConnect(SendPub);													//Lets try to change that
    }
    if(SentStuff == 1 && HasEphemeralPub)										//We have established a connection and we have their keys!
    {
		if(UseRSA)
		{
			mpz_class GMPSymKey;
			mpz_import(GMPSymKey.get_mpz_t(), 32, 1, 1, 0, 0, SymKey);
			mpz_class Values = MyRSA.BigEncrypt(EphClientMod, EphClientE, GMPSymKey);		//Encrypt The Symmetric Key With Their Public Key
			mpz_xor(GMPSymKey.get_mpz_t(), GMPSymKey.get_mpz_t(), GMPSymKey.get_mpz_t());	//Clear
			string MyValues = Export64(Values);												//Base 64

			while(MyValues.size() < RECV_SIZE)
				MyValues.push_back('\0');

			//Send The Encrypted Symmetric Key
			if(send(Client, MyValues.c_str(), RECV_SIZE, 0) < 0)
			{
				ui->StatusLabel->setText(QString("Couldn't send encrypted symmetric key"));
				return -5;
			}
			SentStuff = 2;														//We have given them our symmetric key
		}
		else
			SentStuff = 3;

    }
    return 0;
}

void PeerToPeer::TryConnect(bool SendPublic)
{
	if(ProxyPort > 0)
	{
		if(!ProxyRequest)
		{
			if(IsIP(ClntAddr))
			{
				//SOCKS4 - Assuming no userID is required. Could be modified if becomes relevant
				char ReqField[9];
				ReqField[0] = 0x04;
				ReqField[1] = 0x01;
				uint16_t ServerPort = htons(PeerPort);
				memcpy(&ReqField[2], &ServerPort, 2);
				uint32_t ClntAddrBytes = inet_addr(ClntAddr.c_str());
				memcpy(&ReqField[4], &ClntAddrBytes, 4);
				ReqField[8] = 0;
				send(Client, ReqField, 9, 0);
			}
			else
			{
				//SOCKS4a - Assuming no userID is required. Could be modified if becomes relevant
				char* ReqField = new char[9 + ClntAddr.size() + 1];
				memset(ReqField, 0, 9 + ClntAddr.size() + 1);

				ReqField[0] = 0x04;
				ReqField[1] = 0x01;
				uint16_t ServerPort = htons(PeerPort);
				memcpy(&ReqField[2], &ServerPort, 2);
				ReqField[7] = 0xFF;
				memcpy(&ReqField[9], ClntAddr.c_str(), ClntAddr.size());
				send(Client, ReqField, 9 + ClntAddr.size() + 1, 0);
				delete[] ReqField;
			}

			ProxyRequest = true;
			return;
		}

		if(FD_ISSET(Client, &read_fds))
		{
			ProxyRequest = false;
			char RecvField[8];
			int nbytes = recv(Client, RecvField, 8, 0);
			if(nbytes <= 0)
			{
				//cout << "Disconnected from proxy\n";
				FD_CLR(Client, &master);
				close(Client);
				Client = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
				if(connect(Client, (struct sockaddr*)&socketInfo, sizeof(struct sockaddr_in)) < 0)
				{
					ui->StatusLabel->setText(QString("Could not connect to proxy"));
					close(Client);
					close(Serv);
					return;
				}
				FD_SET(Client, &master);
				if(Client > fdmax)
					fdmax = Client;
				return;
			}

			if(RecvField[0] != 0)
			{
				ui->StatusLabel->setText(QString("Proxy gave bad reply, exiting"));
				close(Client);
				close(Serv);
				ContinueLoop = false;
				return;
			}
			if(RecvField[1] != 0x5a)
			{
				FD_CLR(Client, &master);
				close(Client);
				Client = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
				if(connect(Client, (struct sockaddr*)&socketInfo, sizeof(struct sockaddr_in)) < 0)
				{
					ui->StatusLabel->setText(QString("Could not connect to proxy"));
					close(Client);
					close(Serv);
					ContinueLoop = false;
					return;
				}
				FD_SET(Client, &master);
				if(Client > fdmax)
					fdmax = Client;
				return;
			}
		}
		else
			return;
	}
	else if(connect(Client, (struct sockaddr*)&socketInfo, sizeof(socketInfo)) < 0)
		return;

	//Connect succeeded!!!
	if(UseRSA)
	{
		char* SignedKey = new char[RSA_RECV_SIZE];
		memset(SignedKey, 0, RSA_RECV_SIZE);
		int n = 0;

		//Export Ephemeral Public Key
		mpz_export(&SignedKey[16], (size_t*)&n, -1, 1, 0, 0, EphMyMod.get_mpz_t());
		mpz_export(&SignedKey[16 + MAX_RSA_SIZE], (size_t*)&n, -1, 1, 0, 0, EphMyE.get_mpz_t());

		//Hash Ephemeral Public Key
		sfmt_fill_small_array64(sfmt, (uint64_t*)SignedKey, 2);					//Generate 16 byte salt
		char* Hash = new char[32];
		libscrypt_scrypt((unsigned char*)&SignedKey[16], MAX_RSA_SIZE * 2, (unsigned char*)SignedKey, 16, 16384, 8, 1, (unsigned char*)Hash, 32);

		//Sign The Hash With Static Private Key
		mpz_class GMPValue;
		mpz_import(GMPValue.get_mpz_t(), 32, 1, 1, 0, 0, Hash);			//Import hash into GMP class so we can do math with it
		GMPValue = MyRSA.BigEncrypt(StcMyMod, StcMyD, GMPValue);		//Encrypt hash with static private key
		mpz_export(&SignedKey[16 + (MAX_RSA_SIZE * 2)], (size_t*)&n, -1, 1, 0, 0, GMPValue.get_mpz_t());

		if(SendPublic)
		{
			//Export Static Public Key (In case they need it)
			mpz_export(&SignedKey[16 + (MAX_RSA_SIZE * 3)], (size_t*)&n, -1, 1, 0, 0, StcMyMod.get_mpz_t());
			mpz_export(&SignedKey[16 + (MAX_RSA_SIZE * 4)], (size_t*)&n, -1, 1, 0, 0, StcMyE.get_mpz_t());
		}

		//Send My Public Key And My Modulus Because We Started The Connection
		if(send(Client, SignedKey, RSA_RECV_SIZE, 0) < 0)
		{
			perror("Couldn't send public key");
			return;
		}
	}
	else
	{
		char* SignedKey = new char[96];
		memcpy(SignedKey, EphCurveP, 32);							//Send ephemeral public key
		if(HasStaticPub)
		{
			char* DerivedKey = new char[32];
			curve25519_donna((unsigned char*)DerivedKey, StcCurveK, StcCurvePPeer);
			libscrypt_scrypt((unsigned char*)DerivedKey, 32, (unsigned char*)EphCurveP, 32, 16384, 8, 1, (unsigned char*)&SignedKey[32], 32);	//Attach signature of eph. public key if can

			memset(DerivedKey, 0, 32);
			delete[] DerivedKey;
		}
		else
			memset(&SignedKey[32], 0, 32);			//else, zeros

		if(SendPublic)
			memcpy(&SignedKey[64], StcCurveP, 32);

		if(send(Client, SignedKey, 96, 0) < 0)
		{
			perror("Couldn't send public key");

			delete[] SignedKey;
			return;
		}
		delete[] SignedKey;
	}

	SentStuff = 1;									//We have sent our keys
	ConnectedClnt = true;
	ui->StatusLabel->setText(QString("Waiting For Peer's Response..."));
	return;
}
#endif