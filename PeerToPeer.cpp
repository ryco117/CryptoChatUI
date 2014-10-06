#ifndef PTP_CPP
#define PTP_CPP

#define IV64_LEN 24											//The max length an IV for AES could be (in base64)
#define FILE_PIECE_LEN 2048									//The size in bytes of the blocks used for file sending
#define RECV_SIZE (1 + IV64_LEN + FILE_PIECE_LEN + 16)		//Max size that a message could possibly be in bytes after initial setup
#define MAX_RSA_SIZE 4097									//Max size in bytes that the public key when sent will fill (this is for 16384 bit RSA)

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
		return -1;
	}

	memset(&socketInfo, 0, sizeof(socketInfo));						//Clear data inside socketInfo to be filled with server stuff
	socketInfo.sin_family = AF_INET;								//Use IP addresses
	socketInfo.sin_addr.s_addr = htonl(INADDR_ANY);					//Allow connection from anybody
	socketInfo.sin_port = htons(Port);								//Use port Port
	
	int optval = 1;
	setsockopt(Serv, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);		//Remove Bind already used error
	if(bind(Serv, (struct sockaddr*)&socketInfo, sizeof(socketInfo)) < 0)	//Bind socketInfo to Serv
	{
		close(Serv);
		return -2;
	}
	listen(Serv, MAX_CLIENTS);			//Listen for connections on Serv
	
	//		**-CLIENT-**	
	Client = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);			//assign Client to a file descriptor (socket) that uses IP addresses, TCP
	memset(&socketInfo, 0, sizeof(socketInfo));					//Clear socketInfo to be filled with client stuff
	socketInfo.sin_family = AF_INET;							//uses IP addresses
	socketInfo.sin_addr.s_addr = inet_addr(ClntIP.c_str());		//connects to the ip we specified
	socketInfo.sin_port = htons(Port);							//uses port Port
	
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
    for(unsigned int i = 0; i < MaxClients + 1; i++)			//Look through all sockets
    {
        if(MySocks[i] == -1)									//if MySocks[i] == -1 then go just continue the for loop, this part of the array hasn't been assigned a socket
            continue;
        if(FD_ISSET(MySocks[i], &read_fds))						//check read_fds to see if there is unread data in MySocks[i]
        {
            if(i == 0)											//if i = 0, then based on line 52, we know that we are looking at data on the Serv socket... This means new connection!!
            {
                if((newSocket = accept(Serv, NULL, NULL)) < 0)	//assign socket newSocket to the person we are accepting on Serv
                {
                    close(Serv);								//unless it errors
                    perror("Accept");
                    return -4;
                }
                ConnectedSrvr = true;							//Passed All Tests, We Can Safely Say We Connected

                FD_SET(newSocket, &master);						//Add the newSocket FD to master set
                for(unsigned int j = 1; j < MaxClients + 1; j++)	//assign an unassigned MySocks to newSocket
                {
                    if(MySocks[j] == -1)						//Not in use
                    {
                        MySocks[j] = newSocket;
                        if(newSocket > fdmax)					//if the new file descriptor is greater than fdmax..
                            fdmax = newSocket;					//Change fdmax to newSocket
                        break;
                    }
                }
                if(UseRSA && !HasPub)							//Check if we haven't already assigned the client's public key through an arg.
                {
					char* TempVA = new char[MAX_RSA_SIZE];
					string TempVS;
					nbytes = recv(newSocket, TempVA, MAX_RSA_SIZE, 0);

					for(unsigned int i = 0; i < (unsigned int)nbytes; i++)
						TempVS.push_back(TempVA[i]);

					try
					{
						Import64(TempVS.substr(0, TempVS.find("|", 1)), ClientMod);	//Modulus in Base64 in first half
						//cout << "CM: " << Export64(ClientMod) << "\n\n";
					}
					catch(int e)
					{
						ui->StatusLabel->setText(QString("The received modulus is bad"));
						return -1;
					}

					try
					{
						Import64(TempVS.substr(TempVS.find("|", 1)+1), ClientE);	//Encryption key in Base64 in second half
						//cout << "CE: " << Export64(ClientE) << "\n\n";
					}
					catch(int e)
					{
						ui->StatusLabel->setText(QString("The received RSA encryption key is bad"));
						return -1;
					}
                    if(!SavePub.empty())		//If we set the string for where to save their public key...
                        MakeRSAPublicKey(SavePub, ClientMod, ClientE);		//SAVE THEIR PUBLIC KEY!

					delete[] TempVA;
                }
				else if(!UseRSA)
				{
					if(!HasPub)
					{
						nbytes = recv(newSocket, CurvePPeer, 32, 0);
						if(!SavePub.empty())
	                        MakeCurvePublicKey(SavePub, CurvePPeer);
					}
					unsigned char SaltStr[16] = {(unsigned char)'\x43',(unsigned char)'\x65',(unsigned char)'\x12',(unsigned char)'\x94',(unsigned char)'\x83',(unsigned char)'\x05',(unsigned char)'\x73',(unsigned char)'\x37',\
												 (unsigned char)'\x65',(unsigned char)'\x93',(unsigned char)'\x85',(unsigned char)'\x64',(unsigned char)'\x51',(unsigned char)'\x65',(unsigned char)'\x64',(unsigned char)'\x94'};
					unsigned char Hash[32] = {0};

					curve25519_donna(SharedKey, CurveK, CurvePPeer);
					libscrypt_scrypt(SharedKey, 32, SaltStr, 16, 16384, 14, 2, Hash, 32); //Use agreed upon salt
					mpz_import(SymKey.get_mpz_t(), 32, 1, 1, 0, 0, Hash);
				}
				HasPub = true;
            }
            else		//Data is on a new socket
            {
				char buf[RECV_SIZE] = {'\0'};	//1068 is the max possible incoming data (file part with iv and leading byte)
				for(unsigned int j = 0; j < RECV_SIZE; j++)
                    buf[j] = '\0';

				if((nbytes = recv(MySocks[i], buf, RECV_SIZE, 0)) <= 0)		//handle data from a client
                {
                    // got error or connection closed by client
                    if(nbytes == 0)
                    {
                        // connection closed
                        ui->ReceiveText->append(QString("Server: socket ") + QString::number(MySocks[i]) + QString(" hung up"));
                        ContinueLoop = false;
                        return 0;
                    }
                    else
						perror("Recv");

                    close(MySocks[i]); // bye!
                    MySocks[i] = -1;
                    FD_CLR(MySocks[i], &master); // remove from master set
                    ContinueLoop = false;
                }
                else if(SentStuff == 2 && UseRSA) //if SentStuff == 2, then we still need the symmetric key (should only get here if RSA)
                {
					string ClntKey = buf;
					mpz_class TempKey;
					try
					{
						Import64(ClntKey, TempKey);
					}
					catch(int e)
					{
						ui->StatusLabel->setText(QString("The received symmetric key is bad"));
					}
					SymKey += MyRSA.BigDecrypt(MyMod, MyD, TempKey);							//They sent their sym key with our public key. Decrypt it!

					mpz_class LargestAllowed = 0;
					mpz_class One = 1;
					mpz_mul_2exp(LargestAllowed.get_mpz_t(), One.get_mpz_t(), 256);				//Largest allowed sym key is equal to (1 * 2^256) - 1
					mpz_mod(SymKey.get_mpz_t(), SymKey.get_mpz_t(), LargestAllowed.get_mpz_t());//Modulus by largest 256 bit value ensures within range after adding keys!
					SentStuff = 3;
                }
				else
                {
                    string Msg = "";				//lead byte for data id | varying extension info		| main data
													//-----------------------------------------------------------------------------------------------------
													//0 = msg        	 	| IV64_LEN chars for IV			| 512 message chars (or less)
													//1 = file request	 	| X chars for file length		| Y chars for file loc.
													//2 = request answer 	| 1 char for answer				|
													//3 = file piece	 	| IV64_LEN chars for IV			| FILE_PIECE_LEN bytes of file piece (or less)

					for(unsigned int i = 0; i < (unsigned int)nbytes; i++)	//If we do a simple assign, the string will stop reading at a null terminator ('\0')
                        Msg.push_back(buf[i]);					//so manually push back all values in array buf...

					if(Msg[0] == 0)
					{
						try
						{
							Import64(Msg.substr(1, IV64_LEN), PeerIV);
						}
						catch(int e)
						{
							ui->StatusLabel->setText(QString("The received IV is bad"));
						}

						try
						{
							Msg = Msg.substr(IV64_LEN+1);
						}
						catch(int e)
						{
							cout << "Bad message\n";
							ui->StatusLabel->setText(QString("Bad message received"));
						}
						DropLine(Msg);
                    }
                    else if(Msg[0] == 1)
                    {
                        Sending = -1;		//Receive file mode
						try
						{
							Import64(Msg.substr(1, IV64_LEN), PeerIV);
						}
						catch(int e)
						{
							ui->StatusLabel->setText(QString("Bad IV\n"));
						}
						string PlainText;
						try
						{
							PlainText = MyAES.Decrypt(SymKey, Msg.substr(IV64_LEN+1), PeerIV);
						}
						catch(string e)
						{
							ui->StatusLabel->setText(QString(e.c_str()));
						}

                        FileLength = atoi(PlainText.substr(0, PlainText.find("X", 1)).c_str());
						FileLoc = PlainText.substr(PlainText.find("X", 1)+1);

                        char c;
                        QMessageBox* msgBox = new QMessageBox;
                        msgBox->setText(QString("Save ") + QString(FileLoc.c_str()) + QString(", ") + QString::number(FileLength) + QString(" bytes"));
                        msgBox->setIcon(QMessageBox::Question);
                        msgBox->setStandardButtons(QMessageBox::Yes | QMessageBox::No);
                        if(msgBox->exec() == QMessageBox::Yes)
                        {
                            c = 'y';
                            BytesRead = 0;
                        }
                        else
                        {
                            c = 'n';
                            Sending = 0;
                        }
                        string Accept = "xx";
                        Accept[0] = 2;
                        Accept[1] = c;
                        send(Client, Accept.c_str(), Accept.length(), 0);
                    }
                    else if(Msg[0] == 2)
                    {
                        if(Msg[1] == 'y')
                        {
                            Sending = 3;
                            FilePos = 0;
                        }
                        else
                        {
                            Sending = 0;
                            QMessageBox* msgBox = new QMessageBox;
                            msgBox->setText(QString("Peer rejected file. The transfer was cancelled."));
                            msgBox->setIcon(QMessageBox::Question);
                            msgBox->setStandardButtons(QMessageBox::Ok);
                            msgBox->exec();
                        }
                    }
                    else if(Msg[0] == 3)
                    {
						try
						{
							Import64(Msg.substr(1, IV64_LEN), FileIV);
						}
						catch(int e)
						{
							ui->StatusLabel->setText(QString("Bad IV value when receiving file"));
						}
						ReceiveFile(Msg.substr(IV64_LEN+1));
                    }
                }
            }
        }//End FD_ISSET
    }//End For Loop for sockets
    if(Sending == 3)
        SendFilePt2();
    if(!ConnectedClnt)					//Not conected yet?!?
    {
		TryConnect(SendPub);			//Lets try to change that
    }
    if(SentStuff == 1 && HasPub)		//We have established a connection and we have their keys!
    {
		if(UseRSA)
		{
			string MyValues = Export64(MyRSA.BigEncrypt(ClientMod, ClientE, SymKey));	//Encrypt The Symmetric Key With Their Public Key, base 64

			//Send The Encrypted Symmetric Key
			if(send(Client, MyValues.c_str(), MyValues.length(), 0) < 0)
			{
				perror("Connect failure");
				return -5;
			}
			SentStuff = 2;			//We have given them our symmetric key
		}
		else
			SentStuff = 3;

    }
    return 0;
}

void PeerToPeer::TryConnect(bool SendPublic)
{
	if(connect(Client, (struct sockaddr*)&socketInfo, sizeof(socketInfo)) >= 0) 	//attempt to connect using socketInfo with client values
	{
        if(SendPublic)
		{
			if(UseRSA)
			{
				string TempValues = "";
				string MyValues = "";

				TempValues = Export64(MyMod);		//Base64 will save digits
				MyValues = TempValues + "|";		//Pipe char to seperate keys

				TempValues = Export64(MyE);
				MyValues += TempValues;				//MyValues is equal to the string for the modulus + string for exp concatenated

				//Send My Public Key And My Modulus Because We Started The Connection
				if(send(Client, MyValues.c_str(), MyValues.length(), 0) < 0)
				{
					perror("Connect failure");
					return;
				}
			}
			else
			{
				if(send(Client, CurveP, 32, 0) < 0)
				{
					perror("Connect failure");
					return;
				}
			}
		}
		SentStuff = 1;			//We have sent our keys
		ConnectedClnt = true;
		ui->StatusLabel->setText(QString("Waiting..."));
	}
	return;
}
#endif
