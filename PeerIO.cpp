#ifndef PEER_IO
#define PEER_IO
#include "PeerToPeer.h"
#include "KeyManager.h"
#include "base64.h"

int recvr(int socket, char* buffer, int length, int flags);
string GetName(string file);

void PeerToPeer::SendFilePt1()
{
	Sending = 2;
    QString QFileName = QFileDialog::getOpenFileName(parent, QString("Open File"), "", QString("Files (*.*)"));
    string Name = QFileName.toStdString();
	FileToSend = Name;

	if(Name.empty())
	{
		Sending = 0;
		return;
	}

    fstream File(Name.c_str(), ios::in);
	if(File.is_open())
	{
		char* FileRequest = new char[RECV_SIZE];
		memset(FileRequest, 0, RECV_SIZE);

		Name = GetName(Name);
		File.seekg(0, File.end);
		__uint64_t Length = File.tellg();
		Length = __bswap_64(Length);

		unsigned int EncLength = 8 + Name.length();
		__uint32_t LenPadded = PaddedSize(EncLength);
		char* EncName = new char[LenPadded];
		memset(EncName, 0, LenPadded);
		memcpy(EncName, (void*)(&Length), 8);
		memcpy(&EncName[8], Name.c_str(), Name.length());

		mpz_class IV = RNG->get_z_bits(128);
		string IVStr = Export64(IV);
		while(IVStr.size() < IV64_LEN)
			IVStr.push_back('\0');

		MyAES.Encrypt(EncName, EncLength, IV, SymKey, EncName);

		FileRequest[0] = 1;
		memcpy(&FileRequest[1], IVStr.c_str(), IV64_LEN);
		memcpy(&FileRequest[1 + IV64_LEN + 4], EncName, LenPadded);
		LenPadded = htonl(LenPadded);
		memcpy(&FileRequest[1 + IV64_LEN], &LenPadded, 4);

		delete[] EncName;
		if(send(Client, FileRequest, RECV_SIZE, 0) < 0)
		{
			Sending = 0;
			ui->StatusLabel->setText(QString("File request failure"));
		}
		else
			ui->StatusLabel->setText(QString("Waiting for response..."));

		delete[] FileRequest;
		File.close();
	}
	else
	{
		Sending = 0;
        ui->StatusLabel->setText(QString("Could not open ") + QString(Name.c_str()) + QString(", file transfer cancelled."));
	}
	return;
}

void PeerToPeer::SendFilePt2()
{
	fstream File(FileToSend.c_str(), ios::in | ios::binary);
	if(File.is_open())
	{
		bool Finished = false;
		char* FilePiece = new char[RECV_SIZE];
		memset(FilePiece, 0, RECV_SIZE);

		unsigned int FileLeft = 0;
		File.seekg(0, File.end);
        FileLeft = (unsigned int)File.tellg() - FilePos;
		if(FileLeft > FILE_PIECE_LEN)
			FileLeft = FILE_PIECE_LEN;
		else
			Finished = true;
		
		unsigned int LenPadded = PaddedSize(FileLeft);
		char* Data = new char[LenPadded];

		File.seekg(FilePos, File.beg);
		File.read(Data, FileLeft);
		FilePos += FileLeft;
			
		mpz_class IV = RNG->get_z_bits(128);
		string SIV = Export64(IV);
		while(SIV.size() < IV64_LEN)
			SIV.push_back('\0');
		
		MyAES.Encrypt(Data, FileLeft, IV, SymKey, Data);
		FilePiece[0] = 3;
		memcpy(&FilePiece[1], SIV.c_str(), IV64_LEN);
		LenPadded = htonl(LenPadded);
		memcpy(&FilePiece[1 + IV64_LEN], &LenPadded, 4);
		LenPadded = htonl(LenPadded);
		memcpy(&FilePiece[1 + IV64_LEN + 4], Data, LenPadded);

		int n = send(Client, FilePiece, RECV_SIZE, 0);
		if(n == -1)
		{
			ui->StatusLabel->setText(QString("SendFilePt2 Error"));
			Sending = 0;
		}
		delete[] FilePiece;
		memset(Data, 0, LenPadded);
		delete[] Data;
		File.close();

		if(Finished)
		{
			ui->StatusLabel->setText(QString("Finished sending ") + QString(FileToSend.c_str()) + QString("."));
			Sending = 0;	//file is done after this
		}
	}
	else
	{
		Sending = 0;
        ui->StatusLabel->setText(QString("Could not open ") + QString(FileToSend.c_str()) + QString(", file transfer cancelled."));
	}
	return;
}

void PeerToPeer::ReceiveFile(string& Msg)
{
	fstream File(FileLoc.c_str(), ios::out | ios::app | ios::binary);
	if(File.is_open())
	{
		char* Data = new char[Msg.length()];
		unsigned int DataSize = 0;

		DataSize = MyAES.Decrypt(Msg.c_str(), Msg.length(), FileIV, SymKey, Data);
		if(DataSize == -1)
		{
			Sending = 0;
			memset(Data, 0, DataSize);
			delete[] Data;
			ui->StatusLabel->setText(QString("There was an issue decrypting file"));
			return;
		}
		File.write(Data, DataSize);
		memset(Data, 0, DataSize);
		delete[] Data;

		BytesRead += DataSize;
		if(BytesRead == FileLength)
		{
			Sending = 0;
			ui->StatusLabel->setText(QString("Finished saving ") + QString(FileLoc.c_str()) + QString(", ") + QString::number(FileLength) + QString(" bytes."));
		}
		File.close();
	}
	else
	{
		Sending = 0;
		ui->StatusLabel->setText(QString("Could not open ") + QString(FileLoc.c_str()) + QString(", file transfer cancelled."));
	}
	return;
}

void PeerToPeer::DropLine(string pBuffer)
{
	char* print = new char[pBuffer.length()];
	MyAES.Decrypt(pBuffer.c_str(), pBuffer.length(), PeerIV, SymKey, print);

    ui->ReceiveText->append(QString("Client: ") + QString(print));		//Print What we received
	memset(print, 0, pBuffer.length());
	delete[] print;
	return;
}

void PeerToPeer::SendMessage()
{
    ui->ReceiveText->append(QString("Me: ") + ui->SendText->text());
    QByteArray ba = ui->SendText->text().toLocal8Bit();
    ui->SendText->setText(QString(""));

    mpz_class IV = RNG->get_z_bits(128);
	CipherMsg = "x";
	CipherMsg += Export64(IV);
	while(CipherMsg.size() < 1 + IV64_LEN)
		CipherMsg.push_back('\0');

	CipherMsg[0] = 0;
	unsigned int CipherSize = PaddedSize(ba.size());
	char* Cipher = new char[CipherSize];
	MyAES.Encrypt(ba.data(), ba.size(), IV, SymKey, Cipher);

	//Network Endian
	CipherMsg.push_back((char)((__uint32_t)CipherSize >> 24));
	CipherMsg.push_back((char)(((__uint32_t)CipherSize >> 16) & 0xFF));
	CipherMsg.push_back((char)(((__uint32_t)CipherSize >> 8) & 0xFF));
	CipherMsg.push_back((char)((__uint32_t)CipherSize & 0xFF));
	for(int i = 0; i < CipherSize; i++)
		CipherMsg.push_back(Cipher[i]);

	delete[] Cipher;

	while(CipherMsg.size() < RECV_SIZE)
		CipherMsg.push_back('\0');

	send(Client, CipherMsg.c_str(), RECV_SIZE, 0);
	return;
}

inline int recvr(int socket, char* buffer, int length, int flags)
{
	int i = 0;
	while(i < length)
	{
		int n = recv(socket, &buffer[i], length-i, flags);
		if(n <= 0)
			return n;
		i += n;
	}
	return i;
}

inline string GetName(string file)
{
	int i = 0, j = 0;
	while(true)
	{
        if((j = file.find("/", i)) == (int)string::npos)
			break;
		else
			i = j+1;
	}
	if(i != 0)
		file.erase(0, i);
	return file;
}
#endif