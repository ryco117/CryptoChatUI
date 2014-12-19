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
    string FileRequest = QFileName.toStdString();

	if(FileRequest.empty())
	{
		Sending = 0;
		return;
	}

    fstream File(FileRequest.c_str(), ios::in);
	if(File.is_open())
	{
		FileToSend = FileRequest;
		FileRequest = GetName(FileRequest);
		File.seekg(0, File.end);
		__uint64_t Length = File.tellg();

		mpz_class IV = RNG->get_z_bits(128);
		string EncName;

		//Network Endian
		EncName.push_back((char)(Length >> 56));
		EncName.push_back((char)((Length >> 48) & 0xFF));
		EncName.push_back((char)((Length >> 40) & 0xFF));
		EncName.push_back((char)((Length >> 32) & 0xFF));
		EncName.push_back((char)((Length >> 24) & 0xFF));
		EncName.push_back((char)((Length >> 16) & 0xFF));
		EncName.push_back((char)((Length >> 8) & 0xFF));
		EncName.push_back((char)(Length & 0xFF));

		EncName += FileRequest;
		EncName = MyAES.Encrypt(SymKey, EncName, IV);
		string IVStr = Export64(IV);
		while(IVStr.size() < IV64_LEN)
			IVStr.push_back('\0');

		FileRequest = "x" + IVStr;

		//Network Endian
		FileRequest.push_back((char)((__uint32_t)EncName.size() >> 24));
		FileRequest.push_back((char)(((__uint32_t)EncName.size() >> 16) & 0xFF));
		FileRequest.push_back((char)(((__uint32_t)EncName.size() >> 8) & 0xFF));
		FileRequest.push_back((char)((__uint32_t)EncName.size() & 0xFF));

		FileRequest += EncName;
		FileRequest[0] = 1;

		while(FileRequest.length() < RECV_SIZE)
			FileRequest.push_back('\0');

		if(send(Client, FileRequest.c_str(), FileRequest.length(), 0) < 0)
		{
			perror("File request failure");
			return;
		}
		else
			ui->StatusLabel->setText(QString("Waiting for response..."));
		File.close();
	}
	else
	{
		Sending = 0;
        QMessageBox* msgBox = new QMessageBox;
        msgBox->setText(QString("Could not open ") + QString(FileRequest.c_str()) + QString(", file transfer cancelled."));
        msgBox->setIcon(QMessageBox::Warning);
        msgBox->setStandardButtons(QMessageBox::Ok);
        msgBox->exec();
        delete msgBox;
	}
	return;
}

void PeerToPeer::SendFilePt2()
{
	fstream File(FileToSend.c_str(), ios::in | ios::binary);
	if(File.is_open())
	{
		bool Finished = false;
		unsigned int FileLeft = 0;
		File.seekg(0, File.end);
        FileLeft = (unsigned int)File.tellg() - FilePos;
		if(FileLeft >= FILE_PIECE_LEN)
			FileLeft = FILE_PIECE_LEN;
		else
		{
			Sending = 0;	//file is done after this
			Finished = true;
		}
		
		char* buffer = new char[FileLeft];
		File.seekg(FilePos, File.beg);
		File.read(buffer, FileLeft);
		FilePos += FileLeft;
		
		string Data;
		for(unsigned int i = 0; i < FileLeft; i++)
			Data.push_back(buffer[i]);
			
		mpz_class IV = RNG->get_z_bits(128);
		string SIV = Export64(IV);
		while(SIV.size() < IV64_LEN)
			SIV.push_back('\0');
		
		string Final = "x" + SIV;
		string EncData = MyAES.Encrypt(SymKey, Data, IV);

		//Network Endian
		Final.push_back((char)((__uint32_t)EncData.size() >> 24));
		Final.push_back((char)(((__uint32_t)EncData.size() >> 16) & 0xFF));
		Final.push_back((char)(((__uint32_t)EncData.size() >> 8) & 0xFF));
		Final.push_back((char)((__uint32_t)EncData.size() & 0xFF));

		Final += EncData;
		Final[0] = 3;

		while(Final.size() < RECV_SIZE)
			Final.push_back('\0');

		int n = send(Client, Final.c_str(), Final.length(), 0);	//send the client the encrypted message
		if(n == -1)
		{
			perror("\nSendFilePt2");
			Sending = 0;
		}

		delete[] buffer;
		File.close();
		if(Finished)
		{
			ui->StatusLabel->setText(QString("Finished sending ") + QString(FileToSend.c_str()) + QString("."));
		}
	}
	return;
}

void PeerToPeer::ReceiveFile(string Msg)
{
	fstream File(FileLoc.c_str(), ios::out | ios::app | ios::binary);
	if(File.is_open())
	{
		try
		{
			Msg = MyAES.Decrypt(SymKey, Msg, FileIV);
			File.write(Msg.c_str(), Msg.size());
			BytesRead += Msg.size();
		}
		catch(string s)
		{
			ui->StatusLabel->setText(QString(s.c_str()));
			Sending = 0;
			File.close();
			return;
		}

		if(BytesRead == FileLength)
		{
			ui->StatusLabel->setText(QString("Finished saving ") + QString(FileLoc.c_str()) + QString(", ") + QString::number(FileLength) + QString(" bytes."));
		}
		File.close();
	}
	else
	{
		Sending = 0;
		QMessageBox* msgBox = new QMessageBox;
		msgBox->setText(QString("Could not open ") + QString(FileLoc.c_str()) + QString(", file transfer cancelled."));
		msgBox->setIcon(QMessageBox::Warning);
		msgBox->setStandardButtons(QMessageBox::Ok);
		msgBox->exec();
		delete msgBox;
	}
	return;
}

void PeerToPeer::DropLine(string pBuffer)
{
	string print = MyAES.Decrypt(SymKey, pBuffer, PeerIV);
	
    ui->ReceiveText->append(QString("Client: ") + QString(print.c_str()));		//Print What we received
	return;
}

void PeerToPeer::SendMessage()
{
    ui->ReceiveText->append(QString("Me: ") + ui->SendText->text());
    QByteArray ba = ui->SendText->text().toLocal8Bit();
    ui->SendText->setText(QString(""));

    mpz_class IV = RNG->get_z_bits(128);
	CipherMsg = "x" + Export64(IV);
	CipherMsg[0] = 0;
	while(CipherMsg.size() < 1 + IV64_LEN)
		CipherMsg.push_back('\0');

	string EncMsg = MyAES.Encrypt(SymKey, ba.data(), IV);

	//Network Endian
	CipherMsg.push_back((char)((__uint32_t)EncMsg.size() >> 24));
	CipherMsg.push_back((char)(((__uint32_t)EncMsg.size() >> 16) & 0xFF));
	CipherMsg.push_back((char)(((__uint32_t)EncMsg.size() >> 8) & 0xFF));
	CipherMsg.push_back((char)((__uint32_t)EncMsg.size() & 0xFF));
	CipherMsg += EncMsg;

	while(CipherMsg.size() < RECV_SIZE)
		CipherMsg.push_back('\0');

	send(Client, CipherMsg.c_str(), CipherMsg.length(), 0);
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