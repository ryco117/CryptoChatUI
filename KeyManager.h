#ifndef KEYMANAGER
#define KEYMANAGER
#include <iostream>
#include <string>
#include <sstream>
#include <gmpxx.h>
#include <exception>
#include <QMainWindow>
#include <QMessageBox>
#include <QString>
extern "C"
{
    #include <libscrypt.h>
}

#include "AES.cpp"
#include "base64.h"

/* ---------------------- Fully implementing Curve25519 keys! -------------------------- */
static bool LoadCurvePublicKey(string FileLoc, uint8_t point[32])
{
	QMessageBox* msgBox;
	fstream File(FileLoc.c_str(), ios::in);
	if(File.is_open())
	{
		string Line;
		getline(File, Line);
		if(Line != "crypto-key-ecc")		//Check for proper format
		{
			msgBox = new QMessageBox;
            msgBox->setText(QString("This key was not saved in a recognized format."));
            msgBox->setIcon(QMessageBox::Warning);
            msgBox->setStandardButtons(QMessageBox::Ok);
            msgBox->exec();
			return false;
		}
		File.read((char*)point, 32);
		File.close();
	}
	else
	{
		msgBox = new QMessageBox;
		msgBox->setText(QString("Error: Couldn't open:\n") + QString(FileLoc.c_str()));
		msgBox->setIcon(QMessageBox::Warning);
		msgBox->setStandardButtons(QMessageBox::Ok);
		msgBox->exec();
		delete msgBox;
		return false;
	}
	return true;
}

static bool LoadCurvePrivateKey(string FileLoc, uint8_t mult[32], string* Passwd)
{
	QMessageBox* msgBox;
	fstream File(FileLoc.c_str(), ios::in);
	if(File.is_open())
	{
		char Salt64[24] = {0};
		char IVStr[24] = {0};
		mpz_class IV = 0;
		char Hash[32] = {0};
		mpz_class FinalKey = 0;

		unsigned int FileLength = 0;
		File.seekg(0, File.end);
		FileLength = File.tellg();
		File.seekg(0, File.beg);

		if(!Passwd->empty())
		{
			File.read(Salt64, 24);
			string Salt = Base64Decode(string((const char*)Salt64, 24));
			File.read(IVStr, 24);
			Import64(string((const char*)IVStr, 24), IV);

			libscrypt_scrypt((const unsigned char*)Passwd->c_str(), Passwd->length(), (const unsigned char*)Salt.c_str(), 16, 16384, 14, 2, (unsigned char*)Hash, 32);

			//Clear password from memory once it is no longer needed
			Passwd->replace(0, Passwd->length(), Passwd->length(), '\x0');
			Passwd->clear();

			mpz_import(FinalKey.get_mpz_t(), 32, 1, 1, 0, 0, Hash);

			//Hash needs to be DELETED!
			for(int i = 0; i < 32; i++)
				Hash[i] = 0;
		}

		unsigned int n = FileLength-File.tellg();
		char* Cipher = new char[n];
		File.read(Cipher, n);

		AES crypt;
		string Original;
		string SCipher = "";
		for(unsigned int i = 0; i < n; i++)
			SCipher.push_back(Cipher[i]);

		if(FinalKey != 0)
		{
			try
			{
				Original = crypt.Decrypt(FinalKey, SCipher, IV);
			}
			catch(string e)
			{
				msgBox = new QMessageBox;
	            msgBox->setText(QString("Error: Incorrect password or format"));
	            msgBox->setIcon(QMessageBox::Warning);
	            msgBox->setStandardButtons(QMessageBox::Ok);
	            msgBox->exec();
	            delete msgBox;
				delete[] Cipher;
				File.close();
				return false;
			}
			mpz_xor(FinalKey.get_mpz_t(), FinalKey.get_mpz_t(), FinalKey.get_mpz_t());		//Should zero out all data of our hash/sym key
		}
		else
			Original = SCipher;

		int pos = Original.find('\n');
		if(Original.substr(0, pos) != "crypto-key-ecc")		//Check for proper format
		{
			cout << "Error: Incorrect password or format\n";
			delete[] Cipher;
			File.close();
			return false;
		}

		strcpy((char*)mult, Original.substr(pos+1).c_str());
		delete[] Cipher;
		File.close();
	}
	else
	{
		msgBox = new QMessageBox;
		msgBox->setText(QString("Error: Couldn't open:\n") + QString(FileLoc.c_str()));
		msgBox->setIcon(QMessageBox::Warning);
		msgBox->setStandardButtons(QMessageBox::Ok);
		msgBox->exec();
		delete msgBox;
		return false;
	}
	return true;
}

static void MakeCurvePublicKey(string FileLoc, uint8_t point[32])
{
	fstream File(FileLoc.c_str(), ios::out | ios::trunc);
	if(File.is_open())
	{
		File << "crypto-key-ecc\n";
		File.write((char*)point, 32);
		File.close();
	}
	else
	{
		QMessageBox* msgBox = new QMessageBox;
		msgBox->setText(QString("Error: Couldn't open:\n") + QString(FileLoc.c_str()));
		msgBox->setIcon(QMessageBox::Warning);
		msgBox->setStandardButtons(QMessageBox::Ok);
		msgBox->exec();
		delete msgBox;
	}
	return;
}

static void MakeCurvePrivateKey(string FileLoc, uint8_t mult[32], string* Passwd, char* Salt, mpz_class& IV)
{
	fstream File(FileLoc.c_str(), ios::out | ios::trunc);
	if(File.is_open())
	{
		string Original = "crypto-key-ecc\n";
		char Hash[32] = {0};
		mpz_class FinalKey = 0;

		if(!Passwd->empty())
		{
			libscrypt_scrypt((const unsigned char*)Passwd->c_str(), Passwd->length(), (const unsigned char*)Salt, 16, 16384, 14, 2, (unsigned char*)Hash, 32);

			//VERY IMPORTANT! Clear password from memory once it is no longer needed
			Passwd->replace(0, Passwd->length(), Passwd->length(), '\x0');
			Passwd->clear();

			mpz_import(FinalKey.get_mpz_t(), 32, 1, 1, 0, 0, Hash);

			//Hash needs to be DELETED!
			for(int i = 0; i < 32; i++)
				Hash[i] = 0;
		}

		for(unsigned int i = 0; i < 32; i++)
			Original.push_back((char)mult[i]);

		AES crypt;
		string Cipher;
		if(FinalKey != 0)
			Cipher = crypt.Encrypt(FinalKey, Original, IV);
		else
			Cipher = Original;

		if(FinalKey != 0)
		{
			mpz_xor(FinalKey.get_mpz_t(), FinalKey.get_mpz_t(), FinalKey.get_mpz_t());		//Should zero out all data of our AES key
			File.write(Base64Encode(Salt, 16).c_str(), 24);		//Write the salt in base64
			File.write(Export64(IV).c_str(), 24);				//Write the IV in base64
		}
		File.write(Cipher.c_str(), Cipher.length());			//Write all the "jibberish"
		File.close();
	}
	else
	{
		QMessageBox* msgBox = new QMessageBox;
		msgBox->setText(QString("Error: Couldn't open:\n") + QString(FileLoc.c_str()));
		msgBox->setIcon(QMessageBox::Warning);
		msgBox->setStandardButtons(QMessageBox::Ok);
		msgBox->exec();
		delete msgBox;
	}
	return;
}


/* ---------------------- RSA keys are still supported! -------------------------- */
static bool LoadRSAPublicKey(string FileLoc, mpz_class& Modulus, mpz_class& Enc)
{
    QMessageBox* msgBox;
	fstream File(FileLoc.c_str(), ios::in);
	if(File.is_open())
	{
		string Values;
		getline(File, Values);
		if(Values != "crypto-key-rsa")		//Check for proper format
		{
            msgBox = new QMessageBox;
            msgBox->setText(QString("This key was not saved in a recognized format."));
            msgBox->setIcon(QMessageBox::Warning);
            msgBox->setStandardButtons(QMessageBox::Ok);
            msgBox->exec();
            delete msgBox;

			return false;
		}
		Values = "";
		getline(File, Values);
		try
		{
			Import64(Values, Modulus);		//Decode Base64 Values and store into Modulus
		}
		catch(int e)
		{
            msgBox = new QMessageBox;
            msgBox->setText(QString("Could not load modulus from:\n") + QString(FileLoc.c_str()));
            msgBox->setIcon(QMessageBox::Warning);
            msgBox->setStandardButtons(QMessageBox::Ok);
            msgBox->exec();
            delete msgBox;

			return false;
		}
		
		Values = "";
		getline(File, Values);
		try
		{
			Import64(Values, Enc);		//Decode Base64 Values and store into Enc
		}
		catch(int e)
		{
            msgBox = new QMessageBox;
            msgBox->setText(QString("Could not load encryption value from:\n") + QString(FileLoc.c_str()));
            msgBox->setIcon(QMessageBox::Warning);
            msgBox->setStandardButtons(QMessageBox::Ok);
            msgBox->exec();
            delete msgBox;

			return false;
		}
		File.close();
	}
	else
	{
        msgBox = new QMessageBox;
        msgBox->setText(QString("Error: Couldn't open:\n") + QString(FileLoc.c_str()));
        msgBox->setIcon(QMessageBox::Warning);
        msgBox->setStandardButtons(QMessageBox::Ok);
        msgBox->exec();
        delete msgBox;

		return false;
	}
	return true;
}

static bool LoadRSAPrivateKey(string FileLoc, mpz_class& Dec, string* Passwd)
{
    QMessageBox* msgBox;
	fstream File(FileLoc.c_str(), ios::in);
	if(File.is_open())
	{
        char Salt64[24] = {0};
        char IVStr[24] = {0};
        mpz_class IV = 0;
        char Hash[32] = {0};
        mpz_class FinalKey = 0;
        int n = 0;

        unsigned int FileLength = 0;
        File.seekg(0, File.end);
        FileLength = File.tellg();
        File.seekg(0, File.beg);

        if(!Passwd->empty())
        {
            File.read(Salt64, 24);
            string Salt = Base64Decode(string((const char*)Salt64, 24));
            File.read(IVStr, 24);
            Import64(string((const char*)IVStr, 24), IV);

            n = libscrypt_scrypt((const unsigned char*)Passwd->c_str(), Passwd->length(), (const unsigned char*)Salt.c_str(), 16, 16384, 14, 2, (unsigned char*)Hash, 32);

            //Clear password from memory once it is no longer needed
            Passwd->replace(0, Passwd->length(), Passwd->length(), '\x0');
            Passwd->clear();

            mpz_import(FinalKey.get_mpz_t(), 32, 1, 1, 0, 0, Hash);

            //Hash needs to be DELETED!
            for(int i = 0; i < 32; i++)
                Hash[i] = 0;
        }

        n = FileLength-File.tellg();
        char* Cipher = new char[n];
        File.read(Cipher, n);

        AES crypt;
        string Original;
        string SCipher = "";
        for(int i = 0; i < n; i++)
            SCipher.push_back(Cipher[i]);

        if(FinalKey != 0)
        {
            try
            {
                Original = crypt.Decrypt(FinalKey, SCipher, IV);
            }
            catch(string e)
            {
                msgBox = new QMessageBox;
                msgBox->setText(QString("Error: Incorrect password or format"));
                msgBox->setIcon(QMessageBox::Warning);
                msgBox->setStandardButtons(QMessageBox::Ok);
                msgBox->exec();
                delete msgBox;
                delete[] Cipher;
                File.close();
                return false;
            }
            mpz_xor(FinalKey.get_mpz_t(), FinalKey.get_mpz_t(), FinalKey.get_mpz_t());		//Should zero out all data of our hash/sym key
        }
        else
            Original = SCipher;
		
		int pos = Original.find('\n');
		if(Original.substr(0, pos) != "crypto-key-rsa")		//Check for proper format
		{
            msgBox = new QMessageBox;
            msgBox->setText(QString("Error: Incorrect password or format"));
            msgBox->setIcon(QMessageBox::Warning);
            msgBox->setStandardButtons(QMessageBox::Ok);
            msgBox->exec();
            delete msgBox;
            delete[] Cipher;
            File.close();
			return false;
		}
		try
		{
			Import64(Original.substr(pos+1, string::npos), Dec);
		}
		catch(int e)
		{
            msgBox = new QMessageBox;
            msgBox->setText(QString("Could not load decryption value from:\n") + QString(FileLoc.c_str()));
            msgBox->setIcon(QMessageBox::Warning);
            msgBox->setStandardButtons(QMessageBox::Ok);
            msgBox->exec();
            delete msgBox;
			delete[] Cipher;
			File.close();
			return false;
		}
		delete[] Cipher;
		File.close();
	}
	else
	{
		msgBox = new QMessageBox;
        msgBox->setText(QString("Error: Couldn't open:\n") + QString(FileLoc.c_str()));
        msgBox->setIcon(QMessageBox::Warning);
        msgBox->setStandardButtons(QMessageBox::Ok);
        msgBox->exec();
        delete msgBox;

		return false;
	}
	return true;
}

static void MakeRSAPublicKey(string FileLoc, mpz_class& Modulus, mpz_class& Enc)
{
	fstream File(FileLoc.c_str(), ios::out | ios::trunc);
	if(File.is_open())
	{
		File << "crypto-key-rsa\n";
		File << Export64(Modulus) << "\n";
		File << Export64(Enc) << "\n";
		File.close();
	}
	else
	{
		QMessageBox* msgBox = new QMessageBox;
		msgBox->setText(QString("Error: Couldn't open:\n") + QString(FileLoc.c_str()));
		msgBox->setIcon(QMessageBox::Warning);
		msgBox->setStandardButtons(QMessageBox::Ok);
		msgBox->exec();
		delete msgBox;
	}
	return;
}

static void MakeRSAPrivateKey(string FileLoc, mpz_class& Dec, string* Passwd, char* Salt, mpz_class& IV)
{
	fstream File(FileLoc.c_str(), ios::out | ios::trunc);
	if(File.is_open())
	{
        string Original = "crypto-key-rsa\n";
        char Hash[32] = {0};
        mpz_class FinalKey = 0;
        if(!Passwd->empty())
        {
			libscrypt_scrypt((const unsigned char*)Passwd->c_str(), Passwd->length(), (const unsigned char*)Salt, 16, 16384, 14, 2, (unsigned char*)Hash, 32);

            //VERY IMPORTANT! Clear password from memory once it is no longer needed
            Passwd->replace(0, Passwd->length(), Passwd->length(), '\x0');
            Passwd->clear();

            mpz_import(FinalKey.get_mpz_t(), 32, 1, 1, 0, 0, Hash);

            //Hash needs to be DELETED!
            for(int i = 0; i < 32; i++)
                Hash[i] = 0;
        }
        Original += Export64(Dec);
        AES crypt;
        string Cipher;
        if(FinalKey != 0)
            Cipher = crypt.Encrypt(FinalKey, Original, IV);
        else
            Cipher = Original;

        if(FinalKey != 0)
        {
            mpz_xor(FinalKey.get_mpz_t(), FinalKey.get_mpz_t(), FinalKey.get_mpz_t());		//Should zero out all data of our hash/sym key
            File.write(Base64Encode(Salt, 16).c_str(), 24);		//Write the salt in base64
            File.write(Export64(IV).c_str(), 24);               //Write the IV in base64
        }
        File.write(Cipher.c_str(), Cipher.length());            //Write all the "jibberish"
        File.close();
	}
	else
	{
		QMessageBox* msgBox = new QMessageBox;
		msgBox->setText(QString("Error: Couldn't open:\n") + QString(FileLoc.c_str()));
		msgBox->setIcon(QMessageBox::Warning);
		msgBox->setStandardButtons(QMessageBox::Ok);
		msgBox->exec();
		delete msgBox;
	}
	return;
}
#endif