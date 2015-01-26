#include "mainwindow.h"
#include "ui_mainwindow.h"

#ifndef WINDOWS
	#include "CloseSocket.cpp"
#endif

MainWindow::MainWindow(QWidget *parent) :QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setWindowTitle("CryptoChatUI");

    timer.setInterval(10);
    timer.start();
    connect(&timer, SIGNAL(timeout()), this, SLOT(Update()));

    CreateActions();

	//Load Keys
	setTabOrder(ui->OpenPublicButton, ui->PasswordLine);
	setTabOrder(ui->PasswordLine, ui->OpenPrivateButton);

	//Options
	setTabOrder(ui->UseRSACB, ui->SendPublicCB);
	setTabOrder(ui->SendPublicCB, ui->BindPortLine);
	setTabOrder(ui->BindPortLine, ui->PeerPortLine);
	setTabOrder(ui->PeerPortLine, ui->SavePublicCB);
	setTabOrder(ui->SavePublicCB, ui->PeerPublicLocLine);
	setTabOrder(ui->PeerPublicLocLine, ui->ProxyAddrLine);
	setTabOrder(ui->ProxyAddrLine, ui->MyPublicLocLine);
	setTabOrder(ui->MyPublicLocLine, ui->MyPrivateLocLine);
    setTabOrder(ui->MyPrivateLocLine, ui->MyPrivatePassLine);

    ui->ConnectSettingsWidget->setHidden(true);
    ui->OptionsWidget->setHidden(true);
    ui->LoadMyKeysWidget->setHidden(true);
    ui->ReceiveText->setEnabled(false);
    ui->SendText->setEnabled(false);
    ui->SendButton->setEnabled(false);
    ui->PasswordLine->setEchoMode(QLineEdit::Password);
    ui->MyPrivatePassLine->setEchoMode(QLineEdit::Password);

    rng = new gmp_randclass(gmp_randinit_default);
    SeedAll();

    MyPTP.ui = ui;
    MyPTP.parent = this;
	MyPTP.RNG = rng;
	MyPTP.sfmt = &sfmt;
    MyPTP.Serv = 0;
    MyPTP.Client = 0;
    MyPTP.PeerPort = 5001;
	MyPTP.BindPort = 5001;
	MyPTP.ProxyPort = 0;
	MyPTP.StcClientMod = 0;
	MyPTP.StcClientE = 0;
	MyPTP.Sending = 0;
	MyPTP.HasEphemeralPub = false;
	MyPTP.HasStaticPub = false;
	MyPTP.UseRSA = false;

	LoadSettings();

	if(CanOpenFile("MyKeys.pub", ios_base::in) && CanOpenFile("MyKeys.priv", ios_base::in))
	{
		char* Passwd = new char[256];
		memset(Passwd, 0, 256);
		GetPasswordWidget w(Passwd, this);
		w.setWindowTitle("Private Key Password");
		if(w.exec() == QDialog::Accepted)
		{
			bool HadError = false;
			if(MyPTP.UseRSA)
			{
				if(!LoadRSAPrivateKey("MyKeys.priv", MyPTP.StcMyD, Passwd))
				{
					memset(Passwd, 0, 256);
					delete[] Passwd;
					mpz_xor(MyPTP.StcMyD.get_mpz_t(), MyPTP.StcMyD.get_mpz_t(), MyPTP.StcMyD.get_mpz_t());
					HadError = true;
				}
				else if(!LoadRSAPublicKey("MyKeys.pub", MyPTP.StcMyMod, MyPTP.StcMyE))
				{
					memset(Passwd, 0, 256);
					delete[] Passwd;
					MyPTP.StcMyMod = 0;
					MyPTP.StcMyE = 0;
					mpz_xor(MyPTP.StcMyD.get_mpz_t(), MyPTP.StcMyD.get_mpz_t(), MyPTP.StcMyD.get_mpz_t());
					mpz_xor(MyPTP.StcMyE.get_mpz_t(), MyPTP.StcMyE.get_mpz_t(), MyPTP.StcMyE.get_mpz_t());
					mpz_xor(MyPTP.StcMyMod.get_mpz_t(), MyPTP.StcMyMod.get_mpz_t(), MyPTP.StcMyMod.get_mpz_t());
					HadError = true;
				}
			}
			else
			{
				if(!LoadCurvePrivateKey("MyKeys.priv", MyPTP.StcCurveK, Passwd))
				{
					memset(Passwd, 0, 256);
					delete[] Passwd;
					memset((char*)MyPTP.StcCurveK, 0, 32);
					HadError = true;
				}
				else if(!LoadCurvePublicKey("MyKeys.pub", MyPTP.StcCurveP))
				{
					memset(Passwd, 0, 256);
					delete[] Passwd;
					memset((char*)MyPTP.StcCurveK, 0, 32);
					memset((char*)MyPTP.StcCurveP, 0, 32);
					HadError = true;
				}
			}
			if(!HadError)
				ui->actionLoad_Keys->setDisabled(true);
		}
	}
	#ifdef WINDOWS
		WSADATA wsaData;
		int error = WSAStartup(0x0202, &wsaData); //start and fill results into wsaData and output error

		if(error)
		{
			cout << "Startup error\n";
			return; //Something went wrong
		}
		if(wsaData.wVersion != 0x0202)
		{
			cout << "Wrong version\n";
			WSACleanup(); //Wrong wsaData version(not 2.2)
			return;
		}
	#endif
}

void MainWindow::CreateActions()
{
    ui->actionExit->setShortcut(QKeySequence::Close);
    connect(ui->actionExit, SIGNAL(triggered()), this, SLOT(SafeExit()));
    connect(ui->actionConnect, SIGNAL(triggered()), this, SLOT(ConnectSetup()));
    connect(ui->actionDisconnect, SIGNAL(triggered()), this, SLOT(Disconnect()));
    connect(ui->actionOptions, SIGNAL(triggered()), this, SLOT(OptionsSetup()));
    connect(ui->actionSend_File, SIGNAL(triggered()), this, SLOT(SendFileAction()));
    connect(ui->actionLoad_Keys, SIGNAL(triggered()), this, SLOT(LoadMyKeys()));
    connect(ui->actionLoad_Peer_Public_Key, SIGNAL(triggered()), this, SLOT(LoadPeerPublicKey()));
    connect(ui->actionHelp, SIGNAL(triggered()), this, SLOT(Help()));
    connect(ui->actionAbout, SIGNAL(triggered()), this, SLOT(About()));
	connect(ui->actionLicense, SIGNAL(triggered()), this, SLOT(License()));
	connect(ui->actionDonate, SIGNAL(triggered()), this, SLOT(Donate()));
	connect(ui->actionOwn, SIGNAL(triggered()), this, SLOT(GetOwnStaticPub()));
	connect(ui->actionPeer_s, SIGNAL(triggered()), this, SLOT(GetPeerStaticPub()));
}

void MainWindow::SeedAll()
{
	//Properly Seed
	uint32_t* seed = new uint32_t[20];
	#ifdef WINDOWS
		RtlGenRandom(seed, sizeof(uint32_t) * 20);
	#else
		FILE* random;
		random = fopen ("/dev/urandom", "r");		//Unix provides it, why not use it
		if(random == NULL)
		{
			fprintf(stderr, "Cannot open /dev/urandom!\n");
		}
		for(int i = 0; i < 20; i++)
		{
			fread(&seed[i], sizeof(uint32_t), 1, random);
			srand(seed[i]);							//seed the default random number generator
			rng->seed(seed[i]);						//seed the GMP random number generator
		}
		fclose(random);
	#endif
	sfmt_init_by_array(&sfmt, seed, 20);
	memset(seed, 0, sizeof(uint32_t) * 20);
	delete[] seed;
}

void MainWindow::ConnectSetup()
{
    bool shown = ui->ConnectSettingsWidget->isVisible();
    ui->ConnectSettingsWidget->setVisible(!shown);
    ui->LoadMyKeysWidget->setHidden(true);
    ui->OptionsWidget->setHidden(true);
    ui->ReceiveText->setHidden(!shown);
    ui->SendText->setHidden(!shown);
    ui->SendButton->setHidden(!shown);
	if((MyPTP.UseRSA && MyPTP.StcMyMod != 0) || (!MyPTP.UseRSA && MyPTP.StcCurveK[31] != 0))
	{
		ui->PublicKeyInfoLabel->setText(tr("Public/private keys are set."));
		ui->GenerateButton->setVisible(false);
		ui->actionLoad_Keys->setDisabled(true);
		if(!ui->PeerIPText->text().isEmpty())
		    ui->ConnectButton->setEnabled(true);
	}
	else
	{
		ui->PublicKeyInfoLabel->setText(tr("Since you have not manually loaded a public/private key pair, one can be<br/>\
										   generated for this session and exported to files for future use. It is <b>highly<br/>\
										   recommended</b> that you can confirm in person or across a very trusted medium<br/>\
										   that your peers have received and saved your public key to ensure security<br/>\
										   against a man-in-the-middle actively injecting false public keys as belonging to<br/>\
										   you."));
	}
}

void MainWindow::Disconnect()
{
    if(MyPTP.Serv || MyPTP.Client)
	{
        MyPTP.ContinueLoop = false;
		ui->StatusLabel->setText(QString("Not Connected"));
	}
    else
    {
        msgBox = new QMessageBox;
        msgBox->setText(tr("Uhhh... You weren't connected.."));
        msgBox->setIcon(QMessageBox::Question);
        msgBox->setStandardButtons(QMessageBox::Yes | QMessageBox::No);
        if(msgBox->exec() == QMessageBox::No)
        {
            msgBox->setText(tr("What.. WHAT!!!! Thats bull crap!"));
            msgBox->setIcon(QMessageBox::Warning);
            msgBox->setStandardButtons(QMessageBox::Yes | QMessageBox::No);
            if(msgBox->exec() == QMessageBox::No)
            {
                msgBox->setText(tr("... You're a jerk... Just think about that"));
                msgBox->setIcon(QMessageBox::Question);
                msgBox->setStandardButtons(QMessageBox::Ok | QMessageBox::No);
                if(msgBox->exec() == QMessageBox::No)
                {
                    msgBox->setText(tr("Admit you're a jerk!!!"));
                    msgBox->setIcon(QMessageBox::Warning);
                    msgBox->setStandardButtons(QMessageBox::Ok | QMessageBox::No);
                    int ans = QMessageBox::No;
                    int count = 0;
                    while(ans != QMessageBox::Ok)
                    {
                        ans = msgBox->exec();
                        count++;
                        if(count == 25)
                        {
                            msgBox->setText(tr("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH!!!!!!!!!!!!!!!!\nAAAAAAAHHHHHHHHHHHHHHHHHHHHHHH!!!!!!!!!!!!!!!!!!!!\nAAAAAAAAAAAAAHHHHHHHHHHHHHHHHHHHHHHH!!!!!!!!!!!!!!!!!!!!!"));
                            msgBox->setIcon(QMessageBox::Warning);
                            msgBox->setStandardButtons(QMessageBox::Ok);
                            ans = msgBox->exec();
                        }
                    }
                    if(count != 25)
                    {
                        msgBox->setText(tr("Finally... Now go be stupid somewhere else... (jerk)"));
                        msgBox->setIcon(QMessageBox::Information);
                        msgBox->setStandardButtons(QMessageBox::Close);
                        msgBox->exec();
                    }
                    else
                    {
                        msgBox->setText(tr("I'm sorry about that... I'm going to take my medication...."));
                        msgBox->setIcon(QMessageBox::Information);
                        msgBox->setStandardButtons(QMessageBox::Close);
                        msgBox->exec();
                    }
                }
            }
            else
            {
                msgBox->setText(tr("Thank you! Now just stop wasting both our time.."));
                msgBox->setIcon(QMessageBox::Information);
                msgBox->setStandardButtons(QMessageBox::Close);
                msgBox->exec();
            }
        }
        else
        {
            msgBox->setText(tr("Then why did you try to \"Disconnect\"?\nJust use your head."));
            msgBox->setIcon(QMessageBox::Question);
            msgBox->setStandardButtons(QMessageBox::Ok);
            msgBox->exec();
        }
        delete msgBox;
    }
}

void MainWindow::OptionsSetup()
{
    bool shown = ui->OptionsWidget->isVisible();
    ui->LoadMyKeysWidget->setHidden(true);
    ui->ConnectSettingsWidget->setHidden(true);
    ui->OptionsWidget->setVisible(!shown);
    ui->ReceiveText->setHidden(!shown);
    ui->SendText->setHidden(!shown);
    ui->SendButton->setHidden(!shown);

    ui->PeerPortLine->setText(QString::number(MyPTP.PeerPort));
	ui->BindPortLine->setText(QString::number(MyPTP.BindPort));
}
void MainWindow::on_SavePublicCB_toggled(bool checked)
{
    ui->PeerPublicLocLine->setEnabled(checked);
    if(!checked)
        ui->PeerPublicLocLine->clear();
}
void MainWindow::on_UseRSACB_toggled(bool checked)
{
	MyPTP.UseRSA = checked;
	SaveSettings();
}

void MainWindow::on_CreateKeysButton_clicked()
{
    if(ui->MyPrivateLocLine->text().size() != 0 && ui->MyPublicLocLine->text().size() != 0)
    {
		if((MyPTP.UseRSA && MyPTP.StcMyMod == 0) || (!MyPTP.UseRSA && MyPTP.StcCurveK[31] == 0))
		{
			msgBox = new QMessageBox;
			msgBox->setText(tr("Since no public keys are in memory,\nwill generate new ones."));
	        msgBox->setIcon(QMessageBox::Information);
	        msgBox->setStandardButtons(QMessageBox::Ok);
	        msgBox->exec();
	        delete msgBox;

			if(MyPTP.UseRSA)
				NewRSA.KeyGenerator(MyPTP.StcMyD, MyPTP.StcMyE, MyPTP.StcMyMod, *rng);
			else
				ECC_Curve25519_Create(MyPTP.StcCurveP, MyPTP.StcCurveK, sfmt);
		}

        const char* Passwd = ui->MyPrivatePassLine->text().toStdString().c_str();

		char* SaltStr = new char[16];
		sfmt_fill_small_array64(&sfmt, (uint64_t*)SaltStr, 2);
		uint8_t* TempIV = new uint8_t[16];
		sfmt_fill_small_array64(&sfmt, (uint64_t*)TempIV, 2);

		if(MyPTP.UseRSA)
		{
			MakeRSAPrivateKey(ui->MyPrivateLocLine->text().toStdString(), MyPTP.StcMyD, Passwd, SaltStr, TempIV);
			ui->MyPrivatePassLine->clear();
			MakeRSAPublicKey(ui->MyPublicLocLine->text().toStdString(), MyPTP.StcMyMod, MyPTP.StcMyE);
		}
		else
		{
			MakeCurvePrivateKey(ui->MyPrivateLocLine->text().toStdString(), MyPTP.StcCurveK, Passwd, SaltStr, TempIV);
			ui->MyPrivatePassLine->clear();
			MakeCurvePublicKey(ui->MyPublicLocLine->text().toStdString(), MyPTP.StcCurveP);
		}

		delete[] SaltStr;
		delete[] TempIV;
		if(CanOpenFile(ui->MyPrivateLocLine->text().toStdString()) && CanOpenFile(ui->MyPublicLocLine->text().toStdString()))
			ui->StatusLabel->setText(tr("Generated Keys Successfully"));
	}
    else
    {
		msgBox = new QMessageBox;
        msgBox->setText(tr("Missing file locations."));
        msgBox->setIcon(QMessageBox::Warning);
        msgBox->setStandardButtons(QMessageBox::Ok);
        msgBox->exec();
        delete msgBox;
    }
	return;
}
void MainWindow::on_PeerPortLine_textEdited(const QString &arg1)
{
    bool b;
    int i = arg1.toInt(&b);
    if(b)
        MyPTP.PeerPort = i;
	SaveSettings();
}
void MainWindow::on_BindPortLine_textEdited(const QString &arg1)
{
    bool b;
    int i = arg1.toInt(&b);
    if(b)
        MyPTP.BindPort = i;
	SaveSettings();
}

void MainWindow::on_ProxyAddrLine_textEdited(const QString &arg1)
{
	SaveSettings();
}

void MainWindow::LoadMyKeys()
{
    bool shown = ui->LoadMyKeysWidget->isVisible();
    ui->LoadMyKeysWidget->setVisible(!shown);
    ui->ConnectSettingsWidget->setHidden(true);
    ui->OptionsWidget->setHidden(true);
    ui->ReceiveText->setHidden(!shown);
    ui->SendText->setHidden(!shown);
    ui->SendButton->setHidden(!shown);
}
void MainWindow::on_OpenPublicButton_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this, tr("Open File"), "", tr("All Files (*)"));

	if(MyPTP.UseRSA)
	{
		if(fileName.size() == 0 || !LoadRSAPublicKey(fileName.toStdString(), MyPTP.StcMyMod, MyPTP.StcMyE))
		{
			MyPTP.StcMyMod = 0;
			MyPTP.StcMyE = 0;
		}
		else
		{
			ui->PublicKeyLocLabel->setText(fileName);
		}
	}
	else
	{
		if(fileName.size() == 0 || !LoadCurvePublicKey(fileName.toStdString(), MyPTP.StcCurveP))
		{
			memset((char*)MyPTP.StcCurveP, 0, 32);
		}
		else
			ui->PublicKeyLocLabel->setText(fileName);
	}
}
void MainWindow::on_OpenPrivateButton_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this, tr("Open File"), "", tr("All Files (*)"));
    const char* Pass = ui->PasswordLine->text().toStdString().c_str();
	if(MyPTP.UseRSA)
	{
		if(fileName.size() == 0 || !LoadRSAPrivateKey(fileName.toStdString(), MyPTP.StcMyD, Pass))
			mpz_xor(MyPTP.StcMyD.get_mpz_t(), MyPTP.StcMyD.get_mpz_t(), MyPTP.StcMyD.get_mpz_t());
		else
			ui->PrivateKeyLocLabel->setText(fileName);
	}
	else
	{
		if(fileName.size() == 0 || !LoadCurvePrivateKey(fileName.toStdString(), MyPTP.StcCurveK, Pass))
			memset((char*)MyPTP.StcCurveK, 0, 32);
		else
			ui->PrivateKeyLocLabel->setText(fileName);
	}
	ui->PasswordLine->clear();
}
void MainWindow::on_OKButton_clicked()
{
    ui->LoadMyKeysWidget->setHidden(true);
    ui->ConnectSettingsWidget->setHidden(true);
    ui->ReceiveText->setHidden(false);
    ui->SendText->setHidden(false);
    ui->SendButton->setHidden(false);
}

void MainWindow::LoadPeerPublicKey()
{
    QString fileName = QFileDialog::getOpenFileName(this, tr("Open File"), "", tr("All Files (*)"));
    if(MyPTP.UseRSA)
	{
		if(fileName.size() == 0 || !LoadRSAPublicKey(fileName.toStdString(), MyPTP.StcClientMod, MyPTP.StcClientE))
		{
		    MyPTP.StcClientMod = 0;
		    MyPTP.StcClientE = 0;
		}
	}
	else
	{
		if(fileName.size() == 0 || !LoadCurvePublicKey(fileName.toStdString(), MyPTP.StcCurvePPeer))
		{
		    memset((char*)MyPTP.StcCurvePPeer, 0, 32);
		}
	}
}

void MainWindow::Help()
{
    msgBox = new QMessageBox(this);
	msgBox->setWindowTitle("Help");
    msgBox->setText(tr("Don't understand how all this encryption stuff fits togther?<br/>\
						<b>Consult the book of knowledge!</b><br/>\
						<a href=\"http://en.wikipedia.org/wiki/Public-key_cryptography\">Public Key Cryptography</a><br/>\
						<a href=\"http://en.wikipedia.org/wiki/Elliptic_curve_Diffie%E2%80%93Hellman\">ECDH</a><br/>\
						<a href=\"http://simple.wikipedia.org/wiki/RSA_%28algorithm%29\">RSA</a><br/>\
						<a href=\"http://en.wikipedia.org/wiki/Symmetric-key_algorithm\">Symmetric Key Cryptography</a><br/>\
						<a href=\"http://en.wikipedia.org/wiki/Advanced_Encryption_Standard\">AES</a><br/>\
						<a href=\"http://en.wikipedia.org/wiki/Scrypt\">Scrypt</a><br/><br/>\
						Still have questions? Maybe I'll make a website explaining usage in detail... Someday..."));

	msgBox->setTextFormat(Qt::RichText);
	msgBox->setTextInteractionFlags(Qt::TextBrowserInteraction);

    msgBox->setIcon(QMessageBox::Information);
    msgBox->setStandardButtons(QMessageBox::Ok);
    msgBox->exec();
    delete msgBox;
}

void MainWindow::About()
{
    msgBox = new QMessageBox(this);
	msgBox->setWindowTitle("About");
    msgBox->setText(tr("This is a GUI version of the original CryptoChat.\
					   It was built to maintain complete compatability \
					   between the two versions and so, has the same \
					   capabilities and functionality.<br/><br/>\
					   A secure, chat program that uses ECC Curve25519 or 4096 bit RSA keys to exchange a \
					   256 bit AES key, which is used for the rest of the chat. It uses GMP for it's large number arithmetic. \
					   The public and private keys generated can be stored to files to be reused. The private key may be encrypted\
					   with 256 bit AES using a randomly generated IV and a key derived from a password using scrypt with a \
					   random salt. It is the successor to the original CryptoChat and maintains complete compatibility with it, \
					   but with a nice Qt based graphical interface. Enjoy top-notch, uber-level secure chats (most often about \
					   security, you know it's true :P ).<br/><br/>\
					   \tDeveloped by ryco117"));
	msgBox->setTextFormat(Qt::RichText);
    msgBox->setIcon(QMessageBox::Information);
    msgBox->setStandardButtons(QMessageBox::Ok);
    msgBox->exec();
    delete msgBox;
}

void MainWindow::License()
{
    msgBox = new QMessageBox(this);
	msgBox->setWindowTitle("License");
    msgBox->setText(tr("Copyright (C) 2014  Ryan Andersen<br/>\
<br/>\
				       This program is free software: you can redistribute it and/or modify<br/>\
				       it under the terms of the GNU General Public License as published by<br/>\
				       the Free Software Foundation, either version 3 of the License, or<br/>\
				       (at your option) any later version.<br/>\
<br/>\
				       This program is distributed in the hope that it will be useful,<br/>\
				       but WITHOUT ANY WARRANTY; without even the implied warranty of<br/>\
				       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the<br/>\
				       GNU General Public License for more details.<br/>\
<br/>\
				       You should have received a copy of the GNU General Public License<br/>\
				       along with this program.  If not, see <a href=\"http://www.gnu.org/licenses/\">&lt;http://www.gnu.org/licenses/&gt;</a>."));
	msgBox->setTextFormat(Qt::RichText);
    msgBox->setIcon(QMessageBox::Information);
    msgBox->setStandardButtons(QMessageBox::Ok);
    msgBox->exec();
    delete msgBox;
}

void MainWindow::Donate()
{
	DonateWindow w(this);
	w.setWindowTitle("Donate");
	w.exec();
}

void MainWindow::GetOwnStaticPub()
{
    msgBox = new QMessageBox(this);
	msgBox->setWindowTitle("Own Static Public Key");
	msgBox->setTextFormat(Qt::RichText);
    msgBox->setIcon(QMessageBox::Information);
    msgBox->setStandardButtons(QMessageBox::Ok);

	if((MyPTP.StcMyMod != 0 && MyPTP.UseRSA) || (MyPTP.StcCurveK[31] != 0 && !MyPTP.UseRSA))
	{
		char* StcPubKey64;
		if(MyPTP.UseRSA)
			StcPubKey64 = Export64(MyPTP.StcMyMod);
		else
			StcPubKey64 = Base64Encode((char*)MyPTP.StcCurveP, 32);

		msgBox->setText(StcPubKey64);
		msgBox->exec();
		delete[] StcPubKey64;
	}
	else
	{
		msgBox->setText(tr("Static public key not set"));
		msgBox->exec();
	}

    delete msgBox;
}

void MainWindow::GetPeerStaticPub()
{
    msgBox = new QMessageBox(this);
	msgBox->setWindowTitle("Peer Static Public Key");
	msgBox->setTextFormat(Qt::RichText);
    msgBox->setIcon(QMessageBox::Information);
    msgBox->setStandardButtons(QMessageBox::Ok);

	if(MyPTP.HasStaticPub)
	{
		char* StcPubKey64;
		if(MyPTP.UseRSA)
			StcPubKey64 = Export64(MyPTP.StcClientMod);
		else
			StcPubKey64 = Base64Encode((char*)MyPTP.StcCurvePPeer, 32);

		msgBox->setText(StcPubKey64);
		msgBox->exec();
		delete[] StcPubKey64;
	}
	else
	{
		msgBox->setText(tr("Static public key not set"));
		msgBox->exec();
	}

    delete msgBox;
}

void MainWindow::SendFileAction()
{
    if(MyPTP.GConnected)
        MyPTP.SendFilePt1();
    else
    {
        msgBox = new QMessageBox;
        msgBox->setText(tr("You can't do that right now."));
        msgBox->setIcon(QMessageBox::Warning);
        msgBox->setStandardButtons(QMessageBox::Ok);
        msgBox->exec();
        delete msgBox;
    }
}

void MainWindow::on_ConnectButton_clicked()
{
	StartConnection();
}

void MainWindow::Update()
{
    if(!MyPTP.GConnected && MyPTP.SentStuff == 3)
    {
        ui->LoadMyKeysWidget->setHidden(true);
        ui->ConnectSettingsWidget->setHidden(true);
		ui->OptionsWidget->setHidden(true);

        ui->ReceiveText->setHidden(false);
        ui->SendText->setHidden(false);
        ui->SendButton->setHidden(false);

        ui->SendText->setEnabled(true);
        ui->ReceiveText->setEnabled(true);
        ui->SendButton->setEnabled(true);

		ui->SendText->activateWindow();
		ui->SendText->setFocus();

        MyPTP.GConnected = true;
		ui->StatusLabel->setText(QString("Connected!"));
    }
    if(MyPTP.Serv > 0)
    {
        int error;
        if(MyPTP.ContinueLoop)
		{
            error = MyPTP.Update();
		}
        else
        {
            error = 1;
        }

        if(error != 0)
        {
			for(int i = 0; i < MyPTP.GetMaxClients(); i++)
                if(MyPTP.MySocks[i] > 0)
                    closesocket(MyPTP.MySocks[i]);
			delete[] MyPTP.MySocks;

            closesocket(MyPTP.Serv);
			closesocket(MyPTP.Client);
            MyPTP.Serv = 0;
            MyPTP.Client = 0;
			MyPTP.ClntAddr.clear();
            MyPTP.Sending = 0;
            MyPTP.SentStuff = 0;
            MyPTP.GConnected = false;
            MyPTP.ConnectedClnt = false;
            MyPTP.ConnectedSrvr = false;
			MyPTP.HasEphemeralPub = false;
			MyPTP.HasStaticPub = false;

			//Clear single use values
			memset(MyPTP.SymKey, 0, 32);
			if(MyPTP.UseRSA)
			{
				mpz_xor(MyPTP.EphMyE.get_mpz_t(), MyPTP.EphMyE.get_mpz_t(), MyPTP.EphMyE.get_mpz_t());
				mpz_xor(MyPTP.EphMyD.get_mpz_t(), MyPTP.EphMyD.get_mpz_t(), MyPTP.EphMyD.get_mpz_t());
				mpz_xor(MyPTP.EphMyMod.get_mpz_t(), MyPTP.EphMyMod.get_mpz_t(), MyPTP.EphMyMod.get_mpz_t());
				MyPTP.StcClientMod = 0;
	            MyPTP.StcClientE = 0;
			}
			else
			{
				memset(MyPTP.SharedKey, 0, 32);
				memset((char*)MyPTP.EphCurveP, 0, 32);
				memset((char*)MyPTP.EphCurveK, 0, 32);
				memset((char*)MyPTP.StcCurvePPeer, 0, 32);
			}

            ui->ReceiveText->append(tr("Disconnected from peer."));
            ui->SendButton->setDisabled(true);
            ui->SendText->setDisabled(true);
            ui->ReceiveText->setDisabled(true);
			ui->ConnectButton->setDisabled(true);
			ui->StatusLabel->setText(QString("Not Connected"));

			if(error < 0)
			{
				msgBox = new QMessageBox;
				msgBox->setText(QString("Update loop failed, error code ") + QString::number(error));
				msgBox->setIcon(QMessageBox::Warning);
				msgBox->setStandardButtons(QMessageBox::Ok);
				msgBox->exec();
				delete msgBox;
			}
        }
    }
}
void MainWindow::on_SendButton_clicked()
{
    MyPTP.SendMessage();
}
void MainWindow::on_SendText_returnPressed()
{
    MyPTP.SendMessage();
}

void MainWindow::on_GenerateButton_clicked()
{
	char* Passwd = new char[256];
	memset(Passwd, 0, 256);
	QString PubLoc;
	QString PrivLoc;
	CreateKeysField w(&PubLoc, &PrivLoc, Passwd, this);
	w.setWindowTitle("Create Keys");
	if(w.exec() == QDialog::Rejected)
	{
		ui->StatusLabel->setText(QString("Cancelled creating keys"));
		return;
	}

	if(ui->UseRSACB->isChecked())
	{
		NewRSA.KeyGenerator(MyPTP.StcMyD, MyPTP.StcMyE, MyPTP.StcMyMod, *rng);
	}
	else
	{
		ECC_Curve25519_Create(MyPTP.StcCurveP, MyPTP.StcCurveK, sfmt);
	}

	char* SaltStr = new char[16];
	sfmt_fill_small_array64(&sfmt, (uint64_t*)SaltStr, 2);
	uint8_t* TempIV = new uint8_t[16];
	sfmt_fill_small_array64(&sfmt, (uint64_t*)TempIV, 2);

	if(MyPTP.UseRSA)
	{
		MakeRSAPrivateKey(PrivLoc.toStdString(), MyPTP.StcMyD, Passwd, SaltStr, TempIV);
		ui->MyPrivatePassLine->clear();
		MakeRSAPublicKey(PubLoc.toStdString(), MyPTP.StcMyMod, MyPTP.StcMyE);
	}
	else
	{
		MakeCurvePrivateKey(PrivLoc.toStdString(), MyPTP.StcCurveK, Passwd, SaltStr, TempIV);
		ui->MyPrivatePassLine->clear();
		MakeCurvePublicKey(PubLoc.toStdString(), MyPTP.StcCurveP);
	}
	memset(Passwd, 0, 256);
	delete[] Passwd;

	ui->PublicKeyInfoLabel->setText(tr("Public/private keys are set."));
	ui->GenerateButton->setVisible(false);
	ui->actionLoad_Keys->setDisabled(true);
	ui->StatusLabel->setText(QString("Private/Public keys created!"));
	if(!ui->PeerIPText->text().isEmpty())
        ui->ConnectButton->setEnabled(true);
}

void MainWindow::on_PeerIPText_textEdited(const QString &arg1)
{
	if(((MyPTP.UseRSA && MyPTP.StcMyMod != 0) || (!MyPTP.UseRSA && MyPTP.StcCurveK[31] != 0)) && !arg1.isEmpty())	//For a proper Curve25519, k[31] can't be zero (bit 254 always set) and so this checks if we generated the curve
		ui->ConnectButton->setEnabled(true);
	else
		ui->ConnectButton->setDisabled(true);
}
void MainWindow::on_PeerIPText_returnPressed()
{
    if(ui->ConnectButton->isEnabled())
    {
		StartConnection();
    }
	return;
}

void MainWindow::StartConnection()
{
	MyPTP.ClntAddr = ui->PeerIPText->text().toStdString();
    if(!MyPTP.Serv)
    {
		string ProxyAddr = ui->ProxyAddrLine->text().toStdString();

		//if set a proxy	  but	address doesn't contain colon
		if(!ProxyAddr.empty() && (ProxyAddr.find(":") == string::npos))
		{
			ui->StatusLabel->setText(QString("Improper proxy address"));
			return;
		}
		if(!ProxyAddr.empty())
		{
			MyPTP.ProxyAddr = ProxyAddr.substr(0, ProxyAddr.find(":"));
			MyPTP.ProxyPort = atoi(ProxyAddr.substr(ProxyAddr.find(":") + 1).c_str());
			MyPTP.ProxyRequest = false;
		}
		else
		{
			MyPTP.ProxyAddr.clear();
			MyPTP.ProxyPort = 0;
		}

		//Fill all the One-Use encryption values
		sfmt_fill_small_array64(&sfmt, (uint64_t*)MyPTP.SymKey, 4);			//Create a 256 bit long random value as our sym key
		char* StcPubKey64;
		if(MyPTP.UseRSA)
		{
			NewRSA.KeyGenerator(MyPTP.EphMyD, MyPTP.EphMyE, MyPTP.EphMyMod, *rng);
			StcPubKey64 = Export64(MyPTP.StcMyMod);
		}
		else
		{
			ECC_Curve25519_Create(MyPTP.EphCurveP, MyPTP.EphCurveK, sfmt);
			StcPubKey64 = Base64Encode((char*)MyPTP.StcCurveP, 32);
		}

		ui->ReceiveText->append(QString("Static public key: ") + QString(StcPubKey64) + QString("\n"));
		delete[] StcPubKey64;

        int error = MyPTP.StartServer(1, ui->SendPublicCB->isChecked(), ui->PeerPublicLocLine->text().toStdString());
        if(error)
        {
            msgBox = new QMessageBox;
            msgBox->setText(QString("Could not start server, error code ") + QString::number(error));
            msgBox->setIcon(QMessageBox::Warning);
            msgBox->setStandardButtons(QMessageBox::Ok);
            msgBox->exec();
			delete msgBox;
			ui->StatusLabel->setText(QString("Not Connected"));
        }
		else
			ui->StatusLabel->setText(QString("Attempting to connect to address..."));
    }
	return;
}

void MainWindow::SafeExit()
{
    if(MyPTP.Serv > 0)
        closesocket(MyPTP.Serv);
    MainWindow::close();
}

bool MainWindow::SaveSettings()
{
	fstream Config;
	Config.open(".chat.config", ios_base::out | ios_base::trunc);
	if(Config.is_open())
	{
		Config << "#####################################################################################################################################################################################\n";
		Config << "#### THIS IS AN AUTO GENERATED FILE. DON'T EDIT, USE OPTIONS WINDOW INSTEAD (Case sensitive in case you don't care for warnings ;) but this is regenerated every options change) ####\n";
		Config << "#####################################################################################################################################################################################\n\n";
		if(MyPTP.UseRSA)
			Config << "UseRSA=true\n";
		Config << "BindPort=" << ui->BindPortLine->text().toStdString() << endl;
		Config << "PeerPort=" << ui->PeerPortLine->text().toStdString() << endl;
		if(!ui->ProxyAddrLine->text().isEmpty())
			Config << "UseProxy=" << ui->ProxyAddrLine->text().toStdString() << endl;
	}
	else
		return false;
	return true;
}

bool MainWindow::LoadSettings()
{
	fstream Config;
	Config.open(".chat.config", ios_base::in);
	if(Config.is_open())
	{
		string line = "";
		string Vals[4] = {"UseRSA", "BindPort", "PeerPort", "UseProxy"};
		while(!Config.eof())
		{
			getline(Config, line);
			if(line[0] != '#' && line.length() != 0)
			{
				for(int i = 0; i < 4; i++)
				{
					if(line.substr(0, Vals[i].size()) == Vals[i])
					{
						line = line.substr(Vals[i].size() + 1);
						switch(i)
						{
							case 0:
							{
								if(line == "true")
								{
									MyPTP.UseRSA = true;
									ui->UseRSACB->setChecked(true);
								}
								else if(line == "false")
								{
									MyPTP.UseRSA = true;
									ui->UseRSACB->setChecked(true);
								}
								break;
							}
							case 1:
							{
								bool b;
								int port = QString(line.c_str()).toInt(&b);
								if(b)
								{
									MyPTP.BindPort = port;
									ui->BindPortLine->setText(QString(line.c_str()));
								}
								break;
							}
							case 2:
							{
								bool b;
								int port = QString(line.c_str()).toInt(&b);
								if(b)
								{
									MyPTP.PeerPort = port;
									ui->PeerPortLine->setText(QString(line.c_str()));
								}
								break;
							}
							case 3:
							{
								ui->ProxyAddrLine->setText(QString(line.c_str()));
								break;
							}
						}
					}
				}
			}
		}
	}
	else
		return false;
	return true;
}

MainWindow::~MainWindow()
{
	if(MyPTP.Serv)
	{
		for(int i = 0; i < MyPTP.GetMaxClients(); i++)
		    if(MyPTP.MySocks[i] > 0)
		        closesocket(MyPTP.MySocks[i]);
		delete[] MyPTP.MySocks;

	    closesocket(MyPTP.Serv);
		closesocket(MyPTP.Client);
	}

	//Need proper string handling in the future!! (This will almost certainly do nothing to zero from memory)
	ui->ReceiveText->clear();
	ui->PasswordLine->clear();
	ui->MyPrivatePassLine->clear();

	//Clear critical values (and some public)
	memset(MyPTP.SymKey, 0, 32);
	if(MyPTP.UseRSA)
	{
		mpz_xor(MyPTP.EphMyE.get_mpz_t(), MyPTP.EphMyE.get_mpz_t(), MyPTP.EphMyE.get_mpz_t());
		mpz_xor(MyPTP.EphMyD.get_mpz_t(), MyPTP.EphMyD.get_mpz_t(), MyPTP.EphMyD.get_mpz_t());
	}
	else
	{
		memset(MyPTP.SharedKey, 0, 32);
		memset((char*)MyPTP.EphCurveP, 0, 32);
		memset((char*)MyPTP.EphCurveK, 0, 32);
		memset((char*)MyPTP.StcCurveP, 0, 32);
		memset((char*)MyPTP.StcCurveK, 0, 32);
	}

    delete ui;
    delete rng;
}