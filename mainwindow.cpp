#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "CloseSocket.cpp"

MainWindow::MainWindow(QWidget *parent) :QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setWindowTitle("CryptoChatUI");

    timer.setInterval(0);
    timer.start();
    connect(&timer, SIGNAL(timeout()), this, SLOT(Update()));

    CreateActions();

    ui->ConnectSettingsWidget->setHidden(true);
    ui->OptionsWidget->setHidden(true);
    ui->LoadMyKeysWidget->setHidden(true);
    ui->ReceiveText->setEnabled(false);
    ui->SendText->setEnabled(false);
    ui->SendButton->setEnabled(false);
    ui->PasswordLine->setEchoMode(QLineEdit::Password);
    ui->MyPrivatePassLine->setEchoMode(QLineEdit::Password);

    rng = new gmp_randclass(gmp_randinit_default);
    GMPSeed(rng);

    MyPTP.ui = ui;
    MyPTP.parent = this;
    MyPTP.Serv = 0;
    MyPTP.Client = 0;
    MyPTP.Port = 5001;
    MyPTP.ClientMod = 0;
    MyPTP.ClientE = 0;
    MyPTP.Sending = 0;
    MyPTP.SentStuff = 0;
    MyPTP.RNG = rng;
	MyPTP.HasPub = false;
	MyPTP.UseRSA = false;

    MyPTP.SymKey = rng->get_z_bits(256);
    Keys[0] = 65537;
    Mod = 0;
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
}

void MainWindow::SafeExit()
{
    if(MyPTP.Serv > 0)
        closesocket(MyPTP.Serv);
    MainWindow::close();
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
	if(IsIP(ui->PeerIPText->text().toStdString()) && ((MyPTP.UseRSA && MyPTP.MyMod != 0) || (!MyPTP.UseRSA && MyPTP.CurveK[31] != 0)))
        ui->ConnectButton->setEnabled(true);
}

void MainWindow::Disconnect()
{
    if(MyPTP.Serv)
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

    ui->PortLine->setText(QString::number(MyPTP.Port));
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
}
void MainWindow::on_CreateKeysButton_clicked()
{
    if(ui->MyPrivateLocLine->text().size() != 0 && ui->MyPublicLocLine->text().size() != 0)
    {
		if((MyPTP.UseRSA && MyPTP.MyMod == 0) || (!MyPTP.UseRSA && MyPTP.CurveK[31] == 0))
		{
			msgBox->setText(tr("Since no public keys are in memory,\nwill generate new ones."));
	        msgBox->setIcon(QMessageBox::Information);
	        msgBox->setStandardButtons(QMessageBox::Ok);
	        msgBox->exec();
	        delete msgBox;
			if(MyPTP.UseRSA)
			{
				NewRSA.KeyGenerator(Keys, Mod, *rng, true, false);
				MyPTP.MyMod = Mod;
				MyPTP.MyE = Keys[0];
				MyPTP.MyD = Keys[1];
			}
			else
				ECC_Curve25519_Create(MyPTP.CurveP, MyPTP.CurveK, *rng);
		}

        string Passwd = ui->MyPrivatePassLine->text().toStdString();
		ui->MyPrivateLocLine->text().toStdWString();

		char SaltStr[16] = {0};

		mpz_class Salt = rng->get_z_bits(128);
		mpz_export(SaltStr, 0, 1, 1, 0, 0, Salt.get_mpz_t());
		mpz_class TempIV = rng->get_z_bits(128);

		if(MyPTP.UseRSA)
		{
			MakeRSAPrivateKey(ui->MyPrivateLocLine->text().toStdString(), MyPTP.MyD, &Passwd, SaltStr, TempIV);
			ui->MyPrivatePassLine->clear();
			MakeRSAPublicKey(ui->MyPublicLocLine->text().toStdString(), MyPTP.MyMod, MyPTP.MyE);
		}
		else
		{
			MakeCurvePrivateKey(ui->MyPrivateLocLine->text().toStdString(), MyPTP.CurveK, &Passwd, SaltStr, TempIV);
			ui->MyPrivatePassLine->clear();
			MakeCurvePublicKey(ui->MyPublicLocLine->text().toStdString(), MyPTP.CurveP);
		}
	}
    else
    {
        msgBox->setText(tr("Missing file locations."));
        msgBox->setIcon(QMessageBox::Warning);
        msgBox->setStandardButtons(QMessageBox::Ok);
        msgBox->exec();
        delete msgBox;
    }
	return;
}
void MainWindow::on_PortLine_textEdited(const QString &arg1)
{
    bool b;
    int i = arg1.toInt(&b);
    if(b)
        MyPTP.Port = i;
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
    QString fileName = QFileDialog::getOpenFileName(this, tr("Open File"), "", tr("Files (*.*)"));

	if(MyPTP.UseRSA)
	{
		if(fileName.size() == 0 || !LoadRSAPublicKey(fileName.toStdString(), Mod, Keys[0]))
		{
			Mod = 0;
			Keys[0] = 0;
		}
		else
		{
			ui->PublicKeyLocLabel->setText(fileName);
			MyPTP.MyMod = Mod;
			MyPTP.MyE = Keys[0];
		}
	}
	else
	{
		if(fileName.size() == 0 || !LoadCurvePublicKey(fileName.toStdString(), MyPTP.CurveP))
		{
			memset((char*)MyPTP.CurveP, 0, 32);
		}
		else
			ui->PublicKeyLocLabel->setText(fileName);
	}
}
void MainWindow::on_OpenPrivateButton_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this, tr("Open File"), "", tr("Files (*.*)"));
    string Pass = ui->PasswordLine->text().toStdString();
	if(MyPTP.UseRSA)
	{
		if(fileName.size() == 0 || !LoadRSAPrivateKey(fileName.toStdString(), Keys[1], &Pass))
			Keys[1] = 0;
		else
		{
			ui->PrivateKeyLocLabel->setText(fileName);
			MyPTP.MyD = Keys[1];
		}
	}
	else
	{
		if(fileName.size() == 0 || !LoadCurvePrivateKey(fileName.toStdString(), MyPTP.CurveK, &Pass))
			memset((char*)MyPTP.CurveK, 0, 32);
		else
			ui->PrivateKeyLocLabel->setText(fileName);
	}
	ui->MyPrivatePassLine->clear();
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
    QString fileName = QFileDialog::getOpenFileName(this, tr("Open File"), "", tr("Files (*.*)"));
    if(MyPTP.UseRSA)
	{
		if(fileName.size() == 0 || !LoadRSAPublicKey(fileName.toStdString(), MyPTP.ClientMod, MyPTP.ClientE))
		{
		    MyPTP.ClientMod = 0;
		    MyPTP.ClientE = 0;
		}
	}
	else
	{
		if(fileName.size() == 0 || !LoadCurvePublicKey(fileName.toStdString(), MyPTP.CurvePPeer))
		{
		    memset((char*)MyPTP.CurvePPeer, 0, 32);
		}
	}
}

void MainWindow::Help()
{
    msgBox = new QMessageBox;
    msgBox->setText(tr("Gah!"));
    msgBox->setIcon(QMessageBox::Information);
    msgBox->setStandardButtons(QMessageBox::Ok);
    msgBox->exec();
    delete msgBox;
}

void MainWindow::About()
{
    msgBox = new QMessageBox;
    msgBox->setText(tr("This is a GUI version of the original CryptoChat.\nIt was built to maintain complete compatability\nbetween the two versions and so, has the same\ncapabilities and functionality.\n\n\tDeveloped by ryco117"));
    msgBox->setIcon(QMessageBox::Information);
    msgBox->setStandardButtons(QMessageBox::Ok);
    msgBox->exec();
    delete msgBox;
}

void MainWindow::SendFileAction()
{
    if(MyPTP.GConnected)
        MyPTP.SendFilePt1();
    else
    {
        msgBox = new QMessageBox;
        msgBox->setText(tr("You can't do that right now"));
        msgBox->setIcon(QMessageBox::Warning);
        msgBox->setStandardButtons(QMessageBox::Ok);
        msgBox->exec();
        delete msgBox;
    }
}

void MainWindow::on_ConnectButton_clicked()
{
    if(!MyPTP.Serv)
    {
        int error = MyPTP.StartServer(1, ui->SendPublicCB->isChecked(), ui->PeerPublicLocLine->text().toStdString());
        if(error)
        {
            msgBox = new QMessageBox;
            msgBox->setText(QString("Could not start server, error code ") + QString::number(error));
            msgBox->setIcon(QMessageBox::Warning);
            msgBox->setStandardButtons(QMessageBox::Ok);
            msgBox->exec();
			ui->StatusLabel->setText(QString("Not Connected"));
        }
		else
			ui->StatusLabel->setText(QString("Attempting to connect to address..."));
    }
}
void MainWindow::Update()
{
    if(!MyPTP.GConnected && MyPTP.SentStuff == 3)
    {
        ui->LoadMyKeysWidget->setHidden(true);
        ui->ConnectSettingsWidget->setHidden(true);
        ui->ReceiveText->setHidden(false);
        ui->SendText->setHidden(false);
        ui->SendButton->setHidden(false);
        ui->SendText->setEnabled(true);
        ui->ReceiveText->setEnabled(true);
        ui->SendButton->setEnabled(true);
        MyPTP.GConnected = true;
		ui->StatusLabel->setText(QString("Connected!"));
    }
    if(MyPTP.Serv > 0)
    {
        int error;
        if(MyPTP.ContinueLoop)
            error = MyPTP.Update();
        else
        {
            for(int i = 0; i < MyPTP.GetMaxClients(); i++)
                if(MyPTP.MySocks[i] > 0)
                    closesocket(MyPTP.MySocks[i]);
            if(MyPTP.Client > 0)
                closesocket(MyPTP.Client);

            closesocket(MyPTP.Serv);
            MyPTP.Serv = 0;
            MyPTP.Client = 0;
            MyPTP.Port = 5001;
            MyPTP.ClientMod = 0;
            MyPTP.ClientE = 0;
            MyPTP.Sending = 0;
            MyPTP.SentStuff = 0;
            MyPTP.RNG = rng;
            MyPTP.GConnected = false;
            MyPTP.ConnectedClnt = false;
            MyPTP.ConnectedSrvr = false;
			MyPTP.HasPub = false;
			memset((char*)MyPTP.CurveP, 0, 32);
			memset((char*)MyPTP.CurveK, 0, 32);
			memset((char*)MyPTP.CurvePPeer, 0, 32);

            GMPSeed(rng);
            MyPTP.SymKey = rng->get_z_bits(256);
            Keys[0] = 65537;
            Keys[1] = 0;
            Mod = 0;

            ui->ReceiveText->append(tr("Disconnected from peer."));
            ui->SendButton->setDisabled(true);
            ui->SendText->setDisabled(true);
            ui->ReceiveText->setDisabled(true);
			ui->StatusLabel->setText(QString("Not Connected"));
			ui->ConnectButton->setDisabled(true);
        }

        if(error < 0)
        {
            for(int i = 0; i < MyPTP.GetMaxClients(); i++)
                if(MyPTP.MySocks[i] > 0)
                    closesocket(MyPTP.MySocks[i]);
            if(MyPTP.Client > 0)
                closesocket(MyPTP.Client);

            closesocket(MyPTP.Serv);
            MyPTP.Serv = 0;
            MyPTP.Client = 0;
            MyPTP.Port = 5001;
            MyPTP.ClientMod = 0;
            MyPTP.ClientE = 0;
            MyPTP.Sending = 0;
            MyPTP.SentStuff = 0;
            MyPTP.RNG = rng;
            MyPTP.GConnected = false;
            MyPTP.ConnectedClnt = false;
            MyPTP.ConnectedSrvr = false;
			MyPTP.HasPub = false;
			memset((char*)MyPTP.CurveP, 0, 32);
			memset((char*)MyPTP.CurveK, 0, 32);
			memset((char*)MyPTP.CurvePPeer, 0, 32);


            GMPSeed(rng);
            MyPTP.SymKey = rng->get_z_bits(256);
            Keys[0] = 65537;
            Keys[1] = 0;
            Mod = 0;

            ui->ReceiveText->append(tr("Disconnected from peer."));
            ui->SendButton->setDisabled(true);
            ui->SendText->setDisabled(true);
            ui->ReceiveText->setDisabled(true);
			ui->ConnectButton->setDisabled(true);

            msgBox = new QMessageBox;
            msgBox->setText(QString("Update loop failed, error code ") + QString::number(error));
            msgBox->setIcon(QMessageBox::Warning);
            msgBox->setStandardButtons(QMessageBox::Ok);
            msgBox->exec();
            delete msgBox;
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

void MainWindow::GMPSeed(gmp_randclass* rng)
{
    //Properly Seed rand()
    FILE* random;
    unsigned int seed;
    random = fopen ("/dev/urandom", "r");		//Unix provides it, why not use it
    if(random == NULL)
    {
        fprintf(stderr, "Cannot open /dev/urandom!\n");
        return;
    }
	for(int i = 0; i < 20; i++)
	{
		fread(&seed, sizeof(seed), 1, random);
		srand(seed);							//seed the default random number generator
		rng->seed(seed);						//seed the GMP random number generator
	}
	fclose(random);
}

void MainWindow::on_GenerateButton_clicked()
{
	if(MyPTP.UseRSA)
	{
		NewRSA.KeyGenerator(Keys, Mod, *rng, true, false);
		MyPTP.MyMod = Mod;
		MyPTP.MyE = Keys[0];
		MyPTP.MyD = Keys[1];
	}
	else
	{
		ECC_Curve25519_Create(MyPTP.CurveP, MyPTP.CurveK, *rng);
	}
	ui->StatusLabel->setText(QString("Private/Public keys created!"));
	if(IsIP(ui->PeerIPText->text().toStdString()))
        ui->ConnectButton->setEnabled(true);
}

void MainWindow::on_PeerIPText_textEdited(const QString &arg1)
{

    if(!IsIP(arg1.toStdString()))
        ui->ConnectButton->setDisabled(true);
    else if((MyPTP.UseRSA && MyPTP.MyMod != 0) || (!MyPTP.UseRSA && MyPTP.CurveK[31] != 0))	//For a proper Curve25519, k[31] can't be zero (bit 254 always set) and so this checks if we generated the curve
    {
        MyPTP.ClntIP = arg1.toStdString();
        ui->ConnectButton->setEnabled(true);
    }
}
void MainWindow::on_PeerIPText_returnPressed()
{
    if(ui->ConnectButton->isEnabled())
    {
        if(!MyPTP.Serv)
        {
            int error = MyPTP.StartServer(1, true, string(""));
            if(error)
            {
                msgBox = new QMessageBox;
                msgBox->setText(QString("Could not start server, error code ") + error);
                msgBox->setIcon(QMessageBox::Warning);
                msgBox->setStandardButtons(QMessageBox::Ok);
                msgBox->exec();
            }
        }
    }
}

MainWindow::~MainWindow()
{
    delete ui;
    delete rng;
}
