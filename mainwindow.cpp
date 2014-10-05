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

    if(!shown && Mod != 0 && Keys[1] != 0 && Keys[0] != 0)
    {
        msgBox = new QMessageBox;
        msgBox->setText(tr("You have already manually assigned a public\nand private key. Do you want to use these?"));
        msgBox->setIcon(QMessageBox::Question);
        msgBox->setStandardButtons(QMessageBox::Yes | QMessageBox::No);
        if(msgBox->exec() == QMessageBox::Yes)
        {
            ui->PrimePText->setEnabled(false);
            ui->PrimePRand->setEnabled(false);

            ui->PrimeQText->setEnabled(false);
            ui->PrimeQRand->setEnabled(false);

            ui->EncKeyText->setEnabled(false);
            ui->EncKeyRand->setEnabled(false);
            MyPTP.MyMod = Mod;
            MyPTP.MyE = Keys[0];
            MyPTP.MyD = Keys[1];
        }
        else
        {
            Mod = 0;
            Keys[0] = 65537;
            Keys[1] = 0;
            ui->PublicKeyLocLabel->setText(tr(""));
            ui->PrivateKeyLocLabel->setText(tr(""));

            ui->PrimePText->setEnabled(true);
            ui->PrimePRand->setEnabled(true);

            ui->PrimeQText->setEnabled(true);
            ui->PrimeQRand->setEnabled(true);

            ui->EncKeyText->setEnabled(true);
            ui->EncKeyText->setText(tr("65537"));
            ui->EncKeyRand->setEnabled(true);
        }
        delete msgBox;
    }
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
void MainWindow::on_CreateKeysButton_clicked()
{
    if(ui->MyPrivateLocLine->text().size() != 0 && ui->MyPublicLocLine->text().size() != 0)
    {
        string Passwd = ui->MyPrivatePassLine->text().toStdString();
		ui->MyPrivateLocLine->text().toStdWString();

        bool AnsNo = false;
        if(Mod != 0 || Keys[1] != 0)
        {
            msgBox = new QMessageBox;
            msgBox->setText(tr("You have already assigned a public\nand private key values. Do you want to\nuse these instead of randomly generated one?"));
            msgBox->setIcon(QMessageBox::Question);
            msgBox->setStandardButtons(QMessageBox::Yes | QMessageBox::No);
            if(msgBox->exec() == QMessageBox::No)
                AnsNo = true;
        }

        if(!AnsNo)
        {
            NewRSA.BigPrime(PrimeP, *rng, 2048, 24);
            NewRSA.BigPrime(PrimeQ, *rng, 2048, 24);
            NewRSA.BigPrime(Keys[0], *rng, 2048, 24);

            Mod = PrimeP * PrimeQ;
            mpz_class EulersTot = (PrimeP - 1) * (PrimeQ - 1);
            mpz_invert(Keys[1].get_mpz_t(), Keys[0].get_mpz_t(), EulersTot.get_mpz_t());
        }

		char SaltStr[16] = {0};

		mpz_class Salt = rng->get_z_bits(128);
		mpz_export(SaltStr, 0, 1, 1, 0, 0, Salt.get_mpz_t());
		mpz_class TempIV = rng->get_z_bits(128);

        MakePrivateKey(ui->MyPrivateLocLine->text().toStdString(), Keys[1], &Passwd, SaltStr, TempIV);
		ui->MyPrivatePassLine->clear();
        MakePublicKey(ui->MyPublicLocLine->text().toStdString(), Mod, Keys[0]);
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
    //QByteArray ba = fileName.toLocal8Bit();
    if(fileName.size() == 0 || !LoadPublicKey(fileName.toStdString(), Mod, Keys[0]))
    {
        Mod = 0;
        Keys[0] = 0;
    }
    else
        ui->PublicKeyLocLabel->setText(fileName);
}
void MainWindow::on_OpenPrivateButton_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this, tr("Open File"), "", tr("Files (*.*)"));
	//QByteArray baFile = fileName.toLocal8Bit();
    //QByteArray baPass = ui->PasswordLine->text().toLocal8Bit();
    string Pass = ui->PasswordLine->text().toStdString();
    if(fileName.size() == 0 || !LoadPrivateKey(fileName.toStdString(), Keys[1], &Pass))
        Keys[1] = 0;
    else
        ui->PrivateKeyLocLabel->setText(fileName);

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
    //QByteArray ba = fileName.toLocal8Bit();
    if(fileName.size() == 0 || !LoadPublicKey(fileName.toStdString(), MyPTP.ClientMod, MyPTP.ClientE))
    {
        MyPTP.ClientMod = 0;
        MyPTP.ClientE = 0;
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
        if(MyPTP.MyMod == 0)
        {
            MyPTP.MyMod = PrimeP * PrimeQ;
            MyPTP.MyE = Keys[0];
            mpz_class EulersTot = (PrimeP - 1) * (PrimeQ - 1);
            mpz_invert(Keys[1].get_mpz_t(), Keys[0].get_mpz_t(), EulersTot.get_mpz_t());
            MyPTP.MyD = Keys[1];
        }

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

            GMPSeed(rng);
            MyPTP.SymKey = rng->get_z_bits(128);
            Keys[0] = 65537;
            Keys[1] = 0;
            Mod = 0;

            ui->ReceiveText->append(tr("Disconnected from peer."));
            ui->SendButton->setDisabled(true);
            ui->SendText->setDisabled(true);
            ui->ReceiveText->setDisabled(true);
			ui->StatusLabel->setText(QString("Not Connected"));
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

            GMPSeed(rng);
            MyPTP.SymKey = rng->get_z_bits(128);
            Keys[0] = 65537;
            Keys[1] = 0;
            Mod = 0;

            ui->ReceiveText->append(tr("Disconnected from peer."));
            ui->SendButton->setDisabled(true);
            ui->SendText->setDisabled(true);
            ui->ReceiveText->setDisabled(true);

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
    fread(&seed, sizeof(seed), 1, random);
    srand(seed); 		// seed the default random number generator
    rng->seed(seed);	// seed the GMP random number generator
}

void MainWindow::on_PrimeQText_textEdited(const QString &arg1)
{
    bool failed = false;
    try
    {
        //QByteArray ba = arg1.toLocal8Bit();
        PrimeQ = mpz_class(arg1.toStdString());
    }
    catch(exception e)
    {
        ui->ConnectButton->setDisabled(true);
        failed = true;
    }
    //QByteArray ba = ui->PeerIPText->text().toLocal8Bit();
    if(!failed && Keys[0] != 0 && PrimeP != 0 && PrimeQ != 0 && IsIP(ui->PeerIPText->text().toStdString()))
        ui->ConnectButton->setEnabled(true);
}
void MainWindow::on_PrimeQRand_clicked()
{
    NewRSA.BigPrime(PrimeQ, *rng, 2048, 24);
    ui->PrimeQText->setText(QString(PrimeQ.get_str().c_str()));

    //QByteArray ba = ui->PeerIPText->text().toLocal8Bit();
    if(Keys[0] != 0 && PrimeP != 0 && IsIP(ui->PeerIPText->text().toStdString()))
        ui->ConnectButton->setEnabled(true);
}

void MainWindow::on_PrimePText_textEdited(const QString &arg1)
{
    bool failed = false;
    try
    {
        //QByteArray ba = arg1.toLocal8Bit();
        PrimeP = mpz_class(arg1.toStdString());
    }
    catch(exception e)
    {
        ui->ConnectButton->setDisabled(true);
        failed = true;
    }
    //QByteArray ba = ui->PeerIPText->text().toLocal8Bit();
    if(!failed && Keys[0] != 0 && PrimeP != 0 && PrimeQ != 0 && IsIP(ui->PeerIPText->text().toStdString()))
        ui->ConnectButton->setEnabled(true);
}
void MainWindow::on_PrimePRand_clicked()
{
    NewRSA.BigPrime(PrimeP, *rng, 2048, 24);
    ui->PrimePText->setText(QString(PrimeP.get_str().c_str()));

    //QByteArray ba = ui->PeerIPText->text().toLocal8Bit();
    if(Keys[0] != 0 && PrimeQ != 0 && IsIP(ui->PeerIPText->text().toStdString()))
        ui->ConnectButton->setEnabled(true);
}

void MainWindow::on_EncKeyText_textEdited(const QString &arg1)
{
    bool failed = false;
    try
    {
        //QByteArray ba = arg1.toLocal8Bit();
        Keys[0] = mpz_class(arg1.toStdString());
    }
    catch(exception e)
    {
        ui->ConnectButton->setDisabled(true);
        failed = true;
    }
    //QByteArray ba = ui->PeerIPText->text().toLocal8Bit();
    if(!failed && Keys[0] != 0 && PrimeP != 0 && PrimeQ != 0 && IsIP(ui->PeerIPText->text().toStdString()))
        ui->ConnectButton->setEnabled(true);
}
void MainWindow::on_EncKeyRand_clicked()
{
    NewRSA.BigPrime(Keys[0], *rng, 2048, 24);
    ui->EncKeyText->setText(QString(Keys[0].get_str().c_str()));

	//QByteArray ba = ui->PeerIPText->text().toLocal8Bit();
    if(PrimeP != 0 && PrimeQ != 0 && IsIP(ui->PeerIPText->text().toStdString()))
        ui->ConnectButton->setEnabled(true);
}

void MainWindow::on_PeerIPText_textEdited(const QString &arg1)
{
    //QByteArray ba = arg1.toLocal8Bit();
    if(!IsIP(arg1.toStdString()))
        ui->ConnectButton->setDisabled(true);
    else if(Keys[0] != 0 && ((PrimeP != 0 && PrimeQ != 0) || Mod != 0))
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
            if(MyPTP.MyMod == 0)
            {
                MyPTP.MyMod = PrimeP * PrimeQ;
                MyPTP.MyE = Keys[0];
                mpz_class EulersTot = (PrimeP - 1) * (PrimeQ - 1);
                mpz_invert(Keys[1].get_mpz_t(), Keys[0].get_mpz_t(), EulersTot.get_mpz_t());
                MyPTP.MyD = Keys[1];
            }

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
