#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QMessageBox>
#include <QTimer>
#include <QFileDialog>
#include <QTextEdit>
#include <QDebug>

#ifdef WINDOWS
	#include <winsock2.h>
	#include <Ws2tcpip.h>
	#include <windows.h>
	#include <Ntsecapi.h>
#else
	#include <unistd.h>
	#include <ifaddrs.h>
#endif
#include <iostream>
#include <string>

#define SFMT_MEXP 19937

#include "getpasswordwidget.h"
#include "createkeysfield.h"
#include "donatewindow.h"
#include "curve25519-donna.c"
#include "ecdh.h"
#include "PeerToPeer.cpp"
#include "KeyManager.h"
#include "RSA.cpp"

namespace Ui
{
    class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT
private:
    QTimer timer;

public:
    explicit MainWindow(QWidget *parent = 0);
    void SeedAll();
	gmp_randclass* rng;
	sfmt_t sfmt;
    PeerToPeer MyPTP;
    RSA NewRSA;
    AES Cipher;
    ~MainWindow();

private:
    Ui::MainWindow *ui;
    QMessageBox* msgBox;
    void CreateActions();
	void StartConnection();

private slots:
    void SafeExit();
    void ConnectSetup();
    void Disconnect();
    void SendFileAction();
    void LoadMyKeys();
    void LoadPeerPublicKey();
    void Help();
    void OptionsSetup();
    void on_CreateKeysButton_clicked();
    void on_PeerPortLine_textEdited(const QString &arg1);
	void on_BindPortLine_textEdited(const QString &arg1);
	void on_ProxyAddrLine_textEdited(const QString &arg1);
    void About();
	void License();
	void Donate();
	void GetOwnStaticPub();
	void GetPeerStaticPub();
    void Update();
    void on_PeerIPText_textEdited(const QString &arg1);
    void on_OpenPublicButton_clicked();
    void on_OpenPrivateButton_clicked();
    void on_OKButton_clicked();
    void on_ConnectButton_clicked();
    void on_SendButton_clicked();
    void on_SendText_returnPressed();
    void on_PeerIPText_returnPressed();
    void on_SavePublicCB_toggled(bool checked);
	void on_GenerateButton_clicked();
	void on_UseRSACB_toggled(bool checked);
	bool SaveSettings();
	bool LoadSettings();
};

#endif // MAINWINDOW_H