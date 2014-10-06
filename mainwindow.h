#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QMessageBox>
#include <QTimer>
#include <QFileDialog>
#include <QTextEdit>
#include <QDebug>

#include <unistd.h>
#include <iostream>
#include <string>
#include <ifaddrs.h>

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
    void GMPSeed(gmp_randclass* rng);
    gmp_randclass* rng;
    PeerToPeer MyPTP;
    RSA NewRSA;
    AES Cipher;

    mpz_class SymmetricKey;
    mpz_class Mod;
    mpz_class Keys[2];
    ~MainWindow();

private:
    Ui::MainWindow *ui;
    QMessageBox* msgBox;
    void CreateActions();

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
    void on_PortLine_textEdited(const QString &arg1);
    void About();
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
};

#endif // MAINWINDOW_H