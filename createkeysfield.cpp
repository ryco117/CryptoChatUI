#include "createkeysfield.h"
#include "ui_createkeysfield.h"

CreateKeysField::CreateKeysField(QString* pubLoc, QString* privLoc, char* passwd, QWidget *parent) :
	QDialog(parent),
	ui(new Ui::CreateKeysField)
{
	Passwd = passwd;
	PubLoc = pubLoc;
	*PubLoc = QDir::homePath() + QString("/.CryptoChatUI/MyKeys.pub");
	PrivLoc = privLoc;
	*PrivLoc = QDir::homePath() + QString("/.CryptoChatUI/MyKeys.priv");
	ui->setupUi(this);
	ui->PublicLocField->setText(*PubLoc);
	ui->PrivateLocField->setText(*PrivLoc);
}

void CreateKeysField::on_PublicLocField_textEdited(const QString &arg1)
{
	*PubLoc = arg1;
}

void CreateKeysField::on_PrivateLocField_textEdited(const QString &arg1)
{
	*PrivLoc = arg1;
}

void CreateKeysField::on_PasswordField_textEdited(const QString &arg1)
{
	memcpy(Passwd, arg1.toStdString().c_str(), arg1.size());
}

CreateKeysField::~CreateKeysField()
{
	delete ui;
}