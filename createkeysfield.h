#ifndef CREATEKEYSFIELD_H
#define CREATEKEYSFIELD_H

#include <QDialog>
#include <QDir>

namespace Ui {
class CreateKeysField;
}

class CreateKeysField : public QDialog
{
	Q_OBJECT

public:
	explicit CreateKeysField(QString* pubLoc, QString* privLoc, char* passwd, QWidget *parent = 0);
	~CreateKeysField();

private:
	Ui::CreateKeysField *ui;
	char* Passwd;
	QString* PubLoc;
	QString* PrivLoc;

private slots:
	void on_PublicLocField_textEdited(const QString &arg1);
	void on_PrivateLocField_textEdited(const QString &arg1);
	void on_PasswordField_textEdited(const QString &arg1);
};

#endif // CREATEKEYSFIELD_H
