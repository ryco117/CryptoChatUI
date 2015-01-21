#include "getpasswordwidget.h"
#include "ui_getpasswordwidget.h"

GetPasswordWidget::GetPasswordWidget(char* passwd, QWidget *parent) :
	QDialog(parent),
	ui(new Ui::GetPasswordWidget)
{
	Passwd = passwd;
	ui->setupUi(this);
	ui->PasswordField->setFocus();
}

void GetPasswordWidget::on_PasswordField_textEdited(const QString &arg1)
{
	memcpy(Passwd, arg1.toStdString().c_str(), arg1.size());
}

GetPasswordWidget::~GetPasswordWidget()
{
	delete ui;
}
