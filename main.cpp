#ifndef MAIN_SOURCE
#define MAIN_SOURCE

#ifdef WINDOWS
	#define _WIN32_WINNT  0x0500
	#pragma comment(lib, "Ws2_32.lib")
#endif

#include "mainwindow.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    return a.exec();
}

#endif // MAIN_SOURCE