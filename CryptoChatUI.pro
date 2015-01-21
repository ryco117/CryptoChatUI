#-------------------------------------------------
#
# Project created by QtCreator 2014-02-01T00:52:23
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = CryptoChatUI
TEMPLATE = app

SOURCES += main.cpp\
		SFMT/SFMT.c\
        mainwindow.cpp \
    AES.cpp \
    PeerIO.cpp \
    PeerToPeer.cpp \
    RSA.cpp \
    CloseSocket.cpp \
    curve25519-donna.c \
    donatewindow.cpp \
    createkeysfield.cpp \
    getpasswordwidget.cpp

HEADERS  += mainwindow.h \
    AES.h \
    PeerToPeer.h \
    RSA.h \
    KeyManager.h \
    base64.h \
    ecdh.h \
    donatewindow.h \
    SFMT/SFMT.h \
    createkeysfield.h \
    getpasswordwidget.h

FORMS    += mainwindow.ui \
    donatewindow.ui \
    createkeysfield.ui \
    getpasswordwidget.ui

unix:!macx: LIBS += -lgmpxx

unix:!macx: LIBS += -lgmp

QMAKE_CFLAGS_RELEASE -= -O2
QMAKE_CFLAGS_RELEASE += -O3

QMAKE_CXXFLAGS += -static
QMAKE_CXXFLAGS += -Wno-strict-aliasing
QMAKE_CXXFLAGS += -Wno-unused-function
QMAKE_CXXFLAGS += -Wno-unused-result
QMAKE_CXXFLAGS += -Wno-char-subscripts
QMAKE_CXXFLAGS += -Wno-narrowing
QMAKE_CXXFLAGS += -Wno-maybe-uninitialized
QMAKE_CXXFLAGS_RELEASE -= -O2
QMAKE_CXXFLAGS_RELEASE += -O0

QMAKE_LFLAGS_RELEASE -= -Wl,-O1
QMAKE_LFLAGS_RELEASE += -O3

#unix:!macx: LIBS += -L$$PWD/../../../../../../usr/local/lib/libscrypt.a
unix:!macx: LIBS += /usr/local/lib/libscrypt.a

INCLUDEPATH += $$PWD/../../../../../../usr/local/include
DEPENDPATH += $$PWD/../../../../../../usr/local/include

unix:!macx: PRE_TARGETDEPS += $$PWD/../../../../../../usr/local/lib/libscrypt.a

OBJECTS += AES-NI.o

RESOURCES += \
    resource.qrc