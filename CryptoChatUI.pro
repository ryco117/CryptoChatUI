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
        mainwindow.cpp \
    AES.cpp \
    PeerIO.cpp \
    PeerToPeer.cpp \
    RSA.cpp \
    CloseSocket.cpp \
    curve25519-donna.c

HEADERS  += mainwindow.h \
    AES.h \
    PeerToPeer.h \
    RSA.h \
    KeyManager.h \
    base64.h \
    ecdh.h

FORMS    += mainwindow.ui

unix:!macx: LIBS += -lgmpxx

unix:!macx: LIBS += -lgmp

QMAKE_CXXFLAGS += -O
QMAKE_CXXFLAGS += -static
QMAKE_CXXFLAGS += -Wno-unused-function
QMAKE_CXXFLAGS += -Wno-unused-result
QMAKE_CXXFLAGS += -Wno-maybe-uninitialized
QMAKE_CXXFLAGS += -Wno-strict-aliasing

#unix:!macx: LIBS += -L$$PWD/../../../../../../usr/local/lib/libscrypt.a
unix:!macx: LIBS += /usr/local/lib/libscrypt.a

INCLUDEPATH += $$PWD/../../../../../../usr/local/include
DEPENDPATH += $$PWD/../../../../../../usr/local/include

unix:!macx: PRE_TARGETDEPS += $$PWD/../../../../../../usr/local/lib/libscrypt.a