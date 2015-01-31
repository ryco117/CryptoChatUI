#-------------------------------------------------
#
# Project created by QtCreator 2014-02-01T00:52:23
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = CryptoChatUI
TEMPLATE = app
win32: DEFINES += WINDOWS

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

unix:!macx: LIBS += /usr/local/lib/libscrypt.a
#unix:!macx: LIBS += ./libscrypt.a

unix:!macx: INCLUDEPATH += /usr/local/include
unix:!macx: DEPENDPATH += /usr/local/include

QMAKE_CFLAGS_RELEASE -= -O2
QMAKE_CFLAGS_RELEASE -= -O0

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

unix:!macx: PRE_TARGETDEPS += /usr/local/lib/libscrypt.a

OBJECTS += AES-NI.o

RESOURCES += \
    resource.qrc

win32: LIBS += C:\Library\libgmpxx.a
win32: LIBS += C:\Library\libgmp.a
win32: LIBS += -lWs2_32
win32: LIBS += -lAdvapi32
win32: LIBS += C:\Library\libscrypt.a

win32: INCLUDEPATH += $$PWD/../../../../../../Include
win32: DEPENDPATH += $$PWD/../../../../../../Include