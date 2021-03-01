 TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        cl_hash.cpp \
        crypto.cpp \
        main.cpp \
        rpc.cpp \
        tx.cpp


LIBS += -L/usr/lib/ -ljsoncpp
LIBS += -L/usr/lib/ -lcurl
LIBS += -L/usr/lib/ -lcryptopp
LIBS += -L/usr/lib/ -lcrypto
LIBS += -L/usr/lib/ -lssl
LIBS += -L/usr/lib/ -lOpenCL

HEADERS += \
    assortments.h \
    crypto.h \
    hash.h \
    m_sha256.h \
    rpc.h \
    tx.h \
    uint_custom.h
