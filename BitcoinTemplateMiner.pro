 TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        cl_hash.cpp \
        crypto.cpp \
#        cuda_hash.cpp \
        main.cpp \
        rpc.cpp \
        tx.cpp


#INCLUDEPATH += /usr/include
#DEPENDPATH += /usr/include
LIBS += -L/usr/lib/ -ljsoncpp
LIBS += -L/usr/lib/ -lcurl
LIBS += -L/usr/lib/ -lcryptopp
LIBS += -L/usr/lib/ -lcrypto
LIBS += -L/usr/lib/ -lssl
LIBS += -L/usr/lib/ -lOpenCL

LIBS += -L/usr/include/hashlib++/ -lhl++

HEADERS += \
    assortments.h \
    crypto.h \
    hash.h \
    m_sha256.h \
    rpc.h \
    tx.h \
    uint_custom.h


-O4

DISTFILES += \
#    ../build-BitcoinTemplateMiner-Desktop-Debug/cuda_hash.cu \
#    ../build-BitcoinTemplateMiner-Desktop-Debug/opencl_sha256.cl \
    bitcoin_hash_header.cl \
    vector_add_kernel.cl
