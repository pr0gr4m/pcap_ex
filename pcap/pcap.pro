TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += main.c \
    use_pcap.c \
    parsing.c

HEADERS += \
    use_pcap.h \
    common.h \
    parsing.h

