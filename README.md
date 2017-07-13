# pcap_ex
packet parsing with pcap

Environment : Ubuntu 16.04, QT Creator (with libpcap-dev, libpcap0.8-dev)

Usage : sudo ./pcap (in build directory), launch the browser with port 80

Result : print each layers header data and last payload

* Hex value 00 00 00 00 00 00 is not a payload. It is ethernet padding data.
