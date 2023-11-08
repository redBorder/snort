# dependencies
# pcre-devel
# libdnet-devel
# libs3-devel
# libxml2-devel
# install libtirpc-devel and copy /usr/include/tirpc/rpc/* /usr/include/rpc
# cp /usr/include/tirpc/netconfig.h /usr/include/netconfig.h
./configure --prefix=/ --sbindir=/usr/bin --exec-prefix=/ --with-libpcap-includes=/usr/include --with-libpcap-libraries=/usr/lib --with-libpfring-includes=/usr/include/ --with-libpfring-libraries=/usr/lib --enable-perfprofiling --enable-normalizer --enable-mpls --enable-targetbased --enable-ppm --enable-active-response --enable-reload --enable-react --enable-flexresp3 --with-daq-libraries=/usr/local/lib --with-daq-includes=/usr/local/include --enable-control-socket --enable-gdb --enable-reputationgeoip --enable-shared-rep --enable-extradata-file --enable-file-inspect --with-libs3-includes=/usr/include --with-libs3-libraries=/usr/lib64 --enable-remote-file-s3 
