rm -f /root/rpmbuild/SOURCES/snort-2.9.8.0.tar.gz
( cd .. && make distclean )
( cd /root/projects && tar cfzv /root/rpmbuild/SOURCES/snort-2.9.8.0.tar.gz snort-2.9.8.0/ )
rpmbuild -ba --target x86_64 snort.spec
