rm -f /root/rpmbuild/SOURCES/snort-2.9.20.tar.gz
( cd .. && make distclean )
( cd /root/projects && tar --exclude='.git' -zcvf /root/rpmbuild/SOURCES/snort-2.9.20.tar.gz snort-2.9.20/ )
rpmbuild -ba --target x86_64 snort.spec
