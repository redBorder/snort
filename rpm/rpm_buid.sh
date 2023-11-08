rm -f /root/rpmbuild/SOURCES/snort-2.9.8.3.tar.gz
( cd .. && make distclean )
( cd /root/projects && tar --exclude='.git' -zcvf /root/rpmbuild/SOURCES/snort-2.9.8.3.tar.gz snort-2.9.8.3/ )
rpmbuild -ba --target x86_64 snort.spec
