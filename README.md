RedBorder Snort
===============

RedBorder's Snort with some improvements:
* Creating a parent pid (ppid) file, in order to be able to track pf_ring statistics
* Alert Threshold limits / suppressions can now be tracked by src and dst at the same time
* Added "dont_rotate_on_packets" unified2 option, in order to avoid lonely packets on barnyard
* u2boat is able to filter by gid, sid, timestamp range, and output as text
* Created snort_iplist, in order to be able to reload iplist entries via control socket
* shared memory name now include redborder instance group id
* Integrated geo-ip in reputation preprocessor, so you can block or bypass traffic depending on src/dst geographic location

