ZhakraPro1-5-1
version: 1.5.1

Zhakrapro is a digital forensics GUI app written in Python 2.7.14+ and PyQt4.
It is a file integrity validator, system and device internet monitor.
ZhakraPro was built and tested on both 64 and 32 bits linux  machines.

Internet Monitor:
1. View device established connections (to view all require administrative rights i.e you must be logged in as the admin.)
2. View running processes within device (same applies here as in no.1 )
3. View running processes and users of those processes
4. View network statistics.
5. Stop process (some require administrative rights)
6. View tcp metrics
7. View geolocation of connected IP address
8. Search processes (includes search Rootkit, find PID by process name)

File Modification History
Enter path to the directory where you intend to view its file modification, example /usr/share
Then click view history

File Validation:
1. Enter File path
2. Select a Hash Function (SHA1, SHA256, SHA384, SHA512, MD5)

Licence:
ZhakraPro is licenced under the GNU General Public Licence.
ZhakraPro is distrisbuted in the hope that it will be useful BUT WITHOUT ANY WARRANTY.
See the GNU General Public Licence for more details.

General instructions:
1 For file integrity check, specify full file path. Example: /home/username/myfile.zip
2 Select a hash function to use in integrity check.

Using Zhakrapro in its simplest form (32 bit Linux):
1. Unzip zhakrapro1-5-1-dist-linux-x86.zip as the case maybe, open zhakrapro1-5-1 folder, scroll to zhakrapro1-5-1 application and double click.
Voila !

sha256sum zhakrapro1-5-1-dist-linux_x86.zip:
e905ea9922925dfecbb5bbdc2bc61b540f2c1a20db8b967b9c5149bb2324379b 
 



Developer:
Daniel Osinachi N.
dan.ossy.do@gmail.com
Copyright (C) 2018 Daniel Osinachi N.
15-09-2018
