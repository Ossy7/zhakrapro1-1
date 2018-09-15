import hashlib
import sys
import subprocess
import re
import GeoIP
from PyQt4.QtCore import *
from PyQt4.QtGui import *
__version__ = "1.5.1"

BLOCKSIZE = 65536

class ZhakraPro(QTabWidget):
    def __init__(self, parent=None):
        super(ZhakraPro, self).__init__(parent)
        self.tab1 = QWidget()
        self.tab2 = QWidget()
        self.tab3 = QWidget()
        self.tab4 = QWidget()

        self.addTab(self.tab1, "File Integrity")
        self.addTab(self.tab2, "View Internet Connections")
        self.addTab(self.tab3, "File Modification History")
        self.addTab(self.tab4, "Help")

        self.tab1UI()
        self.tab2UI()
        self.tab3UI()
        self.tab4UI()

        
    def tab1UI(self):
        self.lineedit_fname = QLineEdit("Enter File path")

        self.list_hasher = QListWidget()
        self.list_hasher.setFixedWidth(70)
        self.list_hasher.setStyleSheet("background-color:cyan")
        self.list_hasher.addItems(["SHA1", "SHA256", "SHA384", "SHA512", "MD5"])
        self.list_hasher.itemClicked.connect(self.myhashers)

        self.browser = QTextBrowser()
        self.browser.setAlignment(Qt.AlignCenter)
        
        vbox1 = QVBoxLayout()
        vbox1.addWidget(self.lineedit_fname)

        hbox1 = QHBoxLayout()
        hbox1.addWidget(self.list_hasher)
        hbox1.addWidget(self.browser)

        vbox1.addLayout(hbox1)
        
        self.tab1.setLayout(vbox1)
        self.setGeometry(5, 5, 900, 400)
        
        self.setWindowTitle("ZhakraPro File Integrity Validator and Internet Monitor")

    def tab2UI(self):
        #vbox2 = QVBoxLayout()
        hbox = QHBoxLayout()

        self.listwidget = QListWidget()
        self.listwidget.setFixedWidth(200)
        self.listwidget.setStyleSheet("background-color:cyan")
        self.listwidget.addItem("View Established Connections")
        self.listwidget.addItem("View Running Processes")
        self.listwidget.addItem("View Statistics")
        self.listwidget.addItem("View Process Users")
        self.listwidget.addItem("View Metrics")
        self.listwidget.addItem("Stop Process")
        self.listwidget.addItem("IP Geolocator")
        self.listwidget.addItem("Search Processes")
        self.listwidget.itemClicked.connect(self.mylist)
        
        self.browser1 = QTextBrowser()
        self.browser1.setAlignment(Qt.AlignCenter)

        hbox.addWidget(self.listwidget)
        hbox.addWidget(self.browser1)
        self.tab2.setLayout(hbox)

    def tab3UI(self):
        self.le_dir = QLineEdit("Directory or Folder Path.")
        self.btn_vmodif = QPushButton("View File History")
        self.btn_vmodif.setStyleSheet("background-color:cyan")
        self.btn_vmodif.clicked.connect(self.fhistory)
        self.browser2 = QTextBrowser()

        vbox3 = QVBoxLayout()
        vbox3.addWidget(self.le_dir)
        vbox3.addWidget(self.btn_vmodif)
        vbox3.addWidget(self.browser2)
        self.tab3.setLayout(vbox3)
            
    def tab4UI(self):
        self.browser3 = QTextBrowser()
        #self.browser3.setStyleSheet("background-color:cyan")
        self.browser3.setText("This application is written in Python 2.7.14 and PyQt4."+"\n"\
                             +"Version 1.5.1" + "\n"\
                             +"author: Daniel Osinachi N." +"\n"\
                              +"dan.ossy.do@gmail.com"+"\n"\
                              +"Copyright (C) 2018 Daniel Osinachi N.")
            
        vbox4 = QVBoxLayout()
        vbox4.addWidget(self.browser3)
        self.tab4.setLayout(vbox4)


    def myhashers(self, item):
        if item.text() == "SHA1":
            self.Zhak_sha1()
        elif item.text() == "SHA256":
            self.Zhak_sha256()
        elif item.text() == "SHA384":
            self.Zhak_sha384()
        elif item.text() == "SHA512":
            self.Zhak_sha512()
        elif item.text() == "MD5":
            self.Zhak_md5()
        
            
    def Zhak_sha1(self):
        if self.lineedit_fname.text():
            fname = str(self.lineedit_fname.text())
            hasher = hashlib.sha1()
            try:
                with open(fname, 'rb') as afile_tohash:
                    buf = afile_tohash.read(BLOCKSIZE)
                    while len(buf) > 0:
                        hasher.update(buf)
                        buf = afile_tohash.read(BLOCKSIZE)
                        chksum1 = hasher.hexdigest()
                        self.browser.setText("The SHA1 Checksum for " + " %s " % fname + " : " + " %s "  % chksum1)
            except Exception, IOError:
                self.browser.setText("Please ensure it is a file path.")
        else:
            self.browser.setText("[*] Please specify path to file.")

    def Zhak_sha256(self):
        if self.lineedit_fname.text():
            fname = str(self.lineedit_fname.text())
            hasher = hashlib.sha256()
            try:
                with open(fname, 'rb') as afile_tohash:
                    buf = afile_tohash.read(BLOCKSIZE)
                    while len(buf) > 0:
                        hasher.update(buf)
                        buf = afile_tohash.read(BLOCKSIZE)
                        chksum2 = hasher.hexdigest()
                        self.browser.setText("The SHA256 Checksum for " + " %s " % fname + " : " + " %s "  % chksum2)
            except Exception, IOError:
                self.browser.setText("[*] Please ensure it is a file path.")
        else:
            self.browser.setText("[*] Please specify path to file.")

    def Zhak_sha384(self):
        if self.lineedit_fname.text():
            fname = str(self.lineedit_fname.text())
            hasher = hashlib.sha384()
            try:
                with open(fname, 'rb') as afile_tohash:
                    buf = afile_tohash.read(BLOCKSIZE)
                    while len(buf) > 0:
                        hasher.update(buf)
                        buf = afile_tohash.read(BLOCKSIZE)
                        chksum3 = hasher.hexdigest()
                        self.browser.setText("The SHA384 Checksum for " + " %s " % fname + " : " + " %s "  % chksum3)
            except Exception, IOError:
                self.browser.setText("[*] Please ensure it is a  file path.")
        else:
            self.browser.setText("[*] Please specify path to file.")

    def Zhak_sha512(self):
        if self.lineedit_fname.text():
            fname = str(self.lineedit_fname.text())
            hasher = hashlib.sha512()
            try:
                with open(fname, 'rb') as afile_tohash:
                    buf = afile_tohash.read(BLOCKSIZE)
                    while len(buf) > 0:
                        hasher.update(buf)
                        buf = afile_tohash.read(BLOCKSIZE)
                        chksum5 = hasher.hexdigest()
                        self.browser.setText("The SHA512 Checksum for " + " %s " % fname + " : " + " %s "  % chksum5)
            except Exception, IOError:
                self.browser.setText("[*] Please ensure it is a file path.")
        else:
            self.browser.setText("[*] Please specify path to file.")

    def Zhak_md5(self):
        if self.lineedit_fname.text():
            fname = str(self.lineedit_fname.text())        
            hasher = hashlib.md5()
            try:
                with open(fname, 'rb') as afile_tohash:
                    buf = afile_tohash.read(BLOCKSIZE)
                    while len(buf) > 0:
                        hasher.update(buf)
                        buf = afile_tohash.read(BLOCKSIZE)
                        chksumM5 = hasher.hexdigest()
                        self.browser.setText("The MD5 for " + " %s " % fname + " : " + " %s "  % chksumM5)
            except Exception, IOError:
                self.browser.setText("[*] Please ensure it is a file path.")
        else:
            self.browser.setText("[*] Please specify path to file.")

    def mylist(self, item):
        if item.text() == "View Established Connections":
            self.viewCon()
        elif item.text() == "View Running Processes":
            self.viewProc()
        elif item.text() == "View Statistics":
            self.nt_usage()
        elif item.text() == "View Process Users":
            self.pusers()
        elif item.text() == "View Metrics":
            self.metrics()
        elif item.text() == "Stop Process":
            self.pkiller()
        elif item.text() == "IP Geolocator":
            self.locator()
        elif item.text() == "Search Processes":
            self.search_proc()

    def viewCon(self):
        activeCon = subprocess.check_output(['netstat', '-atulpn'])
        self.browser1.setText(activeCon)

    def viewProc(self):
        activePro = subprocess.check_output(['netstat', '-alpn'])
        self.browser1.setText(activePro)

    def nt_usage(self):
        nt_stat = subprocess.check_output(['netstat', '-s'])
        self.browser1.setText(nt_stat)
        

    def pusers(self):
        runningp = subprocess.check_output(['ps', 'aux'])
        self.browser1.setText(runningp)


    def metrics(self):
        m_tcp = subprocess.check_output(['ip', 'tcp_metrics'])
        self.browser1.setText(m_tcp)

    def pkiller(self):
        text, ok = QInputDialog.getText(self, "Process Killer", "Enter the PID:")
        if ok and text:
            user_text = str(text)
            killer = subprocess.check_output(['kill', user_text])
            self.browser1.setText(killer)

    def locator(self):
        items = ("Website", "IPv4", "IPv6")
        item, ok = QInputDialog.getItem(self, "IP-Domain Geolocator",
                                        "List of available options", items, 0, False)
        if ok and item:
            if item == "Website":
                self.locate_website()
            elif item == "IPv4":
                self.locate_ipv4()
            elif item == "IPv6":
                self.locate_ipv6()
    
    def locate_website(self):
        text, ok = QInputDialog.getText(self, "Website Geolocator", "Enter the website:")
        if ok and text:
            user_text = unicode(text)
            gi = GeoIP.open("/usr/share/GeoIP/GeoIPCity.dat", GeoIP.GEOIP_STANDARD)
            gir = gi.record_by_name(user_text) or gi.record_by_addr(user_text)

            if (len(gir) > 0):
                website_info = [i for i in gir.items()]
                self.browser1.setText(str(website_info))
            else:
                self.browser1.setText("[*]...Record not found.")

            
                
    def locate_ipv4(self):
        text, ok = QInputDialog.getText(self, "IP Geolocator", "Enter the IP address:")
        if ok and text:
            user_text = unicode(text)
            gi = GeoIP.open("/usr/share/GeoIP/GeoIPCity.dat", GeoIP.GEOIP_STANDARD)
            gir = gi.record_by_name(user_text) or gi.record_by_addr(user_text)

            if (len(gir) > 0):
                ipv4_info = [i for i in gir.items()]
                self.browser1.setText(str(ipv4_info))
            else:
                self.browser1.setText("[*]...Record not found.")
                
                                                     
                                                     
    def locate_ipv6(self):
        text, ok = QInputDialog.getText(self, "IPv6 Geolocator", "Enter the IPv6 address:")
        if ok and text:
            user_text = unicode(text)
            gi = GeoIP.open("/usr/share/GeoIP/GeoIPv6.dat", GeoIP.GEOIP_STANDARD)
            gir = gi.country_name_by_name_v6(user_text) or gi.country_name_by_addr_v6(user_text)

            if (len(gir) > 0):
                self.browser1.setText(str(gir))
            else:
                self.browser1.setText("[*]...Record not found.")

    def search_proc(self):
        items = ("Search Rootkit", "Find-PID")
        item, ok = QInputDialog.getItem(self, "Process Searcher",
                                        "List of available options", items, 0, False)
        if ok and item:
            if item == "Search Rootkit":
                self.search_rtkit()
            elif item == "Find-PID":
                self.search_PID()
            

    def search_rtkit(self):
        text, ok = QInputDialog.getText(self, "Search RootKit", "Enter RootKit Name:")
        if ok and text:
            rtkit = str(text)
            rtkit = rtkit.lower()
            running_proc = subprocess.check_output(['ps', 'aux'])
            rewords = re.findall(r'\w+', running_proc)
            
            finder = [rewords[rewords.index(i) -27:rewords.index(i) +2] for i in rewords if (i == rtkit)]
            if (len(finder) > 0):
                self.browser1.setText("Found " + str(len(finder)) +"\n"
                                      + "[*] Please find the PID in the following and confirm using <view process users button>:" +"\n"
                                      + "%s" %(finder[0]))
            else:
                self.browser1.setText("[*]...Not Found.")
                                      
            

    def search_PID(self):
        text, ok = QInputDialog.getText(self, "Find PID ", "Enter Process name:")
        if ok and text:
            pname = str(text)
            pname = pname.lower()
            try:
                pid_finder = subprocess.check_output(['pgrep', '-l', pname])
                self.browser1.setText(pid_finder)
            except Exception, e:
                self.browser1.setText("[*]...Not Found.")

    def fhistory(self):
        if self.le_dir.text():
            dpath = str(self.le_dir.text())
            try:
                fh = subprocess.check_output(['ls', '-actl', dpath])
                self.browser2.setText(fh)
            except Exception, e:
                self.browser2.setText("[*]Please ensure it is a directory or folder path and You have access permission.")
        else:
            self.browser2.setText("[*]...Please specify a path to a folder or directory.")
            
app = QApplication(sys.argv)
form = ZhakraPro()
form.show()
app.exec_()
                
        
                     
        
