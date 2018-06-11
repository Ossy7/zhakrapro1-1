import hashlib
import sys
import subprocess
import re
import GeoIP
from PyQt4.QtCore import *
from PyQt4.QtGui import *
__version__ = "1.4.1"

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
        self.lineedit_fname = QLineEdit("Enter File name or file path")

        self.combobox_options = QComboBox()
        self.combobox_options.addItems(["Select Hash Function", "SHA1", "SHA256", "SHA384", "SHA512", "MD5"])

        self.btn_fhash = QPushButton("Hash File")
        self.browser = QTextBrowser()
        self.browser.setAlignment(Qt.AlignCenter)
        
        vbox1 = QVBoxLayout()
        vbox1.addWidget(self.lineedit_fname)
        vbox1.addWidget(self.combobox_options)
        
        vbox1.addWidget(self.browser)
        self.tab1.setLayout(vbox1)
        self.setGeometry(10, 10, 1100, 500)
        
        self.connect(self.combobox_options,
                     SIGNAL("currentIndexChanged(int)"), self.updateUi)
        self.setWindowTitle("ZhakraPro File Integrity Validator and Internet Monitor")

    def tab2UI(self):
        vbox2 = QVBoxLayout()
        hbox = QHBoxLayout()
        
        self.btn_acon = QPushButton("View Established Connections")
        self.btn_acon.clicked.connect(self.viewCon)
        
        self.btn_rprocess = QPushButton("View Running Processes")
        self.btn_rprocess.clicked.connect(self.viewProc)

        self.btn_stat = QPushButton("View Statistics")
        self.btn_stat.clicked.connect(self.nt_usage)

        self.btn_proc = QPushButton("View Process Users")
        self.btn_proc.clicked.connect(self.pusers)
        
        self.browser1 = QTextBrowser()
        self.browser1.setAlignment(Qt.AlignCenter)

        self.btn_metrics = QPushButton("View Metrics")
        self.btn_metrics.clicked.connect(self.metrics)

        self.btn_pkiller = QPushButton("Stop Process")
        self.btn_pkiller.clicked.connect(self.pkiller)

        self.btn_tracker = QPushButton("IP Geolocator")
        self.btn_tracker.clicked.connect(self.locator)

        self.btn_rtkit = QPushButton("Search Rootkit")
        self.btn_rtkit.clicked.connect(self.search_rtkit)

        hbox.addWidget(self.btn_acon)
        hbox.addWidget(self.btn_rprocess)
        hbox.addWidget(self.btn_stat)
        hbox.addWidget(self.btn_proc)

        hbox.addWidget(self.btn_metrics)
        hbox.addWidget(self.btn_pkiller)
        hbox.addWidget(self.btn_tracker)
        hbox.addWidget(self.btn_rtkit)
        vbox2.addLayout(hbox)

        vbox2.addWidget(self.browser1)
        self.tab2.setLayout(vbox2)

    def tab3UI(self):
        self.le_dir = QLineEdit("Directory or Folder Path.")
        self.btn_vmodif = QPushButton("View File History")
        self.btn_vmodif.clicked.connect(self.fhistory)
        self.browser2 = QTextBrowser()

        vbox3 = QVBoxLayout()
        vbox3.addWidget(self.le_dir)
        vbox3.addWidget(self.btn_vmodif)
        vbox3.addWidget(self.browser2)
        self.tab3.setLayout(vbox3)
        
        

            
    def tab4UI(self):
        self.browser3 = QTextBrowser()
        self.browser3.setText("This application is written in Python 2.7.14 and PyQt4."+"\n"\
                             +"Version 1.4.1" + "\n"\
                             +"author: Daniel Osinachi N." +"\n"\
                              +"dan.ossy.do@gmail.com"+"\n"\
                              +"Copyright (C) 2018 Daniel Osinachi N.")
            
        vbox4 = QVBoxLayout()
        vbox4.addWidget(self.browser3)
        self.tab4.setLayout(vbox4)

    

    def updateUi(self):
        ind = int(self.combobox_options.currentIndex())

        if ind == 1:
            self.Zhak_sha1()
        elif ind == 2:
            self.Zhak_sha256()
        elif ind == 3:
            self.Zhak_sha384()
        elif ind == 4:
            self.Zhak_sha512()
        elif ind == 5:
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
            

    def search_rtkit(self):
        text, ok = QInputDialog.getText(self, "Search RootKit", "Enter RootKit Name:")
        if ok and text:
            rtkit = str(text)
            rtkit = rtkit.lower()
            running_proc = subprocess.check_output(['ps', 'aux'])
            rewords = re.findall(r'\w+', running_proc)
            #finder = [i for i in rewords if (i == rtkit)]
            
            finder = [rewords[rewords.index(i) -27:rewords.index(i) +2] for i in rewords if (i == rtkit)]
            if (len(finder) > 0):
                self.browser1.setText("Found " + str(len(finder)) +"\n"
                                      + "[*] Please find the PID in the following and confirm using <view process users button>:" +"\n"
                                      + "%s" %(finder[0]))
            else:
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
                
        
                     
        
