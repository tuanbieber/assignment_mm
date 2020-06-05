import time
import os
import sys
import PyQt5.QtWidgets as QtWidgets
from PyQt5 import QtCore
from PyQt5.QtWidgets import QCheckBox, QLineEdit, QDialog, QDialogButtonBox, QMessageBox, QPushButton, QApplication, QWidget, QInputDialog, QLineEdit, QFileDialog, QMainWindow, QAction, QMenu, QPlainTextEdit, QLabel, QProgressBar
from PyQt5.QtGui  import QPixmap, QFont
from Encryptor import *

class MainWindow(QtWidgets.QMainWindow, QtWidgets.QApplication):

    def __init__(self, app): # ham __init__ mac dinh, parameter la app
        self.app = app

        QtWidgets.QMainWindow.__init__(self, None)

        self.screen_size = app.primaryScreen().size()
        self.screen_height = self.screen_size.height()
        self.screen_width  = self.screen_size.width()

        self.encrypt_file_file_name_1 = None
        self.encrypt_file_key_name_1 = None
        self.encrypt_file_key_password = None

        self.encrypt_folder_folder_name_1 = None
        self.encrypt_folder_key_name_1 = None

        self.decrypt_file_file_name_1 = None
        self.decrypt_file_key_name_1 = None

        self.progressBar = QProgressBar(self)

        self.grid = QtWidgets.QGridLayout()
        self.frame = QtWidgets.QFrame()

        self.add_method_group_box()
        self.add_logo_group_box()
        self.add_RSA_group_box()
        self.add_encrypt_file_group_box()
        self.add_decrypt_group_box()
        self.add_encrypt_folder_group_box()
        self.add_check_integrity_group_box()

        self.setWindowTitle('Nguyen Thanh Tuan - 1613907')
        self.setMaximumWidth(800)
        self.setMaximumHeight(800)
        self.frame.setLayout(self.grid)
        self.setCentralWidget(self.frame)
        self.show()
    
    # ADDING GROUP BOX TO GUI

    def add_method_group_box(self):
        self.method_group_box = QtWidgets.QGroupBox("Method")
        self.add_method_group_box_layout = QtWidgets.QGridLayout()

        self.method_group_box_label_1 = QLabel('DES is OFF')
        self.method_group_box_label_2 = QLabel('AES CFB 256 is OFF')
        self.method_group_box_label_3 = QLabel('RSA is OFF')
        self.method_group_box_cb_1 = QCheckBox()
        self.method_group_box_cb_2 = QCheckBox()
        self.method_group_box_cb_3 = QCheckBox()
        self.method_group_box_cb_1.stateChanged.connect(lambda: self.turn_on_DES())
        self.method_group_box_cb_2.stateChanged.connect(lambda: self.turn_on_AES())
        self.method_group_box_cb_3.stateChanged.connect(lambda: self.turn_on_RSA())
      
        self.add_method_group_box_layout.addWidget(self.method_group_box_cb_1,    0, 0, 1, 1)
        self.add_method_group_box_layout.addWidget(self.method_group_box_label_1, 0, 1, 1, 1)
        self.add_method_group_box_layout.addWidget(self.method_group_box_cb_2,    1, 0, 1, 1)
        self.add_method_group_box_layout.addWidget(self.method_group_box_label_2, 1, 1, 1, 1)
        self.add_method_group_box_layout.addWidget(self.method_group_box_cb_3,    2, 0, 1, 1)
        self.add_method_group_box_layout.addWidget(self.method_group_box_label_3, 2, 1, 1, 1)

        self.method_group_box.setLayout(self.add_method_group_box_layout)
        self.grid.addWidget(self.method_group_box, 0, 0, 1, 1)

    def add_RSA_group_box(self):
        self.rsa_group_box = QtWidgets.QGroupBox("RSA generating key pair")
        self.add_rsa_group_box_layout = QtWidgets.QGridLayout()

        # self.add_rsa_generating_pubic_key = QPushButton('Generate public key')
        self.add_rsa_generating_private_key = QPushButton('Generate private key and public key')

        # self.add_rsa_group_box_layout.addWidget(self.add_rsa_generating_pubic_key, 0, 0, 1, 1)
        self.add_rsa_group_box_layout.addWidget(self.add_rsa_generating_private_key, 0, 0, 1, 1)

        # self.add_rsa_generating_pubic_key.clicked.connect(lambda: self.save_public_key())
        self.add_rsa_generating_private_key.clicked.connect(lambda: self.saving_key_pair())

        self.rsa_group_box.setLayout(self.add_rsa_group_box_layout)
        self.grid.addWidget(self.rsa_group_box, 3, 0, 1, 1)

    def add_logo_group_box(self):
        self.logo_group_box = QtWidgets.QGroupBox("Logo")
        self.logo_layout = QtWidgets.QGridLayout()

        self.label_logo = QLabel(self)
        self.pixmap1 = QPixmap(resource_path('noname.png'))
        self.pixmap_resized = self.pixmap1.scaled( self.screen_height // 2.8 , self.screen_width // 1.0 , QtCore.Qt.KeepAspectRatio)
        self.label_logo.setPixmap(self.pixmap_resized)

        self.logo_layout.addWidget(self.label_logo, 0, 0, 1, 1)

        self.logo_group_box.setLayout(self.logo_layout)
        self.grid.addWidget(self.logo_group_box, 1, 0, 2, 1)

    def add_encrypt_file_group_box(self):
        self.encrypt_file_group_box = QtWidgets.QGroupBox("Encryption file")
        self.encrypt_layout = QtWidgets.QGridLayout()

        self.encrypt_file_button_1 = QPushButton('Open file')
        self.encrypt_file_label_1 = QLabel('No file selected')
        self.encrypt_file_button_2 = QPushButton('Open encryption key')
        self.encrypt_file_label_2 = QLabel('No key selected')
        self.encrypt_file_label_3 = QLabel('         Password')
        self.encrypt_file_button_3 = QPushButton('Start to encrypt file')
        self.encrypt_file_textline_1 = QLineEdit()
        self.encrypt_file_textline_1.setEchoMode(QtWidgets.QLineEdit.Password)
        self.encrypt_file_group_box.setMaximumWidth(500)
        self.progressBar_1 = QProgressBar()

        self.encrypt_file_button_1.clicked.connect(lambda: self.open_file(self.encrypt_file_file_name_1, self.encrypt_file_label_1))
        self.encrypt_file_button_2.clicked.connect(lambda: self.open_key(self.encrypt_file_key_name_1, self.encrypt_file_label_2))
        self.encrypt_file_button_3.clicked.connect(lambda: self.start_to_encrypt_file())

        self.encrypt_layout.addWidget(self.encrypt_file_button_1, 0, 0)
        self.encrypt_layout.addWidget(self.encrypt_file_label_1,  0, 1)
        self.encrypt_layout.addWidget(self.encrypt_file_button_2, 1, 0)
        self.encrypt_layout.addWidget(self.encrypt_file_label_2,  1, 1)
        self.encrypt_layout.addWidget(self.encrypt_file_label_3, 2, 0, 1, 1)
        self.encrypt_layout.addWidget(self.encrypt_file_textline_1, 2, 1, 1, 1)
        self.encrypt_layout.addWidget(self.encrypt_file_button_3, 3, 0, 1, 2)
        self.encrypt_layout.addWidget(self.progressBar_1, 4, 0, 1, 2)

        self.encrypt_file_group_box.setLayout(self.encrypt_layout)
        self.grid.addWidget(self.encrypt_file_group_box, 0, 1, 1, 1)

        self.encrypt_file_group_box.setEnabled(False)

    def add_encrypt_folder_group_box(self):
        self.encrypt_folder_group_box = QtWidgets.QGroupBox("Encryption folder")
        self.encrypt_folder_layout = QtWidgets.QGridLayout()

        self.encrypt_folder_button_1 = QPushButton('Open folder')
        self.encrypt_folder_label_1 = QLabel('No folder selected')
        self.encrypt_folder_button_2 = QPushButton('Open encryption key')
        self.encrypt_folder_label_2 = QLabel('No key selected')
        self.encrypt_folder_button_3 = QPushButton('Start to encrypt folder')
        self.encrypt_folder_progressBar_1 = QProgressBar()
        self.encrypt_folder_linetext_1 = QLineEdit()
        self.encrypt_folder_linetext_1.setEchoMode(QtWidgets.QLineEdit.Password)
        self.encrypt_folder_label_3 = QLabel('         Password')
        self.encrypt_folder_group_box.setMaximumWidth(500)

        self.encrypt_folder_button_1.clicked.connect(lambda: self.open_folder(self.encrypt_folder_folder_name_1, self.encrypt_folder_label_1))
        self.encrypt_folder_button_2.clicked.connect(lambda: self.open_key(self.encrypt_folder_key_name_1, self.encrypt_folder_label_2))
        self.encrypt_folder_button_3.clicked.connect(lambda: self.start_to_encrypt_folder())

        self.encrypt_folder_layout.addWidget(self.encrypt_folder_button_1, 0, 0)
        self.encrypt_folder_layout.addWidget(self.encrypt_folder_label_1,  0, 1)
        self.encrypt_folder_layout.addWidget(self.encrypt_folder_button_2, 1, 0)
        self.encrypt_folder_layout.addWidget(self.encrypt_folder_label_2,  1, 1)
        self.encrypt_folder_layout.addWidget(self.encrypt_folder_label_3, 2, 0, 1, 1)
        self.encrypt_folder_layout.addWidget(self.encrypt_folder_linetext_1, 2, 1, 1, 1)
        self.encrypt_folder_layout.addWidget(self.encrypt_folder_button_3, 3, 0, 1, 2)
        self.encrypt_folder_layout.addWidget(self.encrypt_folder_progressBar_1, 4, 0, 1, 2)

        self.encrypt_folder_group_box.setLayout(self.encrypt_folder_layout)
        self.grid.addWidget(self.encrypt_folder_group_box, 1, 1, 1, 1)

        self.encrypt_folder_group_box.setEnabled(False)

    def add_decrypt_group_box(self):
        self.decrypt_group_box = QtWidgets.QGroupBox("Decryption file")
        self.decrypt_layout = QtWidgets.QGridLayout()

        self.decrypt_file_button_1 = QPushButton('Open file')
        self.decrypt_file_label_1 = QLabel('No file selected')
        self.decrypt_file_button_2 = QPushButton('Open decryption key')
        self.decrypt_file_label_2 = QLabel('No key selected')
        self.decrypt_file_label_3 = QLabel('         Password')
        self.decrypt_file_button_3 = QPushButton('Start to decrypt file')
        self.progressBar_2 = QProgressBar()
        self.decrypt_group_box.setMaximumWidth(500)
        self.decrypt_file_linetext_1 = QLineEdit()
        self.decrypt_file_linetext_1.setEchoMode(QtWidgets.QLineEdit.Password)


        self.decrypt_file_button_1.clicked.connect(lambda: self.open_file(self.decrypt_file_file_name_1, self.decrypt_file_label_1))
        self.decrypt_file_button_2.clicked.connect(lambda: self.open_key(self.decrypt_file_key_name_1, self.decrypt_file_label_2))
        self.decrypt_file_button_3.clicked.connect(lambda: self.start_to_decrypt_file())

        self.decrypt_layout.addWidget(self.decrypt_file_button_1, 0, 0)
        self.decrypt_layout.addWidget(self.decrypt_file_label_1,  0, 1)
        self.decrypt_layout.addWidget(self.decrypt_file_button_2, 1, 0)
        self.decrypt_layout.addWidget(self.decrypt_file_label_2,  1, 1)
        self.decrypt_layout.addWidget(self.decrypt_file_label_3, 2, 0, 1, 1)
        self.decrypt_layout.addWidget(self.decrypt_file_linetext_1, 2, 1, 1, 1)
        self.decrypt_layout.addWidget(self.decrypt_file_button_3, 3, 0, 1, 2)
        self.decrypt_layout.addWidget(self.progressBar_2, 4, 0, 1, 2)

        self.decrypt_group_box.setLayout(self.decrypt_layout)
        self.grid.addWidget(self.decrypt_group_box, 2, 1, 1, 1)

        self.decrypt_group_box.setEnabled(False)

    def add_check_integrity_group_box(self):
        self.integrity_group_box = QtWidgets.QGroupBox("Check Integriry SHA256")
        self.integrity_layout = QtWidgets.QGridLayout()

        self.integiry_label_1 = QLabel('No file selected')
        self.integiry_label_2 = QLabel('No file selected')
        self.integrity_button_1 = QPushButton('Original file')
        self.integrity_button_2 = QPushButton('Decrypted file')
        self.integrity_button_3 = QPushButton('Check')
        self.integrity_group_box.setMaximumWidth(500)

        self.integrity_button_1.clicked.connect(lambda: self.integrity_get_original_file_name())
        self.integrity_button_2.clicked.connect(lambda: self.integirity_get_decrypted_file_name())
        self.integrity_button_3.clicked.connect(lambda: self.integrity_function_3())


        self.integrity_layout.addWidget(self.integrity_button_1, 1, 0, 1, 1)
        self.integrity_layout.addWidget(self.integiry_label_1, 1, 1, 1, 1)
        self.integrity_layout.addWidget(self.integrity_button_2, 2, 0, 1, 1)
        self.integrity_layout.addWidget(self.integiry_label_2, 2, 1, 1, 1)
        self.integrity_layout.addWidget(self.integrity_button_3, 3, 0, 1, 2)
        
        self.integrity_group_box.setLayout(self.integrity_layout)
        self.grid.addWidget(self.integrity_group_box, 3, 1, 1, 1)

    # FUNCTIOS TO HANDLE EVENTS

    def start_to_encrypt_file(self):

        file_path = self.encrypt_file_label_1.text()
        key_path = self.encrypt_file_label_2.text()
        password =  self.encrypt_file_textline_1.text()
        progress_bar = self.progressBar_1

        if file_path == 'No file selected' :
            msg = QMessageBox()
            msg.setWindowTitle("Alert")
            text = "Please choose a file to encrypt !"
            msg.setText(text)
            x = msg.exec_()  # this will show our messagebox
            return 

        if key_path == 'No key selected':
            msg = QMessageBox()
            msg.setWindowTitle("Alert")
            text = "Please choose a key to encrypt !"
            msg.setText(text)
            x = msg.exec_()  # this will show our messagebox
            return 

        if os.path.exists(file_path+'.encrypted'):
            msg = QMessageBox()
            msg.setWindowTitle("Alert")
            text = "File already encrypted !"
            msg.setText(text)
            x = msg.exec_()  # this will show our messagebox
            # reset the password field
            self.encrypt_file_textline_1.setText('')
            return 

        cryptography = Cryptography()
        if self.method_group_box_cb_1.isChecked():
            cryptography.DES_Encryptor(file_path, key_path, password, progress_bar)
        elif self.method_group_box_cb_2.isChecked(): # aes in on
            cryptography.AES_Encryptor(file_path, key_path, password, progress_bar)
        elif self.method_group_box_cb_3.isChecked():
            encrypted_blob = cryptography.rsa_encrypt_blob(file_path, key_path, progress_bar) # here: key_path is the public key
            #Write the encrypted contents to a file
            fd = open(file_path + '.encrypted', "wb")
            fd.write(encrypted_blob)
            fd.close()

        msg = QMessageBox()
        msg.setWindowTitle("Result")
        text = "Encrypt file successfully !"
        msg.setText(text)
        x = msg.exec_()  # this will show our messagebox

        self.encrypt_file_textline_1.setText('')

    def start_to_decrypt_file(self):
        file_path = self.decrypt_file_label_1.text()
        key_path = self.decrypt_file_label_2.text()
        password = self.decrypt_file_linetext_1.text()
        progress_bar = self.progressBar_2

        if file_path == 'No file selected' :
            msg = QMessageBox()
            msg.setWindowTitle("Alert")
            text = "Please choose a file to decrypt !"
            msg.setText(text)
            x = msg.exec_()  # this will show our messagebox
            return 

        if key_path == 'No key selected':
            msg = QMessageBox()
            msg.setWindowTitle("Alert")
            text = "Please choose a key to decrypt !"
            msg.setText(text)
            x = msg.exec_()  # this will show our messagebox
            return 

        if os.path.exists(file_path.replace('.encrypted', '.decrypted')):
            msg = QMessageBox()
            msg.setWindowTitle("Alert")
            text = "File already decrypted !"
            msg.setText(text)
            x = msg.exec_()  # this will show our messagebox
            # reset the password field
            self.decrypt_file_linetext_1.setText('')
            return 

        cryptography = Cryptography()
        if self.method_group_box_cb_1.isChecked():
            cryptography.DES_Decryptor(file_path, key_path, password, progress_bar)
        elif self.method_group_box_cb_2.isChecked():
            cryptography.AES_Decryptor(file_path, key_path, password, progress_bar)
        elif self.method_group_box_cb_3.isChecked():
            decrypted_blob = cryptography.rsa_decrypt_blob(file_path, key_path, progress_bar) 

            #Write the encrypted contents to a file
            fd = open(file_path.replace('.encrypted', '.decrypted'), "wb")
            fd.write(decrypted_blob)
            fd.close()


        msg = QMessageBox()
        msg.setWindowTitle("Result")
        text = "Decrypt file successfully !"
        msg.setText(text)
        x = msg.exec_()  # this will show our messagebox

        self.decrypt_file_linetext_1.setText('')

        # print('decryption process has finished !')

    def start_to_encrypt_folder(self):
        folder_name = self.encrypt_folder_label_1.text() 
        key_path = self.encrypt_folder_label_2.text()
        password = self.encrypt_folder_linetext_1.text()
        progress = self.encrypt_folder_progressBar_1

        if folder_name == 'No folder selected' :
            msg = QMessageBox()
            msg.setWindowTitle("Alert")
            text = "Please choose a folder to encrypt !"
            msg.setText(text)
            x = msg.exec_()  # this will show our messagebox
            return 

        if key_path == 'No key selected':
            msg = QMessageBox()
            msg.setWindowTitle("Alert")
            text = "Please choose a key to encrypt !"
            msg.setText(text)
            x = msg.exec_()  # this will show our messagebox
            return 

        for file in os.listdir(folder_name):
            # start to encrypt every single file
            file_name = folder_name + '/' + file
            if '.encrypted' in file_name:
                pass
            elif os.path.exists(file_name+'.encrypted'):
                msg = QMessageBox()
                msg.setWindowTitle("Alert")
                text = "File " + file_name + " already encrypted !"
                msg.setText(text)
                x = msg.exec_()  # this will show our messagebox
                # reset the password field
                self.encrypt_folder_linetext_1.setText('')
            else:

                cryptography = Cryptography()
                if self.method_group_box_cb_1.isChecked():
                    cryptography.DES_Encryptor(file_name, key_path, password, progress)
                elif self.method_group_box_cb_2.isChecked(): # aes in on
                    cryptography.AES_Encryptor(file_name, key_path, password, progress)
                elif self.method_group_box_cb_3.isChecked():
                    encrypted_blob = cryptography.rsa_encrypt_blob(file_name, key_path, progress) # here: key_path is the public key

                    #Write the encrypted contents to a file
                    fd = open(file_name + '.encrypted', "wb")
                    fd.write(encrypted_blob)
                    fd.close()

        self.encrypt_folder_linetext_1.setText('')

    def open_file(self, a, b): # a is the name of encrypt file, b is the label needed to changed
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getOpenFileName(None,"QFileDialog.getOpenFileName()", "","All Files (*);;", options=options)
        if fileName:
            a = fileName
            b.setText(str(a))
      
    def open_key(self, a, b):
        if self.method_group_box_cb_3.isChecked():
            options = QFileDialog.Options()
            options |= QFileDialog.DontUseNativeDialog
            fileName, _ = QFileDialog.getOpenFileName(None,"QFileDialog.getOpenFileName()", "","Pem Files (*.pem)", options=options)
            if fileName:
                a = fileName
                b.setText(str(a))
        else:
            options = QFileDialog.Options()
            options |= QFileDialog.DontUseNativeDialog
            fileName, _ = QFileDialog.getOpenFileName(None,"QFileDialog.getOpenFileName()", "","All Files (*)", options=options)
            if fileName:
                a = fileName
                b.setText(str(a))

    def open_folder(self, a, b):
        folder_name = str(QFileDialog.getExistingDirectory(self, "Select folder to encrypt"))
        a = folder_name
        b.setText(str(folder_name))
        self.encrypt_folder_folder_name_1 = folder_name

    def integrity_get_original_file_name(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getOpenFileName(None,"QFileDialog.getOpenFileName()", "","All Files (*)", options=options)
        if not fileName:
            return 
        else:
            self.intergrity_in_file = fileName
            self.integiry_label_1.setText(fileName)

    def integirity_get_decrypted_file_name(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getOpenFileName(None,"QFileDialog.getOpenFileName()", "","All Files (*)", options=options)
        if not fileName:
            return 
        else:
            self.intergrity_out_file = fileName
            self.integiry_label_2.setText(fileName)

    def integrity_function_3(self):
        if self.integiry_label_1.text() == 'No file selected':
            msg = QMessageBox()
            msg.setWindowTitle("Alert")
            text = "Please choose the original file !"
            msg.setText(text)
            x = msg.exec_()  # this will show our messagebox
            # reset the password field
            return 

        if self.integiry_label_2.text() == 'No file selected':
            msg = QMessageBox()
            msg.setWindowTitle("Alert")
            text = "Please choose the decrypted file !"
            msg.setText(text)
            x = msg.exec_()  # this will show our messagebox
            # reset the password field
            return 
            
        cryptography = Cryptography()
        if cryptography.assert_valid_output(self.intergrity_in_file, self.intergrity_out_file):
            msg = QMessageBox()
            msg.setWindowTitle("Alert")
            text = "Two files are identical !"
            msg.setText(text)
            x = msg.exec_()  # this will show our messagebox
            # reset the password field
            return 
        else: 
            msg = QMessageBox()
            msg.setWindowTitle("Alert")
            text = "Two files are NOT identical !"
            msg.setText(text)
            x = msg.exec_()  # this will show our messagebox
            # reset the password field
            return 

    def turn_on_DES(self):
        if self.method_group_box_cb_1.isChecked():
            self.method_group_box_label_1.setText('DES is ON')
            self.method_group_box_cb_2.setChecked(False)
            self.method_group_box_cb_3.setChecked(False)

            self.encrypt_file_group_box.setEnabled(True)
            self.encrypt_folder_group_box.setEnabled(True)
            self.decrypt_group_box.setEnabled(True)
        else:
            self.method_group_box_label_1.setText('DES is OFF')
            self.method_group_box_cb_2.setEnabled(True)
            self.method_group_box_cb_3.setEnabled(True)
            self.encrypt_file_group_box.setEnabled(False)

            self.encrypt_file_group_box.setEnabled(False)
            self.encrypt_folder_group_box.setEnabled(False)
            self.decrypt_group_box.setEnabled(False)

            # self.encrypt_file_label_1.setText('No file selected')
            self.encrypt_file_label_2.setText('No key selected')
            self.encrypt_file_textline_1.setText('')

            # self.decrypt_file_label_1.setText('No file selected')
            self.decrypt_file_label_2.setText('No key selected')
            self.decrypt_file_linetext_1.setText('')

            # self.encrypt_folder_label_1.setText('No folder selected')
            self.encrypt_folder_label_2.setText('No key selected')
            self.encrypt_folder_linetext_1.setText('')

            self.progressBar_1.setValue(0)
            self.encrypt_folder_progressBar_1.setValue(0)
            self.progressBar_2 .setValue(0)

    def turn_on_AES(self):
        if self.method_group_box_cb_2.isChecked():
            self.method_group_box_label_2.setText('AES CFB 256 is ON')
            self.method_group_box_cb_1.setChecked(False)
            self.method_group_box_cb_3.setChecked(False)

            self.encrypt_file_group_box.setEnabled(True)
            self.encrypt_folder_group_box.setEnabled(True)
            self.decrypt_group_box.setEnabled(True)
        else:
            self.method_group_box_label_2.setText('AES CFB 256 is OFF')
            self.method_group_box_cb_1.setEnabled(True)
            self.method_group_box_cb_3.setEnabled(True)

            self.encrypt_file_group_box.setEnabled(False)
            self.encrypt_folder_group_box.setEnabled(False)
            self.decrypt_group_box.setEnabled(False)

            # self.encrypt_file_label_1.setText('No file selected')
            self.encrypt_file_label_2.setText('No key selected')
            self.encrypt_file_textline_1.setText('')

            # self.decrypt_file_label_1.setText('No file selected')
            self.decrypt_file_label_2.setText('No key selected')
            self.decrypt_file_linetext_1.setText('')

            # self.encrypt_folder_label_1.setText('No folder selected')
            self.encrypt_folder_label_2.setText('No key selected')
            self.encrypt_folder_linetext_1.setText('')

            self.progressBar_1.setValue(0)
            self.encrypt_folder_progressBar_1.setValue(0)
            self.progressBar_2 .setValue(0)

    def turn_on_RSA(self):
        if self.method_group_box_cb_3.isChecked():
            self.method_group_box_label_3.setText('RSA is ON')
            self.method_group_box_cb_2.setChecked(False)
            self.method_group_box_cb_1.setChecked(False)

            self.encrypt_file_textline_1.hide()
            self.encrypt_file_label_3.hide()

            self.decrypt_file_linetext_1.hide()
            self.decrypt_file_label_3.hide()
            
            self.encrypt_folder_label_3.hide()
            self.encrypt_folder_linetext_1.hide()

            self.encrypt_file_group_box.setEnabled(True)
            self.encrypt_folder_group_box.setEnabled(True)
            self.decrypt_group_box.setEnabled(True)

        else:
            self.method_group_box_label_3.setText('RSA is OFF')
            self.method_group_box_cb_2.setEnabled(True)
            self.method_group_box_cb_1.setEnabled(True)

            self.encrypt_file_textline_1.show()
            self.encrypt_file_label_3.show()

            self.encrypt_folder_label_3.show()
            self.encrypt_folder_linetext_1.show()

            self.decrypt_file_linetext_1.show()
            self.decrypt_file_label_3.show()

            self.encrypt_file_group_box.setEnabled(False)
            self.encrypt_folder_group_box.setEnabled(False)
            self.decrypt_group_box.setEnabled(False)

            # self.encrypt_file_label_1.setText('No file selected')
            self.encrypt_file_label_2.setText('No key selected')
            self.encrypt_file_textline_1.setText('')

            # self.decrypt_file_label_1.setText('No file selected')
            self.decrypt_file_label_2.setText('No key selected')
            self.decrypt_file_linetext_1.setText('')

            # self.encrypt_folder_label_1.setText('No folder selected')
            self.encrypt_folder_label_2.setText('No key selected')
            self.encrypt_folder_linetext_1.setText('')

            self.progressBar_1.setValue(0)
            self.encrypt_folder_progressBar_1.setValue(0)
            self.progressBar_2 .setValue(0)

    def saving_key_pair(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName1, _ = QFileDialog.getSaveFileName(None,"Enter file name only", "public_key","Key file (*.pem);", options=options)
        # fileName, _ = QFileDialog.getSaveFileName(None,"Enter file name only", "","All Files (*);;Python Files (*.py)", options=options)

        if fileName1:
            msg = QMessageBox()
            msg.setWindowTitle("Result")
            text = "Please wait! This may take a few seconds to complete !"
            msg.setText(text)
            x = msg.exec_()  # this will show our messagebox
        else:
            return 
        
        crypto = Cryptography()
        private_key, public_key = crypto.rsa_generating_key_pair()

        if fileName1:
            fileName1 = fileName1 + '.pem' 
            # print('this is file name ', fileName)
            file = open(fileName1,'wb')
            file.write(public_key)
            file.close()

            msg = QMessageBox()
            msg.setWindowTitle("Result")
            text = "Generating public key successfully !"
            msg.setText(text)
            x = msg.exec_()  # this will show our messagebox

        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName2, _ = QFileDialog.getSaveFileName(None,"Enter file name only", "private_key","Key file (.pem);", options=options)
        
        if fileName2:
            msg = QMessageBox()
            msg.setWindowTitle("Result")
            text = "Please wait! This may take a few seconds to complete !"
            msg.setText(text)
            x = msg.exec_()  # this will show our messagebox
        else:
            return 

        if fileName2:
            fileName2 = fileName2 + '.pem' 
            # print('this is file name ', fileName)
            file = open(fileName2,'wb')
            file.write(private_key)
            file.close()

            msg = QMessageBox()
            msg.setWindowTitle("Result")
            text = "Generating private key successfully !"
            msg.setText(text)
            x = msg.exec_()  # this will show our messagebox

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv) # truyền vào hai args cho hàm 
    file_name = resource_path('captk.qss')
    with open(file_name) as css:
        read_css = css.read()
        app.setStyleSheet(read_css)

    window = MainWindow(app) # goi ham MainWindow, truyen parameter la app

    sys.exit(app.exec_())