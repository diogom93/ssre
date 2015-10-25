"""
Basic Keystore class/module

Diogo Martins & João Meira
MIEEC//FEUP 2015

License: Beerware (free to use and abuse but you buy us a beer if we ever meet)

Currently:
In development
As of:
October 2015
"""

import pydoc
import os
import xml.dom.minidom
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey, AlreadyFinalized

class KeyPair:
    """
    Basic KeyPair object. Encapsulates a key pair with all its structure
    """

    def __init__(self, alias, keyalg, public_key, private_key):
        """
        Basic KeyPair object constructor.

        Arguments:
            alias         - The alias of the key pair
            keyalg        - The algorithm used in encryption
            public_key    - The public counterpart of the pair
            private_key   - The private counterpart of the pair
        """

        self.alias          = alias
        self.keyalg         = keyalg
        self.public_key     = public_key
        self.private_key    = private_key


class KeyStore:
    """
    Basic Keystore object. Encapsulates a keystore file and its functionality.
    """

    def __init__(self, name, file_locus=None):
        """
        Basic Keystore object constructor.

        Arguments:
            name        - The name of the KeyStore file
            file_locus  - The path to the KeyStore file. Defaults to HOME
        Raises:
            OSError     - On file_locus not found
        """

        if file_locus is None:
            self.locus = os.path.expanduser('~')
        elif not os.path.exists(file_locus):
            self.locus = None
            raise OSError("KeyStore path not found!")
        else:
            self.locus = file_locus

        self.name       = name
        self.file_name  = os.path.join(self.locus, self.name)
        self.keys       = {}
        self.__import_keystore()


    def __import_keystore(self):
        """
        Decrypts and imports keystore file.
        Currently reading plainfiles only
        """
        #decryption goes here
        file_ = open(self.file_name)
        self.__load_xml_data(file_.read())

        print(self.keys)

    def getXMLText(nodelist):
        rc = []
        for node in nodelist:
            if node.nodeType == node.TEXT_NODE:
                rc.append(node.data)
        return ''.join(rc)

    def __load_xml_data(self, string):
        """
        Basic xml parser. Currently loading keys

        Arguments:
            string  - The string containing XML data
        """
        self.raw_dom = xml.dom.minidom.parseString(string)
        for key_ in self.raw_dom.getElementsByTagName("key"):
            key_alias       = KeyStore.getXMLText(key_.getElementsByTagName("alias")[0].childNodes)
            key_keyalg      = KeyStore.getXMLText(key_.getElementsByTagName("keyalg")[0].childNodes)
            key_public_key  = KeyStore.getXMLText(key_.getElementsByTagName("public_key")[0].childNodes)
            key_private_key = KeyStore.getXMLText(key_.getElementsByTagName("private_key")[0].childNodes)
            self.keys[key_alias] = KeyPair(key_alias, key_keyalg, key_public_key, key_private_key)


    def __generate_key(password):
        backend = default_backend()
        salt_file = open('salt.hex', 'rb')
        salt = salt_file.read()
        # derive
        kdf = PBKDF2HMAC(
         algorithm=hashes.SHA1(),
         length=32,
         salt=salt,
         iterations=100000,
         backend=backend
        )
        salt_file.close()
        return kdf.derive(password)

    def __verify(password, key):
        backend = default_backend()
        salt_file = open('salt.hex', 'rb')
        salt = salt_file.read()
        # verify
        kdf = PBKDF2HMAC(
         algorithm=hashes.SHA1(),
         length=32,
         salt=salt,
         iterations=100000,
         backend=backend
        )
        salt_file.close()
        try:
            kdf.verify(password, key)
        except:
            return False

        return True

    def store_key(key, keystore_file, master_password):
        """Encrypts file with the given password using RC4"""

        if(type(master_password) is str):
            master_password = str.encode(master_password)

        cipher = Cipher(algorithms.ARC4(master_password), mode=None, backend=default_backend())
        encryptor = cipher.encryptor()

        ct = encryptor.update(key)
        keystore_file.write(ct)

    def load_key(keystore_file, master_password):
        """Decrypts file with the given password using RC4"""

        if(type(master_password) is str):
            master_password = str.encode(master_password)

        cipher = Cipher(algorithms.ARC4(master_password), None, backend=default_backend())
        decryptor = cipher.decryptor()

        ct = keystore_file.read()

        dt = decryptor.update(ct)
        return dt

    def store_password(password, keystore_file_name, master_password):
        key = __generate_key(password)
        keystore_file = open(keystore_file_name, 'wb')
        store_key(key, keystore_file, master_password)
        keystore_file.close()

    def verify_key(rec_key, keystore_file_name, master_password):
        keystore_file = open(keystore_file_name, 'rb')
        good_key = load_key(keystore_file, master_password)
        keystore_file.close()
        return __verify(rec_key, good_key)

x = KeyStore('plain_keystore.xml', os.path.abspath(''))
