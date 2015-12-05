# Section for allowing import of custom classes
import sys
import os

if sys.path[0] != os.path.dirname(os.path.realpath(sys.argv[0])):
    sys.path.insert(0, os.path.dirname(os.path.realpath(sys.argv[0])))

# import the necessary libraries
import hashlib
import cryptography
import Crypto
import timeit # ERROR TESTING REMOVE
import time

# Key derivation function imports
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

import Crypto
import Crypto.Cipher.DES3
import Crypto.Util # ERROR TESTING
import Crypto.Cipher.blockalgo # To get modes of operation for ciphers

# import necessary custom files
import MyBitArray
import BinaryFileHandler
from TimeResults import TimeResults

# Open a given file in byte format
# Start the timer
# Encrypt the file
# Decrypt the file
# Hash the file
# Stop the timer and record the performance of the algorithm.
    # Record the algorithm, the surrounding library, the time taken, and the
    # process iteration number
# Repeat process several times (3)

# Necessary algorithms:
# Block cipher
    # DES
    # Blowfish
# Stream cipher
    # ARC4
    # AES (CTR)
# Asymmetric key encryption
    # RSA
    # DSA
# Hashing algorithm
    # SHA256
    # MD5

class FinalMain:
    def __init__(self, password_filename, message):
        # Establish string representations of ciphers used
        self.blockCipher1 = "Triple DES"
        self.blockCipher2 = "Blowfish"
        self.streamCipher1 = "ARC4"
        self.streamCipher2 = "AES (CTR mode)"
        self.pke1 = "RSA"
        self.pke2 = "DSA"
        self.hash1 = "SHA256"
        self.hash2 = "MD5"
        
        # Create empty dictionaries to store the time results of used libraries
        self.cryptographyTimeResults = {}
        self.PyCryptoTimeResults = {}

        # Run tests
        self.RunLibraryCiphers(password_filename, message.encode("utf-8"))

    def SplitMessage(self, message_byte_array, block_length):
        '''Expects block length to be in bytes.'''
        resultArray = []
        index = 0
        while index < len(message_byte_array):
            resultArray.append(message_byte_array[index : index + block_length])
            index += block_length
        
        return resultArray

    def AddPadding(self, message_byte_array, block_length):
        '''Adds simple padding since none of the libraries seem to implement
           their own.'''

        temp = []
        if len(message_byte_array) % block_length != 0:
            padByte = block_length - (len(message_byte_array) % block_length)
            temp.extend([padByte] * padByte)

        result = []
        result.extend(message_byte_array)
        result.extend(temp)

        return result
        

    def RemovePadding(self, message_byte_array, block_length):
        '''Removes simple padding since none of the libraries seem to implement
           their own.'''
        # Guard conditions
        if len(message_byte_array) < 1:
            return message_byte_array
        
        try:
            padByte = message_byte_array[len(message_byte_array) - 1]
        except IndexError: # ERROR TESTING
            print("index " + str(len(message_byte_array) - 1))
        try:
            if padByte < len(message_byte_array) and \
               padByte == message_byte_array[len(message_byte_array) - padByte]:
                return message_byte_array[:len(message_byte_array) - padByte]
            else:
                return message_byte_array
        except IndexError:
            # ERROR TESTING remove try-except
            print("padbyte " + str(padByte))

    def RunLibraryCiphers(self, password_filename, message):
        '''Runs all designated encryption ciphers. Utilizes the same encryption
           key for symmetric key ciphers and the same pair of keys for asymmetric
           key ciphers.'''

        # Derive a 30-byte salt for use with key derivation
        salt = os.urandom(30)

        # Take a key from a text file
        password = BinaryFileHandler.ReadByteDataFile(password_filename)

        # Run tests regarding the symmetric ciphers, which includes the block
        # ciphers and the stream ciphers
        self.RunBlockCiphers(message, 1, password, salt)
        #RunStreamCiphers(7)

        # Run tests regarding the asymmetric ciphers. The asymmetric ciphers
        # keys separate from the symmetric key generated above, so that will be
        # handled in RunPublicKeyEncrypt.
        #RunPublicKeyEncrypt(3)

        # Run tests regarding the hashing capabilities of the used libraries.
        #RunHashing(30)

        # cryptography backend for use with initializing an asymmetric key
        #backend = cryptography.hazmat.backends.interfaces.RSABackend
        
    
    def RunBlockCiphers(self, message, n_runs, password, salt):
        '''Runs the two block ciphers several times between all three libraries
           in order to assess their performance capabilities.

           Returns nothing.'''
        self.cryptographyTimeResults[self.blockCipher1] = TimeResults(self.blockCipher1, "cryptography")
        # ERROR TESTNIG
        #print(str(self.cryptographyTimeResults[self.blockCipher1]))
        
        self.cryptographyTimeResults[self.blockCipher2] = TimeResults(self.blockCipher2, "cryptography")
        self.PyCryptoTimeResults[self.blockCipher1] = TimeResults(self.blockCipher1, "PyCrypto")
        self.PyCryptoTimeResults[self.blockCipher2] = TimeResults(self.blockCipher2, "PyCrypto")

        # Create triple DES key (192 bits)
        tripleDESKeyDeriver = cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length = 24, # 192 bits
            salt = salt,
            iterations = 2000,
            backend = default_backend()
            )
        tripleDESKey = tripleDESKeyDeriver.derive(password)
        
        # Run algorithms
        self.RunBlockCipher1(message, n_runs, tripleDESKey)
        # ERROR TESTING self.RunBlockCipher2()

        # ERROR TESTING
        print("Cryptography module produced DES3 times of: " + str(self.cryptographyTimeResults))
        print()
        print("PyCrypto module produced DES3 times of: " + str(self.PyCryptoTimeResults))
        print()

    def RunBlockCipher1(self, message, n_runs, key):
        '''Implemented as using Triple DES (Data Encryption Standard) symmetric
           block cipher using 192 bits (24 bytes).

           Runs the first block cipher to assess performance.

           Returns nothing.'''

        for i in range(n_runs):
            #####
            # Run cryptography library implementation

            startTime = time.time() * 10e9

            blockLength = 16
            IV = os.urandom(blockLength)
            tripleDES = Cipher(algorithms.AES(key), modes.CBC(IV), default_backend())
            tripleDESencryptor = tripleDES.encryptor()
            tripleDESdecryptor = tripleDES.decryptor()
            
            # ERROR TESTING
            # Since there doesn't appear to be a built-in padding scheme, I use
            # my own simple one here to conform to cryptography's padding
            # requirement.
            paddedMessage = self.AddPadding(bytearray(message), blockLength)
            # ERROR TESTING
            #print("Padded message is " + str(paddedMessage) + " len(" + str(len(paddedMessage)) + ")")
            
            unpaddedMessage = self.RemovePadding(tripleDESdecryptor.update(tripleDESencryptor.update(paddedMessage)), blockLength)
            # ERROR TESTING just for checking message validity
            #print("Message = " + str(message) + "len(" + str(len(message)) + ")")
            #print("Padded message = " + str(bytearray(paddedMessage)) + "len(" + str(len(paddedMessage)) + ")")
            #print("Decrypted message = " + str(unpaddedMessage) + "len(" + str(len(unpaddedMessage)) + ")")
            
            # ERROR TESTING
            # There is an issue with the finalize function, wherein it seemingly
            # cannot be called as described. It always throws an error arguing that
            # input length is inappropriate, signifying a logic error I am not able
            # to reconcile. Therefore, both the decryptor and encryptor finalize
            # sections have been dropped, which may be the cause that the decrypted
            # message is being arbitrarily truncated with segments of the message
            # remaining in the decryptor's buffer.
            
            
            endTime = time.time() * 10e9

            # ERROR TESTING
            print("start time: " + str(startTime))
            print("end time: " + str(endTime))

            self.cryptographyTimeResults[self.blockCipher1].append((endTime - startTime)/10e3)

            #####
            # Run PyCrypto library implementation
            startTime = time.time()
            blockLength = 8
            IV = os.urandom(blockLength)
            tripleDES = Crypto.Cipher.DES3.new(key, mode=Crypto.Cipher.blockalgo.MODE_CBC, IV=IV)            
            paddedMessage = self.AddPadding(bytearray(message), blockLength)
            extendedMessage = bytearray(IV)
            extendedMessage.extend(paddedMessage)
            
            encryptedMessage = tripleDES.encrypt(bytes(extendedMessage))
            # ERROR TESTING
            #print("Encrypted message = " + str(encryptedMessage))

            decryptedMessage = tripleDES.decrypt(encryptedMessage)
            unpaddedMessage = self.RemovePadding(decryptedMessage[blockLength:], blockLength)
            # ERROR TESTING
            #print("Decrypted message = " + str(decryptedMessage))
            #print("Unpadded message = " + str(unpaddedMessage))
            
            endTime = time.time()
            self.PyCryptoTimeResults[self.blockCipher1].append(endTime - startTime)

    #def RunBlockCipher2:
        '''Implemented as using Blowfish symmetric block cipher.

           Runs the second block cipher to assess performance.

           Returns nothing.'''
     #   return None

    #def RunStreamCiphers:

    #def RunStreamCipher1:

    #def RunStreamCipher2:

    #def RunPublicKeyEncrypt:

    #def RunPKE1:

    #def RunPKE2:

    #def RunPublicKeyDecrypt:

    #def RunPKD1:

    #def RunPKD2:

    #def RunHashing:

    #def Run

if __name__ == "__main__":
    print("Running main for FinalMain.")
    print("Module found in " + str(os.path.dirname(os.path.realpath(sys.argv[0]))))
    print()

    passwordFilename = "TestPassword.txt"
    message = "This is a test message. Of great size."
    finalClass = FinalMain(passwordFilename, message)
