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
import Crypto.Cipher.Blowfish
import Crypto.Cipher.ARC4
import Crypto.Cipher.AES
import Crypto.Cipher.PKCS1_OAEP # ERROR TESTING RSA implementation?
import Crypto.Util.Counter # For use with PyCrypto's AES implementation of a CTR mode stream cipher (acts just like an initialization vector)
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
    def __init__(self, password_filename, message_filename):
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

        # Unwrap message
        #message_byte_array = BinaryFileHandler.ReadByteDataFile(message_filename)

        # ERROR TESTING
        directoryPath = BinaryFileHandler.GetScriptDirectory()
        dataFileName = BinaryFileHandler.GetFileNameWithExtension(message_filename)

        if len(dataFileName.split(".")) < 2:
            dataFileName += ".txt"

        print("Filename for message: " + str(dataFileName))
        file = open(os.path.join(directoryPath, dataFileName), "rb")
        print("File opened correctly")
        message_byte_array = file.read()
        #print("File contents: " + str(result))'
        print("File contents read")
        file.close()
    
        # Run tests
        self.RunLibraryCiphers(password_filename, message_byte_array)

        
        # ERROR TESTING
        print("Cryptography module produced DES3 times of: " + str(self.cryptographyTimeResults))
        print()
        print("PyCrypto module produced DES3 times of: " + str(self.PyCryptoTimeResults))
        print()

    def SplitMessage(self, message_byte_array, block_length):
        '''Expects block length to be in bytes.'''
        resultArray = []
        index = 0
        while index < len(message_byte_array):
            resultArray.append(message_byte_array[index : index + block_length])
            index += block_length

        # ERROR TESTING
        print("Split message result: " + str(len(resultArray)))
        
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

        padByte = message_byte_array[len(message_byte_array) - 1]
        if padByte < len(message_byte_array) and \
            padByte != 0 and \
            padByte == message_byte_array[len(message_byte_array) - padByte]:
            return message_byte_array[:len(message_byte_array) - padByte]
        else:
            return message_byte_array

    def RunCryptographyAndUnpadSplitMessage(self, split_message, cipher, block_length):
        '''A small snippet of code to centralize the work of encrypting and then
           decrypting a message that has been spliced since the cryptography
           library cannot handle data over a certain size (it causes Python to
           crash). Not to be used for ARC4 stream cipher since it doesn't have
           any padding applied.

           Variables:
           --split_message: The message split up into chunks.
           --cipher: The cryptography cipher used (not its encryptor or decryptor)
           --block_length: Block length of cipher input. Used to remove padding
           from decrypted message.

           Returns the decrypted, unpadded message conjoined into one bytearray.'''
        unpaddedMessage = bytearray()
        encryptor = cipher.encryptor()
        decryptor = cipher.decryptor()
        
        for segment in split_message:
            unpaddedSegment = self.RemovePadding(decryptor.update(encryptor.update(segment)), block_length)
            unpaddedMessage.extend(unpaddedSegment)

        return unpaddedMessage

    def RunLibraryCiphers(self, password_filename, message_byte_array):
        '''Runs all designated encryption ciphers. Utilizes the same encryption
           key for symmetric key ciphers and the same pair of keys for asymmetric
           key ciphers.'''
        # ERROR TESTING
        print("checkpoint 1")

        # Derive a 30-byte salt for use with key derivation
        salt = os.urandom(30)

        # ERROR TESTING
        print("checkpoint 2")
        

        # Take a key from a text file
        password = BinaryFileHandler.ReadByteDataFile(password_filename)

        # Run tests regarding the symmetric ciphers, which includes the block
        # ciphers and the stream ciphers
        self.RunBlockCiphers(message_byte_array, 2, password, salt)
        self.RunStreamCiphers(message_byte_array, 4, password, salt)

        # Run tests regarding the asymmetric ciphers. The asymmetric ciphers
        # keys separate from the symmetric key generated above, so that will be
        # handled in RunPublicKeyEncrypt.
        #RunPublicKeyEncrypt(3)

        # Run tests regarding the hashing capabilities of the used libraries.
        #RunHashing(30)

        # cryptography backend for use with initializing an asymmetric key
        #backend = cryptography.hazmat.backends.interfaces.RSABackend
        
    
    def RunBlockCiphers(self, message_byte_array, n_runs, password, salt):
        '''Runs the two block ciphers several times between all three libraries
           in order to assess their performance capabilities.

           Returns nothing.'''
        self.cryptographyTimeResults[self.blockCipher1] = TimeResults(self.blockCipher1, "cryptography")
        # ERROR TESTNIG
        #print(str(self.cryptographyTimeResults[self.blockCipher1]))
        print("checkpoint 3")
        
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
        self.RunBlockCipher1(message_byte_array, n_runs, tripleDESKey)
        # ERROR TESTING self.RunBlockCipher2()
        self.RunBlockCipher2(message_byte_array, n_runs, tripleDESKey)


    def RunBlockCipher1(self, message_byte_array, n_runs, key):
        '''Implemented as using Triple DES (Data Encryption Standard) symmetric
           block cipher using 192 bits (24 bytes).

           Runs the first block cipher to assess performance.

           Returns nothing.'''

        # ERROR TESTING
        print("checkpoint 4")

        for i in range(n_runs):
            #####
            # Run cryptography library implementation

            startTime = time.time()

            blockLength = 8
            IV = os.urandom(blockLength)

            # ERROR TESTING
            print("checkpoint run1")
            
            tripleDES = Cipher(algorithms.TripleDES(key), modes.CBC(IV), default_backend())
            tripleDESencryptor = tripleDES.encryptor()
            tripleDESdecryptor = tripleDES.decryptor()
            
            # ERROR TESTING
            # Since there doesn't appear to be a built-in padding scheme, I use
            # my own simple one here to conform to cryptography's padding
            # requirement.
            paddedMessage = self.AddPadding(message_byte_array, blockLength)
            # ERROR TESTING
            #print("Padded message is " + str(paddedMessage) + " len(" + str(len(paddedMessage)) + ")")
            
            # ERROR TESTING
            print("checkpoint run2")

            # ERROR TESTING
            # Do you NEED to split it up?
            # Yes. Yes you do.
            splitMessage = self.SplitMessage(paddedMessage, 500 * blockLength)

            # ERROR TESTING
            print("len of split message is " + str(len(splitMessage)))

            # ERROR TESTING
            #unpaddedMessage = self.RemovePadding(tripleDESdecryptor.update(tripleDESencryptor.update(paddedMessage)), blockLength)

            unpaddedMessage = bytearray()
            for segment in splitMessage:
                unpaddedSegment = self.RemovePadding(tripleDESdecryptor.update(tripleDESencryptor.update(segment)), blockLength)
                # ERROR TESTING
                if unpaddedSegment is None:
                    print("Unpadded segment has len " + str(len(splitMessage[len(splitMessage)-1])))
                unpaddedMessage.extend(unpaddedSegment)

            # ERROR TESTING
            # ERROR TESTING!!!!
            ###################################
            # Output file isn't correct. It's missing about 2K bytes (5506 segments)
            BinaryFileHandler.WriteByteDataFile("TestOutput.jpg", unpaddedMessage)
            
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
            
            
            endTime = time.time()

            # ERROR TESTING
            print("checkpoint run3")

            # ERROR TESTING
            print("start time: " + str(startTime))
            print("end time: " + str(endTime))

            self.cryptographyTimeResults[self.blockCipher1].append(endTime - startTime)

            #####
            # Run PyCrypto library implementation
            startTime = time.time()
            blockLength = 8
            IV = os.urandom(blockLength)
            tripleDES = Crypto.Cipher.DES3.new(key, mode=Crypto.Cipher.blockalgo.MODE_CBC, IV=IV)            
            paddedMessage = self.AddPadding(message_byte_array, blockLength)
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

            # ERROR TESTING
            # ERROR TESTING!!!!
            ###################################
            # Output file isn't correct. It's missing about 2K bytes (5506 segments)
            # ERROR TESTING
            # It IS correct for this one. Why?
            BinaryFileHandler.WriteByteDataFile("TestOutput.jpg", unpaddedMessage)
            
            endTime = time.time()
            self.PyCryptoTimeResults[self.blockCipher1].append(endTime - startTime)

    def RunBlockCipher2(self, message_byte_array, n_runs, key):
        '''Implemented as using Blowfish symmetric block cipher.

           Runs the second block cipher to assess performance.

           Returns nothing.'''
        for i in range(n_runs):
            ###########
            # Run cryptography library implementation

            startTime = time.time()

            blockLength = 8
            IV = os.urandom(blockLength)

            blowfish = Cipher(algorithms.Blowfish(key), modes.CBC(IV), default_backend())
            blowfishEncryptor = blowfish.encryptor()
            blowfishDecryptor = blowfish.decryptor()

            paddedMessage = self.AddPadding(message_byte_array, blockLength)

            splitMessage = self.SplitMessage(paddedMessage, 500 * blockLength)

            unpaddedMessage = bytearray()
            for segment in splitMessage:
                unpaddedSegment = self.RemovePadding(blowfishDecryptor.update(blowfishEncryptor.update(segment)), blockLength)
                unpaddedMessage.extend(unpaddedSegment)
           
            # ERROR TESTING
            # ERROR TESTING!!!!
            ###################################
            # Output file isn't correct. It's missing about 2K bytes (5506 segments)
            # ERROR TESTING
            # It IS correct for this one. Why?
            BinaryFileHandler.WriteByteDataFile("TestOutput.jpg", unpaddedMessage)

            endTime = time.time()
            self.cryptographyTimeResults[self.blockCipher2].append(endTime - startTime)

            ##############
            # Run PyCrypto library implementation
            startTime = time.time()

            blockLength = 8
            IV = os.urandom(blockLength)
            blowfish = Crypto.Cipher.Blowfish.new(key, mode=Crypto.Cipher.blockalgo.MODE_CBC, IV=IV)
            self.AddPadding(message_byte_array, blockLength)
            extendedMessage = bytearray(IV)
            extendedMessage.extend(paddedMessage)

            encryptedMessage = blowfish.encrypt(bytes(extendedMessage))
            decryptedMessage = blowfish.decrypt(encryptedMessage)
            unpaddedMessage = self.RemovePadding(decryptedMessage[blockLength:], blockLength)

            # ERROR TESTING
            # Output image file. Customize to make a different name?
            BinaryFileHandler.WriteByteDataFile("TestOutput.jpg", unpaddedMessage)

            endTime = time.time()
            self.PyCryptoTimeResults[self.blockCipher2].append(endTime - startTime)

            ###########

    def RunStreamCiphers(self, message_byte_array, n_runs, password, salt):
        '''Runs the two stream ciphers several times between all three libraries
           in order to assess their performance capabilities.

           Returns nothing.'''
        self.cryptographyTimeResults[self.streamCipher1] = TimeResults(self.streamCipher1, "cryptography")
        self.cryptographyTimeResults[self.streamCipher2] = TimeResults(self.streamCipher2, "cryptography")
        self.PyCryptoTimeResults[self.streamCipher1] = TimeResults(self.streamCipher1, "PyCrypto")
        self.PyCryptoTimeResults[self.streamCipher2] = TimeResults(self.streamCipher2, "PyCrypto")

        # Create 192 bit key for use in stream cipher
        streamCipherKeyDeriver = cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length = 24, # 192 bits
            salt = salt,
            iterations = 2000,
            backend = default_backend()
            )
        streamCipherKey = streamCipherKeyDeriver.derive(password)

        # Run algorithms
        self.RunStreamCipher1(message_byte_array, n_runs, streamCipherKey)
        self.RunStreamCipher2(message_byte_array, n_runs, streamCipherKey)

    def RunStreamCipher1(self, message_byte_array, n_runs, key):
        '''Implemented as using ARC4 symmetric block cipher using 192 bits (24
           bytes).

           Runs the first stream cipher to assess performance.

           Returns nothing.'''

        for i in range(n_runs):
            ########
            # Run cryptography library implementation
            startTime = time.time()

            arc4 = Cipher(algorithms.ARC4(key), None, default_backend())
            arc4Encryptor = arc4.encryptor()
            arc4Decryptor = arc4.decryptor()

            # ERROR TESTING not required? paddedMessage = self.AddPadding(message_byte_array, blockLength)

            splitMessage = self.SplitMessage(message_byte_array, 8000)
            unpaddedMessage = bytearray()
            for segment in splitMessage:
                unpaddedSegment = arc4Decryptor.update(arc4Encryptor.update(segment))
                unpaddedMessage.extend(unpaddedSegment)

            # ERROR TESTING
            # Accurate output? Change output file name.
            BinaryFileHandler.WriteByteDataFile("TestOutput.jpg", unpaddedMessage)

            endTime = time.time()
            self.cryptographyTimeResults[self.streamCipher1].append(endTime - startTime)

            ###########
            # Run PyCrypto library implementation
            startTime = time.time()
            arc4 = Crypto.Cipher.ARC4.new(key)
            encryptedMessage = arc4.encrypt(message_byte_array)
            decryptedMessage = arc4.decrypt(encryptedMessage)

            # ERROR TESTING Rename output file. ALSO: Should this be after endtime?
            BinaryFileHandler.WriteByteDataFile("TestOutput.jpg", decryptedMessage)

            endTime = time.time()
            self.PyCryptoTimeResults[self.streamCipher1].append(endTime - startTime)

            ##########

    def RunStreamCipher2(self, message_byte_array, n_runs, key):
        '''Implemented as using AES (Advanced Encryption Standard) symmetric
           cipher in CTR (Counter) mode which allows it to run as a stream
           cipher. The key is 192 bits (24 bytes).

           Runs the second stream cipher to assess performance.

           Returns nothing.'''

        for i in range(n_runs):
            ########
            # Run cryptography library implementation
            startTime = time.time()

            blockLength = 16
            IV = os.urandom(blockLength)

            aes = Cipher(algorithms.AES(key), modes.CTR(IV), default_backend())

            paddedMessage = self.AddPadding(message_byte_array, blockLength)
            splitMessage = self.SplitMessage(paddedMessage, 500 * blockLength)

            # ERROR TESTING RunCryptographyAndUnpadSplitMessage(self, split_message, cipher, block_length):
            unpaddedMessage = self.RunCryptographyAndUnpadSplitMessage(splitMessage, aes, blockLength)

            # ERROR TESTING rename output file and move outside of timing testing?
            BinaryFileHandler.WriteByteDataFile("TestOutput.jpg", unpaddedMessage)

            endTime = time.time()
            self.cryptographyTimeResults[self.streamCipher2].append(endTime - startTime)

            ##########
            # Run PyCrypto library implementation
            startTime = time.time()
            blockLength = 16
            IV = os.urandom(blockLength)

            # AES in CTR mode for the PyCrypto library requires a counter instead
            # of an initialization vector
            aes = Crypto.Cipher.AES.new(key, mode=Crypto.Cipher.blockalgo.MODE_CTR, counter=Crypto.Util.Counter.new(128))

            paddedMessage = self.AddPadding(message_byte_array, blockLength)
            encryptedMessage = aes.encrypt(bytes(paddedMessage))
            decryptedMessage = aes.decrypt(encryptedMessage)
            unpaddedMessage = self.RemovePadding(decryptedMessage[blockLength:], blockLength)

            # ERROR TESTING rename output file
            BinaryFileHandler.WriteByteDataFile("TestOutput.jpg", unpaddedMessage)

            endTime = time.time()
            self.PyCryptoTimeResults[self.streamCipher2].append(endTime - startTime)

            ###########
            


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
    #messageFilename = "TestMessage.txt"
    messageFilename = "TestImage.jpg"
    finalClass = FinalMain(passwordFilename, messageFilename)
