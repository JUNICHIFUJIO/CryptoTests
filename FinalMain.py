# Author: Thomas Brown
# CSS 527 Final Project
# This project was designed to test the performance capabilities of three
# cryptographic libraries. The libraries used are cryptography, PyCrypto, and
# chilkat. The program's usage, if called as the top-level executable is:
#       ./python3.4 FinalMain.py testInputFile
# The program will print output to the given output file and use the password
# from the given password file.
#
# IMPORTANT: For the input file, the file MUST RESIDE IN THE SAME DIRECTORY AS
# THIS SCRIPT.
#
# Chosen algorithms:
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

# Section for allowing import of custom classes
import sys
import os

if sys.path[0] != os.path.dirname(os.path.realpath(sys.argv[0])):
    sys.path.insert(0, os.path.dirname(os.path.realpath(sys.argv[0])))

# import the necessary libraries
import hashlib
import cryptography
import Crypto
import time

# Key derivation function imports
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import cryptography.hazmat.primitives # for hashes
import cryptography.hazmat.primitives.asymmetric

# PyCrypto library
import Crypto
import Crypto.Cipher.DES3
import Crypto.Cipher.Blowfish
import Crypto.Cipher.ARC4
import Crypto.Cipher.AES
#import Crypto.Cipher.PKCS1_OAEP # ERROR TESTING RSA implementation?
import Crypto.Util.Counter # For use with PyCrypto's AES implementation of a CTR mode stream cipher (acts just like an initialization vector)
import Crypto.Cipher.blockalgo # To get modes of operation for ciphers
import Crypto.PublicKey.RSA # For RSA module material
import Crypto.PublicKey.DSA # For DSA module material
import Crypto.Random.random # For random (Used in DSA)
import Crypto.Hash.SHA # For SHA (Used in DSA)
import Crypto.Hash.MD5 # For MD5

# Chilkat library (Symmetric ciphers)
import chilkat

# import necessary custom files
# import MyBitArray # ERROR TESTING REMOVE?
import BinaryFileHandler
from TimeResults import TimeResults

class FinalMain:
    def __init__(self, message_filename, output_filename, password_filename):
        # Establish string representations of ciphers used
        self.blockCipher1 = "Triple DES"
        self.blockCipher2 = "Blowfish"
        self.streamCipher1 = "ARC4"
        self.streamCipher2 = "AES (CTR mode)"
        self.PKE1 = "RSA"
        self.PKE2 = "DSA"
        self.hash1 = "SHA256"
        self.hash2 = "MD5"

        # Centralize chilkat trial error message
        self.chilkatError = "The chilkat library offers a free 30 day trial for its services. If outside of this trial, chilkat functions will essentially return None constantly. Unfortunately, that seems to be the case now."
        
        # Create empty dictionaries to store the time results of used libraries
        self.cryptographyTimeResults = {}
        self.PyCryptoTimeResults = {}
        self.chilkatTimeResults = {}

        # Unwrap message into byte array
        directoryPath = BinaryFileHandler.GetScriptDirectory()
        dataFileName = BinaryFileHandler.GetFileNameWithExtension(message_filename)
        if len(dataFileName.split(".")) < 2:
            dataFileName += ".txt"
        print("Filename for message: " + str(dataFileName))
        file = open(os.path.join(directoryPath, dataFileName), "rb")
        print("File opened correctly")
        message_byte_array = file.read()
        print("File contents read")
        file.close()

        # Create output file/clear output file
        BinaryFileHandler.WriteByteDataFile(output_filename, b"")
    
        # Run tests
        self.RunLibraryCiphers(password_filename, message_byte_array, dataFileName)

        # Append time result data to output file
        for timeResult in self.cryptographyTimeResults.values():
            timeResult.AppendToFile(output_filename, 2)
            timeResult.AppendAverageToFile(output_filename, 1)
        for timeResult in self.PyCryptoTimeResults.values():
            timeResult.AppendToFile(output_filename, 2)
            timeResult.AppendAverageToFile(output_filename, 1)
        for timeResult in self.chilkatTimeResults.values():
            timeResult.AppendToFile(output_filename, 2)
            timeResult.AppendAverageToFile(output_filename, 1)

    def SplitMessage(self, message_byte_array, block_length):
        '''Splits a passed byte array into a a fresh array of int arrays.
           Expects block length to represent the number of bytes desired for
           each resulting chunk.

           Returns array of int arrays representing the split up byte array.'''
        resultArray = []
        index = 0
        while index < len(message_byte_array):
            resultArray.append(message_byte_array[index : index + block_length])
            index += block_length

        return resultArray

    def AddPadding(self, message_byte_array, block_length):
        '''Adds simple padding for messages to make a message the correct length.
           Fills remaining byte spaces with a byte representing the number of
           empty byte spaces.

           Returns fresh array of padded message bytes.'''

        temp = []
        if len(message_byte_array) % block_length != 0:
            padByte = block_length - (len(message_byte_array) % block_length)
            temp.extend([padByte] * padByte)

        result = []
        result.extend(message_byte_array)
        result.extend(temp)

        return result
        

    def RemovePadding(self, message_byte_array, block_length):
        '''Removes simple padding for messages to make a message the correct
           length. Removes all trailing pad bytes.

           Returns fresh array of unpadded message bytes or original message if
           no padding exists.'''
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

    def DisplayCipherStart(self, library_string, algorithm_string, iteration_number):
        '''Centralized print code displaying which algorithm for which library is
           beginning.'''
        print("Beginning " + str(library_string) + " " + str(algorithm_string) + " run " + str(iteration_number+1) + ".")

    def DisplayCipherEnd(self, library_string, algorithm_string, iteration_number):
        '''Centralized print code displaying which algorithm for which library is
           ending.'''
        print(str(library_string) + " " + str(algorithm_string) + " run " + str(iteration_number+1) + " completed.")

    def RunChilkatSymmetricCiphers(self, message_filename, n_runs):
        '''Runs the chilkat library's symmetric ciphers. Separated from other
           code because chilkat reads data from files only.'''
        self.chilkatTimeResults[self.blockCipher1] = TimeResults(self.blockCipher1, "chilkat")
        self.chilkatTimeResults[self.blockCipher2] = TimeResults(self.blockCipher2, "chilkat")
        self.chilkatTimeResults[self.streamCipher1] = TimeResults(self.streamCipher1, "chilkat")
        self.chilkatTimeResults[self.streamCipher2] = TimeResults(self.streamCipher2, "chilkat")

        for i in range(n_runs):
            self.DisplayCipherStart("chilkat", "symmetric encryptions", i)
            self.RunChilkatSymmCipher(self.blockCipher1, "3des", "cbc", 192, message_filename)
            self.RunChilkatSymmCipher(self.blockCipher2, "blowfish2", "cbc", 192, message_filename)
            self.RunChilkatSymmCipher(self.streamCipher1, "arc4", "cbc", 128, message_filename)
            self.RunChilkatSymmCipher(self.streamCipher2, "aes", "ctr", 192, message_filename)
            self.DisplayCipherEnd("chilkat", "symmetric encryptions", i)

    def RunChilkatSymmCipher(self, crypt_algorithm_string, ck_crypt_algorithm, cipher_mode, key_length, message_filename):
        '''Runs a chilkat library symmetric cipher using the given parameters.'''
        # Run chilkat library implementation of block cipher 1 (triple DES)
        startTime = time.time()

        crypt = chilkat.CkCrypt2()

        success = crypt.UnlockComponent("30 day trial.")
        if success != True:
            print(self.chilkatError)
            
        crypt.put_CryptAlgorithm(ck_crypt_algorithm)
        crypt.put_CipherMode(cipher_mode)
        crypt.put_KeyLength(key_length)
        crypt.put_PaddingScheme(0)
        crypt.RandomizeIV()
        crypt.RandomizeKey()
        inputBytes = chilkat.CkByteData()
        inputBytes.loadFile(message_filename)
        encryptedMessage = chilkat.CkByteData()
        crypt.EncryptBytes(inputBytes, encryptedMessage)
        decryptedMessage = chilkat.CkByteData()
        crypt.DecryptBytes(encryptedMessage, decryptedMessage)

        endTime = time.time()
        # If output of the algorithm is desired, uncomment the line below
        #decryptedMessage.saveFile("chilkatoutput" + crypt_algorithm_string + "." + message_filename.split('.')[1])
        self.chilkatTimeResults[crypt_algorithm_string].append(endTime - startTime)

    def RunChilkatAsymmCiphers(self, message_filename, n_runs):
        '''Runs the chilkat library's asymmetric ciphers. Separated from other
           code because chilkat reads data from files only.'''
        self.chilkatTimeResults[self.PKE1] = TimeResults(self.PKE1, "chilkat")
        self.chilkatTimeResults[self.PKE2] = TimeResults(self.PKE2, "chilkat")
        
        for i in range(n_runs):
            # Run chilkat library implementation of RSA.
            self.DisplayCipherStart("chilkat", "RSA", i)
            startTime = time.time()

            rsa = chilkat.CkRsa()

            success = rsa.UnlockComponent("30 day trial.")
            if success != True:
                print(self.chilkatError)

            rsa.GenerateKey(1024)
            inputBytes = chilkat.CkByteData()
            inputBytes.loadFile(message_filename)
            encryptedMessage = chilkat.CkByteData()
            rsa.EncryptBytes(inputBytes, False, encryptedMessage)
            decryptedMessage = chilkat.CkByteData()
            rsa.DecryptBytes(encryptedMessage, True, decryptedMessage)
               
            endTime = time.time()
            # If output of the algorithm is desired, uncomment the line below
            #decryptedMessage.saveFile("chilkatoutputrsa." + message_filename.split('.')[1])
        
            self.chilkatTimeResults[self.PKE1].append(endTime - startTime)
            self.DisplayCipherEnd("chilkat", "RSA", i)
            
            ########
            # Run chilkat library implementation of DSA.
            self.DisplayCipherStart("chilkat", "DSA", i)
            startTime = time.time()

            # Generate a CK hash for the signature
            crypt = chilkat.CkCrypt2()
            success = crypt.UnlockComponent("30 day trial.")
            if success != True:
                print(self.chilkatError)
            crypt.put_EncodingMode("hex")
            crypt.put_HashAlgorithm("md5")
            hashStr = crypt.hashFileENC(message_filename)

            # Begin DSA work        
            dsa = chilkat.CkDsa()

            success = dsa.UnlockComponent("30 day trial.")
            if success != True:
                print(self.chilkatError)
                
            dsa.GenKey(2048)
            # Sign (encrypt)
            dsa.SetEncodedHash("hex", hashStr)
            dsa.SignHash()
            # Verify (decrypt)
            dsa.Verify()

            endTime = time.time()
            self.chilkatTimeResults[self.PKE2].append(endTime - startTime)
            self.DisplayCipherEnd("chilkat", "DSA", i)
            
    def RunChilkatHashAlgorithms(self, message_filename, n_runs):
        '''Runs the chilkat library's hash algorithms. Separated from other
           code because chilkat reads data from files only.'''
        self.chilkatTimeResults[self.hash1] = TimeResults(self.hash1, "chilkat")
        self.chilkatTimeResults[self.hash2] = TimeResults(self.hash2, "chilkat")
        
        algorithms = [self.hash1.lower(), self.hash2.lower()]
        for algorithm in algorithms:
            for i in range(n_runs):
                self.DisplayCipherStart("chilkat", algorithm, i)
                ########
                # Run chilkat library implementation of hash algorithm.
                startTime = time.time()

                # Prep for making a hash
                crypt = chilkat.CkCrypt2()
                success = crypt.UnlockComponent("30 day trial.")
                if success != True:
                    print(self.chilkatError)
                crypt.put_EncodingMode("hex")
                crypt.put_HashAlgorithm(algorithm)
                hashStr = crypt.hashFileENC(message_filename)

                endTime = time.time()
                self.chilkatTimeResults[algorithm.upper()].append(endTime - startTime)
                # If output of the algorithm is desired, uncomment the line below
                #decryptedMessage.saveFile("chilkatoutput" + algorithm + ".txt")
                self.DisplayCipherEnd("chilkat", "algorithm", i)

    def RunLibraryCiphers(self, password_filename, message_byte_array, message_filename):
        '''Runs all designated encryption ciphers. Utilizes the same encryption
           key for symmetric key ciphers and the same pair of keys for asymmetric
           key ciphers.'''
        # Derive a 30-byte salt for use with key derivation
        salt = os.urandom(30)

        # Take a key from a text file
        password = BinaryFileHandler.ReadByteDataFile(password_filename)

        # Run tests regarding the symmetric ciphers, which includes the block
        # ciphers and the stream ciphers
        nRuns = 7
        self.RunBlockCiphers(message_byte_array, nRuns, password, salt)
        self.RunStreamCiphers(message_byte_array, nRuns, password, salt)
        self.RunChilkatSymmetricCiphers(message_filename, nRuns)

        # Run tests regarding the asymmetric ciphers. The asymmetric ciphers
        # keys separate from the symmetric key generated above, so that will be
        # handled in RunPublicKeyEncrypt.
        nRuns = 3
        self.RunPublicKeyEncrypt(message_byte_array, nRuns)
        self.RunChilkatAsymmCiphers(message_filename, nRuns)

        # Run tests regarding the hashing capabilities of the used libraries.
        nRuns = 10
        self.RunHashes(message_byte_array, nRuns, 1)
        self.RunChilkatHashAlgorithms(message_filename, nRuns)
    
    def RunBlockCiphers(self, message_byte_array, n_runs, password, salt):
        '''Runs the two block ciphers several times between two libraries
           in order to assess their performance capabilities.

           Returns nothing.'''
        self.cryptographyTimeResults[self.blockCipher1] = TimeResults(self.blockCipher1, "cryptography")
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
        self.RunBlockCipher2(message_byte_array, n_runs, tripleDESKey)

    def RunBlockCipher1(self, message_byte_array, n_runs, key):
        '''Implemented as using Triple DES (Data Encryption Standard) symmetric
           block cipher using 192 bits (24 bytes).

           Runs the first block cipher to assess performance.

           Returns nothing.'''
        for i in range(n_runs):
            #####
            # Run cryptography library implementation
            self.DisplayCipherStart("cryptography", "Triple DES", i)

            startTime = time.time()

            blockLength = 8
            IV = os.urandom(blockLength)

            tripleDES = Cipher(algorithms.TripleDES(key), modes.CBC(IV), default_backend())
            tripleDESencryptor = tripleDES.encryptor()
            tripleDESdecryptor = tripleDES.decryptor()
            paddedMessage = self.AddPadding(message_byte_array, blockLength)
            splitMessage = self.SplitMessage(paddedMessage, 500 * blockLength)
            unpaddedMessage = bytearray()
            for segment in splitMessage:
                unpaddedSegment = self.RemovePadding(tripleDESdecryptor.update(tripleDESencryptor.update(segment)), blockLength)
                unpaddedMessage.extend(unpaddedSegment)

            endTime = time.time()

            # If output of the algorithm is desired, uncomment the line below
            #BinaryFileHandler.WriteByteDataFile("cryptographyoutputdes." + message_filename.split('.')[1])
            self.cryptographyTimeResults[self.blockCipher1].append(endTime - startTime)
            self.DisplayCipherEnd("cryptography", "Triple DES", i)
            
            #####
            # Run PyCrypto library implementation
            self.DisplayCipherStart("PyCrypto", "Triple DES", i)
            startTime = time.time()
            blockLength = 8
            IV = os.urandom(blockLength)
            tripleDES = Crypto.Cipher.DES3.new(key, mode=Crypto.Cipher.blockalgo.MODE_CBC, IV=IV)            
            paddedMessage = self.AddPadding(message_byte_array, blockLength)
            extendedMessage = bytearray(IV)
            extendedMessage.extend(paddedMessage)
            encryptedMessage = tripleDES.encrypt(bytes(extendedMessage))
            decryptedMessage = tripleDES.decrypt(encryptedMessage)
            unpaddedMessage = self.RemovePadding(decryptedMessage[blockLength:], blockLength)
            endTime = time.time()
            
            # If output of the algorithm is desired, uncomment the line below
            #BinaryFileHandler.WriteByteDataFile("PyCryptooutputdes." + message_filename.split('.')[1])
            self.PyCryptoTimeResults[self.blockCipher1].append(endTime - startTime)
            self.DisplayCipherEnd("PyCrypto", "Triple DES", i)

    def RunBlockCipher2(self, message_byte_array, n_runs, key):
        '''Implemented as using Blowfish symmetric block cipher.

           Runs the second block cipher to assess performance.

           Returns nothing.'''
        for i in range(n_runs):
            ###########
            # Run cryptography library implementation
            self.DisplayCipherStart("cryptography", "Blowfish", i)

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
            endTime = time.time()
            
            # If output of the algorithm is desired, uncomment the line below
            #BinaryFileHandler.WriteByteDataFile("cryptographyoutputblowfish." + message_filename.split('.')[1])
            self.cryptographyTimeResults[self.blockCipher2].append(endTime - startTime)
            self.DisplayCipherEnd("cryptography", "Blowfish", i)

            ##############
            # Run PyCrypto library implementation
            self.DisplayCipherStart("PyCrypto", "Blowfish", i)
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

            endTime = time.time()
            
            # If output of the algorithm is desired, uncomment the line below
            #BinaryFileHandler.WriteByteDataFile("PyCryptooutputblowfish." + message_filename.split('.')[1])
            self.PyCryptoTimeResults[self.blockCipher2].append(endTime - startTime)
            self.DisplayCipherEnd("PyCrypto", "Blowfish", i)            

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
            self.DisplayCipherStart("cryptography", "ARC4", i)
            startTime = time.time()

            arc4 = Cipher(algorithms.ARC4(key), None, default_backend())
            arc4Encryptor = arc4.encryptor()
            arc4Decryptor = arc4.decryptor()

            splitMessage = self.SplitMessage(message_byte_array, 8000)
            unpaddedMessage = bytearray()
            for segment in splitMessage:
                unpaddedSegment = arc4Decryptor.update(arc4Encryptor.update(segment))
                unpaddedMessage.extend(unpaddedSegment)

            endTime = time.time()
            
            # If output of the algorithm is desired, uncomment the line below
            #BinaryFileHandler.WriteByteDataFile("cryptographyoutputarc4." + message_filename.split('.')[1])
            self.cryptographyTimeResults[self.streamCipher1].append(endTime - startTime)
            self.DisplayCipherEnd("cryptography", "ARC4", i)
            
            ###########
            # Run PyCrypto library implementation
            self.DisplayCipherStart("PyCrypto", "ARC4", i)
            startTime = time.time()
            arc4 = Crypto.Cipher.ARC4.new(key)
            encryptedMessage = arc4.encrypt(message_byte_array)
            decryptedMessage = arc4.decrypt(encryptedMessage)

            endTime = time.time()
            
            # If output of the algorithm is desired, uncomment the line below
            #BinaryFileHandler.WriteByteDataFile("PyCryptooutputarc4." + message_filename.split('.')[1])
            self.PyCryptoTimeResults[self.streamCipher1].append(endTime - startTime)
            self.DisplayCipherEnd("PyCrypto", "ARC4", i)

    def RunStreamCipher2(self, message_byte_array, n_runs, key):
        '''Implemented as using AES (Advanced Encryption Standard) symmetric
           cipher in CTR (Counter) mode which allows it to run as a stream
           cipher. The key is 192 bits (24 bytes).

           Runs the second stream cipher to assess performance.

           Returns nothing.'''

        for i in range(n_runs):
            ########
            # Run cryptography library implementation
            self.DisplayCipherStart("cryptography", "AES (CTR)", i)
            startTime = time.time()

            blockLength = 16
            IV = os.urandom(blockLength)

            aes = Cipher(algorithms.AES(key), modes.CTR(IV), default_backend())

            paddedMessage = self.AddPadding(message_byte_array, blockLength)
            splitMessage = self.SplitMessage(paddedMessage, 500 * blockLength)
            unpaddedMessage = self.RunCryptographyAndUnpadSplitMessage(splitMessage, aes, blockLength)

            endTime = time.time()
            
            # If output of the algorithm is desired, uncomment the line below
            #BinaryFileHandler.WriteByteDataFile("cryptographyoutputaes." + message_filename.split('.')[1])
            self.cryptographyTimeResults[self.streamCipher2].append(endTime - startTime)
            self.DisplayCipherEnd("cryptography", "AES (CTR)", i)

            ##########
            # Run PyCrypto library implementation
            self.DisplayCipherStart("PyCrypto", "AES (CTR)", i)
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

            endTime = time.time()
            
            # If output of the algorithm is desired, uncomment the line below
            #BinaryFileHandler.WriteByteDataFile("PyCryptooutputaes." + message_filename.split('.')[1])
            self.PyCryptoTimeResults[self.streamCipher2].append(endTime - startTime)
            self.DisplayCipherEnd("PyCrypto", "AES (CTR)", i)
            
    def RunPublicKeyEncrypt(self, message_byte_array, n_runs):
        '''Runs the two public key/asymmetric key encryption ciphers between
           all three libraries in order to assess their performance capabilities.

           Returns nothing.'''
        # Set up time result slots
        self.cryptographyTimeResults[self.PKE1] = TimeResults(self.PKE1, "cryptography")
        self.cryptographyTimeResults[self.PKE2] = TimeResults(self.PKE2, "cryptography")
        self.PyCryptoTimeResults[self.PKE1] = TimeResults(self.PKE1, "PyCrypto")
        self.PyCryptoTimeResults[self.PKE2] = TimeResults(self.PKE2, "PyCrypto")
        
        # Run algorithms
        self.RunPKE1(message_byte_array, n_runs)
        self.RunPKE2(message_byte_array, n_runs)

    def RunPKE1(self, message_byte_array, n_runs):
        '''Implemented as using RSA asymmetric key encryption.

           Runs the first public key encryption/decryption algorithm to assess
           performance.

           Returns nothing.'''

        for i in range(n_runs):
            ######
            # Run cryptography library implementation
            self.DisplayCipherStart("cryptography", "RSA", i)
            startTime = time.time()
            # Generate keys
            privateKey = cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(65537, 2048, default_backend())
            publicKey = privateKey.public_key()
            # Split message into segments for management
            blockLength = int(1500/8)
            splitMessage = self.SplitMessage(message_byte_array, blockLength)
            decryptedMessage = bytearray()
            for segment in splitMessage:
                # Encrypt message with public key
                encryptedMessage = publicKey.encrypt(segment,
                                                     cryptography.hazmat.primitives.asymmetric.padding.OAEP(
                                                         cryptography.hazmat.primitives.asymmetric.padding.MGF1(algorithm = hashes.SHA1()),
                                                         algorithm = hashes.SHA1(),
                                                         label = None
                                                         )
                                                     )
                # Decrypt message with private key
                plaintext = privateKey.decrypt(encryptedMessage,
                                                      cryptography.hazmat.primitives.asymmetric.padding.OAEP(
                                                          mgf = cryptography.hazmat.primitives.asymmetric.padding.MGF1(algorithm = hashes.SHA1()),
                                                          algorithm = hashes.SHA1(),
                                                          label = None
                                                          )
                                                      )

                decryptedMessage.extend(plaintext)
            
            endTime = time.time()
            
            # If output of the algorithm is desired, uncomment the line below
            #BinaryFileHandler.WriteByteDataFile("cryptographyoutputrsa." + message_filename.split('.')[1])
            self.cryptographyTimeResults[self.PKE1].append(endTime - startTime)
            self.DisplayCipherEnd("cryptography", "RSA", i)

            ###########
            # Run PyCrypto library implementation
            self.DisplayCipherStart("PyCrypto", "RSA", i)
            startTime = time.time()
            
            key = Crypto.PublicKey.RSA.generate(2048)

            splitMessage = self.SplitMessage(message_byte_array, blockLength)
            decryptedMessage = bytearray()
            for segment in splitMessage:
                encryptedSegment = key.encrypt(segment, b"Random byte string")
                decryptedSegment = key.decrypt(encryptedSegment)
                decryptedMessage.extend(decryptedSegment)

            endTime = time.time()
            
            # If output of the algorithm is desired, uncomment the line below
            #BinaryFileHandler.WriteByteDataFile("PyCryptooutputrsa." + message_filename.split('.')[1])
            self.PyCryptoTimeResults[self.PKE1].append(endTime - startTime)
            self.DisplayCipherEnd("PyCrypto", "RSA", i)

    def RunPKE2(self, message_byte_array, n_runs):
        '''Implemented as using DSA (Digital Signature Algorithm).

           Runs the second public key encryption/decryption algorithm to assess
           performance.

           Returns nothing.'''

        for i in range(n_runs):
            #########
            # Run cryptography library implementation
            self.DisplayCipherStart("cryptography", "DSA", i)
            startTime = time.time()

            # Generate the private and public keys
            privateKey = cryptography.hazmat.primitives.asymmetric.dsa.generate_private_key(
                key_size = 1024,
                backend = default_backend()
                )
            publicKey = privateKey.public_key()

            # Sign and verify the file
            signer = privateKey.signer(cryptography.hazmat.primitives.hashes.SHA256())
            signer.update(message_byte_array)
            signature = signer.finalize()
            verifier = publicKey.verifier(signature, cryptography.hazmat.primitives.hashes.SHA256())
            verifier.update(message_byte_array)
            verifier.verify()

            endTime = time.time()
            # If output of the algorithm is desired, uncomment the line below
            #BinaryFileHandler.WriteByteDataFile("cryptographyoutputdsa." + message_filename.split('.')[1])
            self.cryptographyTimeResults[self.PKE2].append(endTime - startTime)
            self.DisplayCipherEnd("cryptography", "DSA", i)

            ###########
            # Run PyCrypto library implementation
            self.DisplayCipherStart("PyCrypto", "DSA", i)
            startTime = time.time()
            # Generate DSA key pair (can generate public key from this object)
            key = Crypto.PublicKey.DSA.generate(1024)
            # Generate the signature of the data
            DSAHash = Crypto.Hash.SHA.new(message_byte_array).digest()
            k = Crypto.Random.random.StrongRandom().randint(1,key.q-1)
            signature = key.sign(DSAHash, k)
            # Verify (pseudo-decrypt) signature
            isValid = key.verify(DSAHash, signature)

            endTime = time.time()
            # If output of the algorithm is desired, uncomment the line below
            #BinaryFileHandler.WriteByteDataFile("PyCryptooutputdsa." + message_filename.split('.')[1])
            self.PyCryptoTimeResults[self.PKE2].append(endTime - startTime)
            self.DisplayCipherStart("PyCrypto", "DSA", i)

    def RunHashes(self, message_byte_array, n_runs, n_hashes):
        '''Runs the two hashing algorithms several times between all three
           libraries in order to assess their performance capabilities.
           Hashing algorithms are very fast and difficult to measure for
           performance, so each time measurement is for n_hashes hashes.

           Returns nothing.'''
        self.cryptographyTimeResults[self.hash1] = TimeResults(self.hash1, "hashlib")
        self.cryptographyTimeResults[self.hash2] = TimeResults(self.hash2, "hashlib")
        self.PyCryptoTimeResults[self.hash1] = TimeResults(self.hash1, "PyCrypto")
        self.PyCryptoTimeResults[self.hash2] = TimeResults(self.hash2, "PyCrypto")

        # Run hashing algorithms
        self.RunHash1(message_byte_array, n_runs, n_hashes)
        self.RunHash2(message_byte_array, n_runs, n_hashes)

    def RunHash1(self, message_byte_array, n_runs, n_hashes):
        '''Implemented as using SHA-256 hashing algorithm.

           Runs the first hashing algorithm to assess performance.

           Returns nothing.'''
        for i in range(n_runs):
            #####
            # Run native library implementation (hashlib)
            startTime = time.time()

            for x in range(n_hashes):
                hashlib.sha256(message_byte_array).digest()

            endTime = time.time()
            # If output of the algorithm is desired, uncomment the line below
            #BinaryFileHandler.WriteByteDataFile("hashliboutputsha256.txt")
            self.cryptographyTimeResults[self.hash1].append((endTime - startTime)/n_hashes)
            #####
            # Run PyCrypto library implementation
            startTime = time.time()

            for x in range(n_hashes):
                h = Crypto.Hash.SHA256.new()
                h.update(message_byte_array)

            endTime = time.time()
            
            # If output of the algorithm is desired, uncomment the line below
            #BinaryFileHandler.WriteByteDataFile("PyCryptooutputsha256.txt")
            self.PyCryptoTimeResults[self.hash1].append((endTime - startTime)/n_hashes)        

    def RunHash2(self, message_byte_array, n_runs, n_hashes):
        '''Implemented as using MD5 hashing algorithm.

           Runs the second hashing algorithm to assess performance.

           Returns nothing.'''
        for i in range(n_runs):
            #####
            # Run native library implementation (hashlib)
            startTime = time.time()

            for x in range(n_hashes):
                hashlib.md5(message_byte_array).digest()

            endTime = time.time()
            # If output of the algorithm is desired, uncomment the line below
            #BinaryFileHandler.WriteByteDataFile("hashliboutputmd5.txt")
            self.cryptographyTimeResults[self.hash2].append((endTime - startTime)/n_hashes)

            #####
            # Run PyCrypto library implementation
            startTime = time.time()

            for x in range(n_hashes):
                h = Crypto.Hash.MD5.new()
                h.update(message_byte_array)

            endTime = time.time()
            # If output of the algorithm is desired, uncomment the line below
            #BinaryFileHandler.WriteByteDataFile("PyCryptooutputmd5.txt")
            self.PyCryptoTimeResults[self.hash2].append((endTime - startTime)/n_hashes)

if __name__ == "__main__":
    print("Running main for FinalMain.")
    print("Module found in " + str(os.path.dirname(os.path.realpath(sys.argv[0]))))
    print()

    if len(sys.argv) != 4:
        raise ValueError("Usage: ./python3.4 FinalMain.py testInputFile testOutputFile passwordFile")

    messageFilename = sys.argv[1]
    outputFilename = sys.argv[2]
    passwordFilename = sys.argv[3]
    finalClass = FinalMain(messageFilename, outputFilename, passwordFilename)
