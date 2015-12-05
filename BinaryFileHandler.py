# Section for allowing import of custom classes
import sys
import os

if sys.path[0] != os.path.dirname(os.path.realpath(sys.argv[0])):
    sys.path.insert(0, os.path.dirname(os.path.realpath(sys.argv[0])))

######################################
#            METHODS START
######################################
# Easier to read way to access the top level executable's script path.
# Useful for locating modules/files.
def GetScriptDirectory():
    return os.path.dirname(os.path.realpath(sys.argv[0]))

# Get the file's name without the extension or directory path.
def GetFileName(path):
    fileNameWithExtension = GetFileNameWithExtension(path)
    fileName = fileNameWithExtension.split(".")[0]

    return fileName

# Get the file's name with the extension but without the directory path.
# Cannot be used to infer a file's extension, only to get the file name with
# the extension from the full path.
def GetFileNameWithExtension(path):
    head, tail = os.path.split(path)
    fileNameWithExtension = tail

    return fileNameWithExtension

# Get the file's extension as a string.
# Cannot be used to infer a file's extension, only to get the extension from the
# full path or file name.
def GetFileExtension(file_name):
    filePathParts = file_name.split(".")
    fileExtension = filePathParts[len(filePathParts) - 1]

    return fileExtension

# Writes a binary file with the given file name, complete with extension.
# Returns the name of the file written.
def WriteByteDataFile(data_file_name, data):
    directoryPath = GetScriptDirectory()
    dataFileName = GetFileNameWithExtension(data_file_name)

    # Append .txt if there's no file extension given
    if len(dataFileName.split(".")) < 2:
        # if there's no extension for the file name...
        dataFileName += ".txt"

    # Open and write to the file
    file = open(os.path.join(directoryPath, dataFileName), "wb")
    file.write(data)
    file.close()

    return dataFileName

def OpenWriteByteDataFile(data_file_name):
    '''Opens a write-only binary file with the given file name, complete with
       extension. Returns the file handler. Expects the user to close the
       file when finished.'''
    directoryPath = GetScriptDirectory()
    dataFileName = GetFileNameWithExtension(data_file_name)

    # Append .txt if tere's no file extension given
    if len(dataFileName.split(".")) < 2:
        # if there's no extension for the file name...
        dataFileName += ".txt"

    # Open and write to the file
    file = open(os.path.join(directoryPath, dataFileName), "wb")

    return file

def OpenAppendByteDataFile(data_file_name):
    '''Opens an append binary file with the given file name, complete with
       extension. Returns the file handler. Expects the user to close the
       file when finished.'''
    directoryPath = GetScriptDirectory()
    dataFileName = GetFileNameWithExtension(data_file_name)

    # Append .txt if there's no file extension given
    if len(dataFileName.split(".")) < 2:
        # if there's no extension for the file name...
        dataFileName += ".txt"

    # Open and write to the file
    file = open(os.path.join(directoryPath, dataFileName), "ab")

    return file

# Read a binary file with the given file name and return an array of bytes.
# Returns the array of bytes held in the file.
def ReadByteDataFile(data_file_name):
    directoryPath = GetScriptDirectory()
    dataFileName = GetFileNameWithExtension(data_file_name)

    # Append .txt if there's no file extension given
    if len(dataFileName.split(".")) < 2:
        # if there's no extension for the file name...
        dataFileName += ".txt"
        
    file = open(os.path.join(directoryPath, dataFileName), "rb")
    result = file.read()
    file.close()

    return result

######################################
#               MAIN
######################################
if __name__ == "__main__":
    print("Running Main for BinaryFileHandler module.")
    print("Testing GetScriptDirectory()")
    print(GetScriptDirectory())
    print("Testing ReadByteDataFile() with 'TestInput'")
    print(ReadByteDataFile('TestInput'))
    print("Testing WriteByteDataFile() with 'TestOutput.txt'")
    output = "My test output for BinaryFileHandler."
    WriteByteDataFile("TestOutput.txt", bytes(output, "utf-8"))
    print("Expected file contents: " + output)
    print("Testing GetFileName() with TestInput.txt")
    print(GetFileName("TestInput.txt"))
    print("Testing GetFileNameWithExtension() with os.path.join(GetScriptDirectory(), TestInput.txt)")
    print("(os.path.join(GetScriptDirectory(), 'TestInput.txt') returns..." + os.path.join(GetScriptDirectory(), "TestInput.txt") + ")")
    print(GetFileNameWithExtension(os.path.join(GetScriptDirectory(), "TestInput.txt")))
    print("Testing GetFileExtension() with TestInput.txt")
    print(GetFileExtension("TestInput.txt"))
