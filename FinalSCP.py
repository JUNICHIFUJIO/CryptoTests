# Section for allowing import of custom classes
import sys
import os

if sys.path[0] != os.path.dirname(os.path.realpath(sys.argv[0])):
    sys.path.insert(0, os.path.dirname(os.path.realpath(sys.argv[0])))

# Imports
from subprocess import Popen, PIPE, STDOUT
import time
from TimeResults import TimeResults

if __name__ == "__main__":
    # sys.argv[1] should represent the file to be passed along
    if len(sys.argv) != 2:
        raise ValueError("Usage: python FinalSCP.py fileToBeTransferred")
    
    nRuns = 5
    fileToBeTransferred = sys.argv[1]
    outputFilename = "SCPResults.txt"
    algorithms = [
        "3des-cbc",
        "aes128-cbc",
        "aes192-cbc",
        "aes256-cbc",
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr",
        "arcfour",
        "arcfour128",
        "arcfour256",
        "blowfish-cbc",
        "cast128-cbc"
        ]

    timeResults = {}
    

    for algorithm in algorithms:
        timeResults[algorithm] = TimeResults(algorithm, "scp")
        for i in range(nRuns):
            startTime = time.time()
            command = "scp -o 'StrictHostKeyChecking no' -c " + algorithm + ' ' + fileToBeTransferred \
                      + ' brownt4@uw1-320-lab.uwb.edu:Documents'
            os.system(command)
            #Popen(command, shell=True, stdout = PIPE, stderr = STDOUT)
            endTime = time.time()
            timeResults[algorithm].append(endTime - startTime)
        print(algorithm + " runs finished.")

    for timeResult in timeResults.values():
        timeResult.AppendToFile(outputFilename, 3)
        timeResult.AppendAverageToFile(outputFilename, 1)
