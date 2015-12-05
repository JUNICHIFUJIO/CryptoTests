# ERROR TESTING:
# Requires commenting and organization.

# Section for allowing import of custom classes
import sys
import os

if sys.path[0] != os.path.dirname(os.path.realpath(sys.argv[0])):
    sys.path.insert(0, os.path.dirname(os.path.realpath(sys.argv[0])))
    
######################################
#               IMPORTS              #
######################################
import timeit # ERROR TESTING REMOVE
from BinaryFileHandler import OpenAppendByteDataFile

######################################
#             CLASS START            #
######################################
class TimeResults:
    ######################################
    #            METHODS START
    ######################################
    def __init__(self, algorithm_used_str, surrounding_library_str):
        # Algorithm used
        self.algorithmUsed = algorithm_used_str
        # Surrounding library
        self.surroundingLibrary = surrounding_library_str
        # Time taken
        self.secondsTaken = []
        # Process iteration number
        self.nRuns = 0

    def __len__(self):
        return self.nRuns

    def __str__(self):
        '''String representation of the time results. Displays algorithm used,
           the encapsulating library, the time taken in microseconds, and the
           process iteration number.'''
        string = "Algorithm: " + str(self.algorithmUsed) \
                 + os.linesep + "Library used: " + str(self.surroundingLibrary) \
                 + os.linesep + "Time taken (seconds): " + os.linesep + "\t" + str(self.secondsTaken) \
                 + os.linesep + "Number of runs tracked: " + str(self.nRuns)

        return string

    def __repr__(self):
        return str(self)

    def append(self, seconds_taken):
        '''Appends a time result that has the same algorithm used and surrounding
           libraries.'''
        originalLen = len(self.secondsTaken)
        self.secondsTaken.append(seconds_taken)
        self.nRuns += 1
        return len(self.secondsTaken) == originalLen + 1

    def Average(self):
        '''Method designed to find the average of recorded time results.'''
        if self.nRuns < 1:
            return 0

        avgSum = 0
        for result in self.secondsTaken:
            avgSum += result

        return avgSum/self.nRuns

    # ERROR TESTING REMOVE
    def AVG(*time_results):
        '''Static function designed to find the average of the time results
           given.'''
        # Guard Conditions
        if(len(time_results) < 1):
            return 0

        avgSum = 0
        nResults = 0
        # Sum
        for result in time_results:
            try:
                avgSum += result.secondsTaken
                nResults += 1
            except AttributeError:
                try:
                    avgSum += result
                    nResults += 1
                except(TypeError, AttributeError):
                    raise AttributeError("Invalid argument passed to TimeResults.Average method. Please only pass TimeResult objects.")

        # Average
        try:
            return avgSum/nResults
        except ZeroDivisionError:
            raise ZeroDivisionError("Internal error in TimeResults.Average static method.")

    def AverageReadable(self):
        '''Creates a readable string representing the average of the time
           results passed to it. Returns a utf-8 encoded string representing the
           average time in seconds as well as the number of time results passed into it.'''
        # Create result string
        string = "For entries:"
        for timeEntry in self.secondsTaken:
            string += os.linesep + "\t" + str(timeEntry) + " seconds"
        # Append average
        string += os.linesep + os.linesep + "Average = " + str(self.Average()) + " seconds (" + str(self.nRuns) + " time entries)"

        return string.encode("utf-8")
   
    def AppendToFile(self, filename, n_line_breaks=0):
        '''Appends user-friendly description of this time result object to
           a specified text file. If line breaks are desired, they will be
           appended to the file before the data.'''
        # Guard conditions
        if n_line_breaks < 0:
            n_line_breaks = 0
        
        # Open binary file in append mode
        filehandler = OpenAppendByteDataFile(filename)

        # If line breaks are desired, append them before the data
        lineBreak = tuple(os.linesep)
        if n_line_breaks > 0:
            lineBreakBytes = bytearray()
            for i in range(n_line_breaks):
                lineBreakBytes.extend(ord(char) for char in lineBreak)
            filehandler.write(lineBreakBytes)
        
        # Append byte format of string representation of self to file
        filehandler.write(bytes(str(self).encode("utf-8")))

        # Insert a newline to prepare for readable format considering future
        # data appending
        filehandler.write(bytearray(ord(char) for char in lineBreak))

        # Close file
        filehandler.close()
    
    def AppendAverageToFile(self, filename, n_line_breaks=0):
        '''Appends user-friendly description of a time result average to
           a specified text file.'''
        # Guard conditions
        if n_line_breaks < 0:
            n_line_breaks = 0
            
        # Open binary file in append mode
        filehandler = OpenAppendByteDataFile(filename)

        # If line breaks are desired, append them before the data
        lineBreak = tuple(os.linesep)
        if n_line_breaks > 0:
            lineBreakBytes = bytearray()
            for i in range(n_line_breaks):
                lineBreakBytes.extend(ord(char) for char in lineBreak)
            filehandler.write(lineBreakBytes)

        # Append byte format of string representation of average to file
        filehandler.write(bytes(self.AverageReadable()))

        # Insert a newline to prepare for readable format considering future
        # data appending
        filehandler.write(bytearray(ord(char) for char in lineBreak))

        # Close file
        filehandler.close()

######################################
#               MAIN                 #
######################################
if __name__ == "__main__":
    print("Running main for TimeResults module.")
    print("Module found in " + str(os.path.dirname(os.path.realpath(sys.argv[0]))))
    print()

    algorithmUsed = "SHA256"
    surroundingLibrary = "hashlib"
    secondsTaken = 6.2903e-7
    # ERROR TESTING REMOVE nRuns = 2
    
    print("Testing module with:" \
          + os.linesep + "\t" + str(algorithmUsed) + " algorithm" \
          + os.linesep + "\t" + str(surroundingLibrary) + " library")
          # ERROR TESTING REMOVE + os.linesep + "\t" + str(secondsTaken) + " seconds" \
          # ERROR TESTING REMOVE + os.linesep + "\t" + "Number of runs: " + str(nRuns) + os.linesep)
    print()

    # ERROR TESTING REMOVE myResults = TimeResults(algorithmUsed, surroundingLibrary, secondsTaken, iterationNumber)
    myResults = TimeResults(algorithmUsed, surroundingLibrary)
    print("Time results object displays as:")
    print(str(myResults))
    print()

    filename = "TimeResultTest.txt"
    print("Testing writing of file to: " + str(filename))
    myResults.AppendToFile(filename)
    print("Testing appending of Time result object with 2 breaklines to: " + str(filename))
    myResults.AppendToFile(filename, 2)
    print()

    print("Testing appendage of time result (" + str(secondsTaken) + ")")
    myResults.append(secondsTaken)
    print(str(myResults))
    print("Appending change to file (" + str(filename) + ").")
    myResults.AppendToFile(filename, 1)
    print()
    
    print("Testing method Average with Time result object: ")
    print(str(myResults.Average))
    print("Testing appendage of average's information to file (" + str(filename) + ")")
    myResults.AppendAverageToFile(filename, 1)
    print()
