# Section for allowing import of custom classes
import sys
import os

if sys.path[0] != os.path.dirname(os.path.realpath(sys.argv[0])):
    sys.path.insert(0, os.path.dirname(os.path.realpath(sys.argv[0])))

######################################
#            CLASS START
######################################
# Takes a series of bytes or bits and converts them to a manageable list of bits
class MyBitArray:
    ######################################
    #            CONSTRUCTOR
    ######################################
    def __init__(self):
        self.bits = []

    ######################################
    #            METHODS
    ######################################

    # Converts an iterable of bytes to bits and stores them.
    def FromBytes(self, bytes_):
        self.bits = [0] * (len(bytes_) * 8)
                
        bitIndex = 0
        for byte in bytes_:
            for i in reversed(range(8)):
                if(byte & (1 << i) != 0):
                    self.bits[bitIndex] = 1
                else:
                    self.bits[bitIndex] = 0
                bitIndex += 1

    # Stores the iterable of bits inside.
    def FromBits(self, bits):
        self.bits = bits.copy()

    # Converts stored bits to bytes array.
    # Returns fresh MyBitArray holding bytes.
    def ToBytes(self):
        result = bytearray()
        byteIndex = 0
        bitIndex = 0
        while (byteIndex * 8) < len(self):
            try:
                theBits = self.bits[bitIndex : bitIndex + 8]
            except IndexError:
                theBits = self.bits[bitIndex :]
            result.append(0)
            for i in range(len(theBits)):
                result[byteIndex] = result[byteIndex] | (theBits[i] << (len(theBits) - 1 - i))
                bitIndex += 1
            byteIndex += 1

        return bytes(result)

    # Appends a single bit to the bit array.
    # Raises ValueError if bit isn't a 1 or 0.
    def append(self, bit):
        if int(bit) == 1 or int(bit) == 0:
            self.bits.append(bit)
        else:
            raise ValueError("Passed in bit was not a 1 or 0")

    # Appends all bits in the passed in bit array to this bit array.
    def extend(self, bit_array):
        try:
            self.bits.extend(bit_array.bits)
        except AttributeError:
            self.bits.extend(bit_array)

    # Returns a fresh MyBitArray that contains this bit array's bits rotated
    # to the left by n_rotations.
    def RotateLeft(self, n_rotations = 1):
        try:
            n_rotations %= len(self.bits)
            shiftedBits = MyBitArray()
            shiftedBits.extend(self.bits[n_rotations:])
            shiftedBits.extend(self.bits[:n_rotations])
            return shiftedBits
        except (ZeroDivisionError, IndexError) as error:
            return MyBitArray()

    # Returns a fresh MyBitArray that contains this bit array's bits rotated
    # to the right by n_rotations.
    def RotateRight(self, n_rotations = 1):
        try:
            n_rotations %= len(self.bits)
            shiftedBits = MyBitArray()
            shiftedBits.extend(self.bits[len(self.bits)-n_rotations:])
            shiftedBits.extend(self.bits[:len(self.bits)-n_rotations])
            return shiftedBits
        except (ZeroDivisionError, IndexError) as error:
            return MyBitArray()

    def SHR(self, n_rotations = 1):
        ''' Rotates right the bits in the bit array and pads with zeroes on the
            most significant bits. Returns fresh MyBitArray object.'''
        # Guard conditions
        if n_rotations < 0:
            # Handle invalid input
            raise ValueError("Desired number of rotations must be greater than or equal to 0.")

        if n_rotations >= len(self.bits):
            # Handle all cases where the desired number of rotations is greater
            # than or equal to the maximum allowed.
            emptyBitArray = MyBitArray()
            emptyBitArray.bits = [0] * len(self.bits)
            return emptyBitArray
        else:
            result = MyBitArray()
            result.bits = [0] * n_rotations
            rotatedBits = self.RotateRight(n_rotations)
            result.extend(rotatedBits.bits[n_rotations:])
            return result

    def SHL(self, n_rotations = 1):
        ''' Rotates left the bits in the bit array and pads with zeroes on the
            least significant bits. Returns fresh MyBitArray object.'''
        # Guard conditions
        if n_rotations < 0:
            # Handle invalid input
            raise ValueError("Desired number of rotations must be greater than or equal to 0.")

        if n_rotations >= len(self.bits):
            # Handle all cases where the desired number of rotations is greater
            # than or equal to the maximum allowed.
            emptyBitArray = MyBitArray()
            emptyBitArray.bits = [0] * len(self.bits)
            return emptyBitArray
        else:
            result = MyBitArray()
            result.extend(self.RotateLeft(n_rotations)[:len(self) - n_rotations])
            result.extend([0] * n_rotations)
            return result

    ######################################
    #           BUILT-IN METHODS
    ######################################
    def __len__(self):
        return len(self.bits)
        
    def __getitem__(self, key):
        return self.bits[key]

    def __setitem__(self, index, value):
        self.bits[index] = value

    def __copy__(self):
        copy = type(self)()
        copy.FromBits(copy.copy(self.bits))
        return copy

    def __deepcopy__(self, memo):
        deepcopy = type(self)()
        deepcopy.FromBits(copy.deepcopy(self.bits, memo))
        return deepcopy

    def __reversed__(self):
        return self.MyReverseBitArrayIterator(self.bits)
                                   
    def __xor__(self, other):
        result = MyBitArray()
        shorterArr = self
        longerArr = other
        if len(other) < len(self):
            shorterArr = other
            longerArr = self

        shorterIndex = len(shorterArr) - 1
        longerIndex = len(longerArr) - 1

        while True:
            if shorterIndex >= 0 and longerIndex >= 0:
                XORBit = shorterArr[shorterIndex] ^ longerArr[longerIndex]
                shorterIndex -= 1
                longerIndex -= 1
            elif longerIndex >= 0:
                XORBit = longerArr[longerIndex]
                longerIndex -= 1
            else:
                break

            result.bits.insert(0, XORBit)

        return result

    def __inv__(self):
        result = MyBitArray()
        result.FromBits(self.bits)
        for i in range(len(result)):
            if result.bits[i] == 0:
                result.bits[i] = 1
            elif result.bits[i] == 1:
                result.bits[i] = 0
            else:
                raise ValueError

        return result

    def __invert__(self):
        return self.__inv__()

    def __str__(self):
        string = "["
        if len(self) > 0:
            string += self.bits[0].__str__()
            index = 1
            while index < len(self):
                string += ", "
                if index % 8 == 0:
                    string += "| "
                string += self.bits[index].__str__()
                index += 1
        string += "]"

        return string

    ######################################
    #            ITERATOR
    ######################################
    def __iter__(self):
        return self.MyBitArrayIterator(self.bits)

    ######################################
    #            SUB CLASSES
    ######################################
    class MyBitArrayIterator:
        def __init__(self, bits):
            self.index = 0
            self.bits = bits

        def __iter__(self):
            return self

        def __next__(self):
            try:
                result = self.bits[self.index]
            except IndexError:
                raise StopIteration
            self.index += 1
            return result

    class MyReverseBitArrayIterator:
        def __init__(self, bits):
            self.index = len(bits) - 1
            self.bits = bits

        def __iter__(self):
            return self

        def __next__(self):
            try:
                result = self.bits[self.index]
            except IndexError:
                raise StopIteration
            self.index -= 1
            return result

######################################
#               MAIN
######################################
if __name__ == "__main__":
    print("Running Main for MyBitArray!")
    BitArray = MyBitArray()
    BitArray.FromBytes(bytes([120, 18, 94]))
    print(BitArray)
    print(BitArray.ToBytes())
    BitArray.FromBytes(BitArray.ToBytes())
    print(BitArray.ToBytes())
    print("Testing RotateLeft method:")
    print(BitArray.RotateLeft())
    print("Testing RotateLeft method with 3 rotations:")
    print(BitArray.RotateLeft(3))
    print("Testing original Bit array")
    print(BitArray)
    print("Testing SHR method with 2 rotations:")
    print(BitArray.SHR(2))
    excessRotations = len(BitArray) + 1
    print("Testing SHR method with " + str(excessRotations) + " rotations: (length of bit array is " + str(len(BitArray)) + ")")
    print(BitArray.SHR(excessRotations))
    print("Testing SHL method with 2 rotations:")
    print(BitArray.SHL(2))
    print("Testing SHL method with " + str(excessRotations) + " rotations: (length of bit array is " + str(len(BitArray)) + ")")
    print(BitArray.SHL(excessRotations))
    print()
    print("Testing __len__()")
    print(len(BitArray))
    print("Testing __reversed__()")
    print(reversed(BitArray))
    print("Testing __xor__()")
    OtherBitArray = MyBitArray()
    OtherBitArray.FromBytes(bytes([8, 0, 0]))
    print((BitArray ^ OtherBitArray))
    print("Testing __not__()")
    print(~BitArray)
    print("Testing append method:")
    BitArray.append(1)
    print(BitArray)
    try:
        BitArray.append(8)
        print(BitArray)
    except ValueError:
        print("Value Error correctly raised for append method")
