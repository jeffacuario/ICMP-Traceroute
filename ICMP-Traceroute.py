# Jeffrey Acuario
# CS372 - Project 2 Traceroute

# #################################################################################################################### #
# Resources used                                                                                                       #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
# For the error responses
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml

# Help to understand ping and tracert commands
    # https://www.youtube.com/watch?v=vJV-GBZ6PeM

# Traceroute info 
    # James F Kurose, Keith Ross Computer Networking A Top Down Approach 8E, Chapter 1.4.3 End-to-End Delay section Traceroute
    # https://www.thousandeyes.com/learning/glossary/traceroute
    
# Understanding checksum
    # https://stackoverflow.com/questions/20247551/icmp-echo-checksum

# To verify website ip in different continent
    # https://www.iplocation.net/ip-lookup
    # https://check-host.net/


# #################################################################################################################### #
# Imports                                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
import os
from socket import *
import struct
import time
import select
import time

# #################################################################################################################### #
# Class IcmpHelperLibrary                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
class IcmpHelperLibrary:
    # ################################################################################################################ #
    # Class IcmpPacket                                                                                                 #
    #                                                                                                                  #
    # References:                                                                                                      #
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                           #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket:
        # ############################################################################################################ #
        # IcmpPacket Class Scope Variables                                                                             #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __icmpTarget = ""               # Remote Host
        __destinationIpAddress = ""     # Remote Host IP Address
        __header = b''                  # Header after byte packing
        __data = b''                    # Data after encoding
        __dataRaw = ""                  # Raw string data before encoding
        __icmpType = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0            # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0          # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0      # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 30
        __ttl = 255                     # Time to live

        __DEBUG_IcmpPacket = False      # Allows for debug output

        # ############################################################################################################ #
        # IcmpPacket Class Getters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)   # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum              # Rotate and add

            answer = ~checksum                  # Invert bits
            answer = answer & 0xffff            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                   self.getIcmpType(),              #  8 bits / 1 byte  / Format code B
                                   self.getIcmpCode(),              #  8 bits / 1 byte  / Format code B
                                   self.getPacketChecksum(),        # 16 bits / 2 bytes / Format code H
                                   self.getPacketIdentifier(),      # 16 bits / 2 bytes / Format code H
                                   self.getPacketSequenceNumber()   # 16 bits / 2 bytes / Format code H
                                   )     

        def __encodeData(self):
            current_time = time.time()
            data_time = struct.pack("d", current_time)               # Used to track overall round trip time
                                                                     # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")
            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()                 # packHeader() and encodeData() transfer data to their respective bit
                                                # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()        # Result will set new checksum value
            self.__packHeader()                 # Header is rebuilt to include new checksum value


        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            # Compares each of the variables of the Packet with the original Data sent 
            # Set the valid data variable in the IcmpPacket_EchoReply class based the outcome of the data comparison
        
            print("validateIcmpReplyPacketWithOriginalPingData Started...") if self.__DEBUG_IcmpPacket else 0

            # Type {Reply Type must be set to 0}
            icmpReplyPacket.setIcmpType_isValid(icmpReplyPacket.getIcmpType() == 0)
            print(f"Type expected: {0} Type actual: {icmpReplyPacket.getIcmpType()} Result: {icmpReplyPacket.getIcmpType_isValid()}") if self.__DEBUG_IcmpPacket else 0

            # Code {Reply Code must be set to 0}
            icmpReplyPacket.setIcmpCode_isValid(icmpReplyPacket.getIcmpCode() == self.getIcmpCode())
            print(f"Code expected: {self.getIcmpCode()} Code actual: {icmpReplyPacket.getIcmpCode()} Result: {icmpReplyPacket.getIcmpCode_isValid()}") if self.__DEBUG_IcmpPacket else 0

            # Packet Identifier
            icmpReplyPacket.setIcmpIdentifier_isValid(icmpReplyPacket.getIcmpIdentifier() == self.getPacketIdentifier())
            print(f"Identifier expected: {self.getPacketIdentifier()} Identifier actual: {icmpReplyPacket.getIcmpIdentifier()} Result: {icmpReplyPacket.getIcmpIdentifier_isValid()}") if self.__DEBUG_IcmpPacket else 0
    
            # Sequence Number
            icmpReplyPacket.setIcmpSequence_isValid(icmpReplyPacket.getIcmpSequenceNumber() == self.getPacketSequenceNumber())
            print(f"Sequence number expected: {self.getPacketSequenceNumber()} Sequence number actual: {icmpReplyPacket.getIcmpSequenceNumber()} Result: {icmpReplyPacket.getIcmpSequence_isValid()}") if self.__DEBUG_IcmpPacket else 0

            # Raw Data
            icmpReplyPacket.setIcmpData_isValid(icmpReplyPacket.getIcmpData() == self.getDataRaw())
            print(f"Data expected: {self.getDataRaw()} Data actual: {icmpReplyPacket.getIcmpData()} Result: {icmpReplyPacket.getIcmpData_isValid()}") if self.__DEBUG_IcmpPacket else 0

            # Checksum
            # Recalculates checksum and compares with the checksum value from the Reply 
            recalculated_checksum = icmpReplyPacket.packAndRecalculateChecksumReply()
            icmpReplyPacket.setIcmpHeaderCheckSum_isValid(icmpReplyPacket.getIcmpHeaderChecksum() == recalculated_checksum)

            print(f"Checksum expected: {icmpReplyPacket.getIcmpHeaderChecksum()} Checksum recalculated: {recalculated_checksum} Result: {icmpReplyPacket.getIcmpHeaderCheckSum_isValid()}") if self.__DEBUG_IcmpPacket else 0

            # Checks if all values are valid
            icmpReplyPacket.setIsValidResponse(
                icmpReplyPacket.getIcmpType_isValid() and 
                icmpReplyPacket.getIcmpCode_isValid() and 
                icmpReplyPacket.getIcmpHeaderCheckSum_isValid() and 
                icmpReplyPacket.getIcmpIdentifier_isValid() and 
                icmpReplyPacket.getIcmpSequence_isValid() and 
                icmpReplyPacket.getIcmpData_isValid()
            )

            print(f"Valid: {icmpReplyPacket.isValidResponse()}") if self.__DEBUG_IcmpPacket else 0

        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def sendEchoRequest(self):
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            print("Pinging (" + self.__icmpTarget + ") " + self.__destinationIpAddress)

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 30
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    print("  *        *        *        *        *    Request timed out.")
                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect

                if timeLeft <= 0:
                    print("  *        *        *        *        *    Request timed out (By no remaining time left).")

                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]

                    if icmpType == 11:
                        # Type 11, Time Exceeded Message output for codes 0 and 1
                        if icmpCode == 0:
                            print("Time to Live exceeded in Transit")
                        elif icmpCode == 1:
                            print("Fragment Reassembly Time Exceeded")

                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                (
                                    self.getTtl(),
                                    (timeReceived - pingStartTime) * 1000,
                                    icmpType,
                                    icmpCode,
                                    addr[0]
                                )
                              )

                    elif icmpType == 3:
                        # Type 3, Destination Unreachable Message output for codes 0 and 1
                        if icmpCode == 0:
                            print("Destination Network Unreachable")
                        elif icmpCode == 1:
                            print("Destination Host Unreachable")
                            
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s" %
                                  (
                                      self.getTtl(),
                                      (timeReceived - pingStartTime) * 1000,
                                      icmpType,
                                      icmpCode,
                                      addr[0]
                                  )
                              )

                    elif icmpType == 0:                         # Echo Reply
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        # returns the Calculated RTT after sending
                        return icmpReplyPacket.printResultToConsole(
                            self.getDataRaw(), 
                            self.getPacketChecksum(), 
                            self.getPacketIdentifier(), 
                            self.getPacketSequenceNumber(), 
                            self.getTtl(), 
                            timeReceived, 
                            addr
                            )
                    else:
                        print("error")
            except timeout:
                print("  *        *        *        *        *    Request timed out (By Exception).")
            finally:
                mySocket.close()

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i+1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __recvPacket = b''
        __isValidResponse = False
        __headerReply = b''
        __dataReply = b'' 
        __packetChecksumReply = 0            

        # Variable validity for each value that can be obtained from the class
        __IcmpType_isValid = False
        __IcmpCode_isValid = False
        __IcmpHeaderCheckSum_isValid = False
        __IcmpIdentifier_isValid = False
        __IcmpSequence_isValid = False
        __IcmpData_isValid = False

        __DEBUG_IcmpPacketReply = False         # For debugging purposes


        # ############################################################################################################ #
        # IcmpPacket_EchoReply Constructors                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __init__(self, recvPacket):
            self.__recvPacket = recvPacket

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)   # Used to track overall round trip time
                                                               # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def isValidResponse(self):
            return self.__isValidResponse

        def getRecv(self): # For debugging purposes
            return self.__recvPacket

        # For easily tracking and identify which data points within the echo reply are valid
        def getIcmpType_isValid(self):
            return self.__IcmpType_isValid

        def getIcmpCode_isValid(self):
            return self.__IcmpCode_isValid

        def getIcmpHeaderCheckSum_isValid(self):
            return self.__IcmpHeaderCheckSum_isValid

        def getIcmpIdentifier_isValid(self):
            return self.__IcmpIdentifier_isValid

        def getIcmpSequence_isValid(self):
            return self.__IcmpSequence_isValid

        def getIcmpDateTimeSent_isValid(self):
            return self.__IcmpDateTimeSent_isValid

        def getIcmpData_isValid(self):
            return self.__IcmpData_isValid

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        def setIcmpType_isValid(self, booleanValue):
            self.__IcmpType_isValid = booleanValue

        def setIcmpCode_isValid(self, booleanValue):
            self.__IcmpCode_isValid = booleanValue

        def setIcmpHeaderCheckSum_isValid(self, booleanValue):
            self.__IcmpHeaderCheckSum_isValid = booleanValue

        def setIcmpIdentifier_isValid(self, booleanValue):
            self.__IcmpIdentifier_isValid = booleanValue

        def setIcmpSequence_isValid(self, booleanValue):
            self.__IcmpSequence_isValid = booleanValue

        def setIcmpDateTimeSent_isValid(self, booleanValue):
            self.__IcmpDateTimeSent_isValid = booleanValue

        def setIcmpData_isValid(self, booleanValue):
            self.__IcmpData_isValid = booleanValue

        def setpacketChecksumReply(self, recalculatedChecksum):
            self.__packetChecksumReply = recalculatedChecksum

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # Check sum validation
        def __recalculateChecksumReply(self):
            print("calculateChecksum Started for Reply...") if self.__DEBUG_IcmpPacketReply else 0
            packetAsByteData = b''.join([self.__headerReply, self.__dataReply])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacketReply else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacketReply else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacketReply else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)   # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum              # Rotate and add

            answer = ~checksum                  # Invert bits
            answer = answer & 0xffff            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacketReply else 0

            self.setpacketChecksumReply(answer)

        def __packHeaderReply(self):
            self.__headerReply = struct.pack("!BBHHH",
                                   self.getIcmpType(),              #  8 bits / 1 byte  / Format code B
                                   self.getIcmpCode(),              #  8 bits / 1 byte  / Format code B
                                   # We want to set it equal to 0 which clears the checksum first before recalculating
                                   self.__packetChecksumReply,      # 16 bits / 2 bytes / Format code H
                                   self.getIcmpIdentifier(),        # 16 bits / 2 bytes / Format code H
                                   self.getIcmpSequenceNumber()     # 16 bits / 2 bytes / Format code H
                                   )

        def __encodeDataReply(self):
            data_time = struct.pack("d", self.getDateTimeSent())
            data_time = data_time[::-1]
            dataRawEncoded = self.getIcmpData().encode("utf-8")
            self.__dataReply = data_time + dataRawEncoded
            
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def packAndRecalculateChecksumReply(self):
            self.__packHeaderReply()                 # packHeader() and encodeData() transfer data to their respective bit
                                                     # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeDataReply()
            self.__recalculateChecksumReply()        # Result will set new checksum value
            return self.__packetChecksumReply

        def printResultToConsole(self, DataRaw, PacketChecksum, PacketIdentifier, PacketSequenceNumber, ttl, timeReceived, addr):
            # Identify if the echo response is valid and report the error information details. 
            # For example, if the raw data is different, print to the console what the expected value and the actual value.

            # All values are valid
            if self.isValidResponse():
                bytes = struct.calcsize("d")
                timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]
                calculated_RTT = (timeReceived - timeSent) * 1000
                print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d        Identifier=%d    Sequence Number=%d    %s" %
                    (
                        ttl,
                        calculated_RTT,
                        self.getIcmpType(),
                        self.getIcmpCode(),
                        self.getIcmpIdentifier(),
                        self.getIcmpSequenceNumber(),
                        addr[0]
                    )
                    )
                
                return calculated_RTT

            # Issue with comparisions
            else:
                print("Issue found comparing values!")
                # DataRaw
                if self.getIcmpData_isValid() == False:
                    print(f"Data expected: {DataRaw}\nData actual: {self.getIcmpData()}\nResult: {self.getIcmpData_isValid()}\n")

                # Type
                if self.getIcmpType_isValid() == False:
                    print(f"Type expected: {0}\nType actual: {self.getIcmpType()}\nResult: {self.getIcmpType_isValid()}\n")

                # Code
                if self.getIcmpCode_isValid() == False:
                    print(f"Code expected: {0}\nCode actual: {self.getIcmpCode()}\nResult: {self.getIcmpCode_isValid()}\n")

                # PacketChecksum
                if self.getIcmpHeaderCheckSum_isValid() == False:
                    print(f"Checksum expected: {PacketChecksum}\nChecksum actual: {self.getIcmpHeaderChecksum()}\nResult: {self.getIcmpHeaderCheckSum_isValid()}\n")

                # PacketIdentifier
                if self.getIcmpIdentifier_isValid() == False:
                    print(f"Identifier expected: {PacketIdentifier}\nIdentifier actual: {self.getIcmpIdentifier()}\nResult: {self.getIcmpIdentifier_isValid()}\n")

                # PacketSequenceNumber
                if self.getIcmpSequence_isValid() == False:
                    print(f"Sequence expected: {PacketSequenceNumber}\nSequence actual: {self.getIcmpSequenceNumber()}\nResult: {self.getIcmpSequence_isValid()}\n")


    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False                  # Allows for debug output

    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def __sendIcmpEchoRequest(self, host):
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        # Array to keep track of all the RTT 
        RTT_list = []

        # Count for valid and invalid transmissions
        lost = 0
        sent = 0

        for i in range(4): # change number to get # of times for ping
            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                           # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)


            request = icmpPacket.sendEchoRequest()          # Build IP
            sent += 1 # increment sent 

            # Handle issues with transmission
            if request == None:                            
                lost += 1
            elif request < 0:
                lost += 1
            else:
                # Append value of RTT to array
                RTT_list.append(round(request))

            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            # we should be confirming values are correct, such as identifier and sequence number and data
        
        # Output message after completing all pings including number of packets sent, lost, and % loss
        print(f"\nPing statistics for {host}:\n    Packets: Sent = {sent}, Received = {sent-lost}, Lost = {lost} ({int((lost/sent)*100)}% loss),")

        # Handle all packets lost
        if len(RTT_list) == 0:
            print("No Packet Received!")
        else:
            # Output message with minimum, maximum, and average RTT
            print(f"Approximate round trip times in milli-seconds:\n    Minimum = {min(RTT_list)}ms, Maximum = {max(RTT_list)}ms, Average = {round(sum(RTT_list)/len(RTT_list))}ms\n")

    def __sendIcmpTraceRoute(self, host):
        print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        # Build code for trace route here

        # For tracking number of valid requests (reached target address)
        count = 0

        print(f"Tracing route to {host} over a maximum of 30 hops:\n")

        for i in range(1,30): # change number to get # of hops
            for j in range(3): # each hop sends 3 requests
                # Build packet
                icmpPacket = IcmpHelperLibrary.IcmpPacket()

                randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                               # Some PIDs are larger than 16 bit

                packetIdentifier = randomIdentifier
                packetSequenceNumber = i

                icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
                icmpPacket.setIcmpTarget(host)

                # Ttl is based on i, currently it is going up by 1, starting at 1.
                icmpPacket.setTtl(i)
                
                request = icmpPacket.sendEchoRequest()
                # request > 0 means valid, increment count
                if request:
                    count +=1

                icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
                icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0

                # End after 3 valid requests 
                if count == 3:
                    return
            print("----------------------------------------------------------------------------")

    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions                                                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def sendPing(self, targetHost):
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)
        print("\nTrace complete.\n")

# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()

    # Choose one of the following by uncommenting out the line

        # ping
    # icmpHelperPing.sendPing("209.233.126.254")
    icmpHelperPing.sendPing("www.google.com")
    time.sleep(10)
    # icmpHelperPing.sendPing("oregonstate.edu")
    # icmpHelperPing.sendPing("gaia.cs.umass.edu")

        # traceroute
    # icmpHelperPing.traceRoute("209.233.126.254")
    # icmpHelperPing.traceRoute("gaia.cs.umass.edu")      # first
    # icmpHelperPing.traceRoute("oregonstate.edu")
    icmpHelperPing.traceRoute("www.google.com")       # second
    # icmpHelperPing.traceRoute("www.facebook.com")

        # two on different continents:
    # icmpHelperPing.traceRoute("www.lazada.com.ph")    # third
    # icmpHelperPing.traceRoute("allegro.pl")           # fourth


if __name__ == "__main__":
    main()