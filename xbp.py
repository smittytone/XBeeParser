#!/usr/bin/env python

##########################################################################
#                                                                        #
# XBeeParser 1.0.2                                                       #
# Copyright 2018, Tony Smith (@smittytone)                               #
# License: MIT (terms attached to this repo)                             #
#                                                                        #
##########################################################################


##########################################################################
# Program library imports                                                #
##########################################################################

import sys, math

##########################################################################
# Constants covering key XBee and Zigbee commands, data types, etc.      #
##########################################################################

# XBee Request Commands
XBEE_CMD_AT                                 = 0x08
XBEE_CMD_QUEUE_PARAM_VALUE                  = 0x09
XBEE_CMD_ZIGBEE_TRANSMIT_REQ                = 0x10
XBEE_CMD_EXP_ADDR_ZIGBEE_CMD_FRAME          = 0x11
XBEE_CMD_REMOTE_CMD_REQ                     = 0x17
XBEE_CMD_CREATE_SOURCE_ROUTE                = 0x21

# XBee Response Frame IDs
XBEE_CMD_AT_RESPONSE                        = 0x88
XBEE_CMD_MODEM_STATUS                       = 0x8A
XBEE_CMD_ZIGBEE_TRANSMIT_STATUS             = 0x8B
XBEE_CMD_ZIGBEE_RECEIVE_PACKET              = 0x90
XBEE_CMD_ZIGBEE_EXP_RX_INDICATOR            = 0x91
XBEE_CMD_ZIGBEE_IO_DATA_SAMPLE_RX_INDICATOR = 0x92
XBEE_CMD_XBEE_SENSOR_READ_INDICATOR         = 0x94
XBEE_CMD_NODE_ID_INDICATOR                  = 0x95
XBEE_CMD_REMOTE_CMD_RESPONSE                = 0x97
XBEE_CMD_OTA_FIRMWARE_UPDATE_STATUS         = 0xA0
XBEE_CMD_ROUTE_RECORD_INDICATOR             = 0xA1
XBEE_CMD_DEVICE_AUTH_INDICATOR              = 0xA2
XBEE_CMD_MANY_TO_ONE_ROUTE_REQ_INDICATOR    = 0xA3

# ZCL Global Commands
ZCL_GLOBAL_CMD_READ_ATTR_REQ                = 0x00
ZCL_GLOBAL_CMD_READ_ATTR_RSP                = 0x01
ZCL_GLOBAL_CMD_WRITE_ATTR_REQ               = 0x02
ZCL_GLOBAL_CMD_WRITE_ATTR_UND               = 0x03
ZCL_GLOBAL_CMD_WRITE_ATTR_RSP               = 0x04
ZCL_GLOBAL_CMD_WRITE_ATTR_NO                = 0x05
ZCL_GLOBAL_CMD_CONF_REPT_REQ                = 0x06
ZCL_GLOBAL_CMD_CONF_REPT_RSP                = 0x07
ZCL_GLOBAL_CMD_READ_REPT_REQ                = 0x08
ZCL_GLOBAL_CMD_READ_REPT_RSP                = 0x09
ZCL_GLOBAL_CMD_REPT_ATTR                    = 0x0A
ZCL_GLOBAL_CMD_DEFAULT_RSP                  = 0x0B
ZCL_GLOBAL_CMD_DISC_ATTR_REQ                = 0x0C
ZCL_GLOBAL_CMD_DISC_ATTR_RSP                = 0x0D
ZCL_GLOBAL_CMD_READ_ATTR_STR_REQ            = 0x0E
ZCL_GLOBAL_CMD_WRITE_ATTR_STR_REQ           = 0x0F
ZCL_GLOBAL_CMD_WRITE_ATTR_STR_RSP           = 0x10
ZCL_GLOBAL_CMD_DISC_RCMDS_REQ               = 0x11
ZCL_GLOBAL_CMD_DISC_RCMDS_RSP               = 0x12
ZCL_GLOBAL_CMD_DISC_GCMDS_REQ               = 0x13
ZCL_GLOBAL_CMD_DISC_GCMDS_RSP               = 0x14
ZCL_GLOBAL_CMD_DISC_ATTR_EXT_REQ            = 0x15
ZCL_GLOBAL_CMD_DISC_ATTR_EXT_RSP            = 0x16

# Internal ZCL frame types
ATT_TYPE_READ_RSP                           = 0x00
ATT_TYPE_WRITE_REQ                          = 0x01
ATT_TYPE_WRITE_RSP                          = 0x02


##########################################################################
# Application-specific constants                                         #
##########################################################################

# App Constants
TEXT_SIZE = 30
SPACE_STRING = "                                                             "
APP_VERSION = "1.0.2"

# ZCL Global Command names
ZCLCommmands = ["Read Attributes", "Read Attributes Response", "Write Attributes", "Write Attributes Undivided",
                "Write Attributes Response", "Write Attributes No Response", "Configure Reporting", "Configure Reporting Response",
                "Read Reporting Configuration", "Read Reporting Configuration Response", "Report Attributes", "Default Response",
                "Discover Attributes", "Discover Attributes Response"]


##########################################################################
# Application globals                                                    #
##########################################################################

escaped = True
debug = False
prefixed = False


##########################################################################
# Packet-processing entry point                                          #
##########################################################################

def processPacket(packet):
    # Process a string of hex bytes received or sent via an XBee
    # Parameters:
    #   1. String - the packet data as a hexadecimal string as passed in via
    #               the command line
    # Returns:
    #   Nothing
    global escaped

    # Convert hex string to upper case
    packet = packet.upper()
    
    # Run through the string and remove spaces, if any, between codes
    done = False
    i = 0
    while done is False:
        c = packet[i]
        if c == " ":
            packet = packet[0:i] + packet[i + 1:]
        else:
            i = i + 1
        if i >= len(packet):
            done = True
    
    if debug is True:
        print(packet)
    
    # Does the data contain an even number of characters? It should
    # TODO Should this just pad the end with 0?
    if len(packet) % 2 != 0:
        print("[ERROR] Packet data does not contain an even number of octets")
        return

    # Convert each pair of characters (which represent a single byte)
    # to integer values in an array
    # NOTE 'escaped' indicates whether the packet contains escaped
    #      characters, an XBee feature
    values = []
    done = False
    escapeNextChar = False
    i = 0
    while done is False:
        c = packet[i:i+2]
        if c == "7D" and escaped is True and escapeNextChar is False:
            escapeNextChar = True
        elif escapeNextChar is True:
            values.append(int(c, 16) ^ 0x20)
            escapeNextChar = False
        else:
            values.append(int(c, 16))
        
        i = i + 2
        if i >= len(packet):
            done = True

    # Is the first character the XBee packet marker?
    if values[0] == 0x7E:
        print("XBee frame found")
    else:
        print("[ERROR] Packet data does not start with an XBee signature (" + getHex(values[0],2) + ", should be 7E)")
        return
    
    # Test the checksum value (the last byte in the packet)
    checksum = values[len(values) - 1]
    cs = 0
    for i in range(3, len(values) - 1):
        cs = cs + values[i]
    cs = (0xFF - (cs & 0xFF)) & 0xFF
    if cs != checksum:
        print("[ERROR] Packet checksum test failed (" + getHex(cs,2) + " should be " + getHex(checksum,2) + ")")
        return

    # Display the frame data length
    length = values[1] * 256 + values[2]
    print(padText("Frame length") + str(length) + " bytes")

    # Look for XBee frame types and decode the data individually
    cmd = values[3]
    if cmd == XBEE_CMD_AT:
        decodeSendATCommand(values) #DONE
    elif cmd == XBEE_CMD_QUEUE_PARAM_VALUE:
        decodeParamQueueRequest(values) #DONE
    elif cmd == XBEE_CMD_ZIGBEE_TRANSMIT_REQ:
        decodeZigbeeTransitRequest(values) #DONE
    elif cmd == XBEE_CMD_EXP_ADDR_ZIGBEE_CMD_FRAME:
        decodeExplicitZigbeeCmdRequest(values) #DONE
    elif cmd == XBEE_CMD_REMOTE_CMD_REQ:
        decodeRemoteCmdRequest(values) #DONE
    elif cmd == XBEE_CMD_CREATE_SOURCE_ROUTE:
        decodeCreateSourceRouteRequest(values) #DONE
    elif cmd == XBEE_CMD_AT_RESPONSE:
        decodeATResponse(values) #DONE
    elif cmd == XBEE_CMD_MODEM_STATUS:
        decodeModemStatus(values) #DONE
    elif cmd == XBEE_CMD_ZIGBEE_TRANSMIT_STATUS:
        decodeZigbeeTransmitStatus(values) #DONE
    elif cmd == XBEE_CMD_ZIGBEE_RECEIVE_PACKET:
        decodeZigbeeReceivePacket(values) #DONE
    elif cmd == XBEE_CMD_ZIGBEE_EXP_RX_INDICATOR:
        decodeZigbeeRXIndicator(values) #DONE
    elif cmd == XBEE_CMD_ZIGBEE_IO_DATA_SAMPLE_RX_INDICATOR:
        decodeZigbeeDataSampleRXIndicator(values) #DONE
    elif cmd == XBEE_CMD_XBEE_SENSOR_READ_INDICATOR:
        decodeXBeeSensorReadIndicator(values) #DONE
    elif cmd == XBEE_CMD_NODE_ID_INDICATOR:
        decodeNodeIDIndicator(values) #DONE
    elif cmd == XBEE_CMD_REMOTE_CMD_RESPONSE:
        decodeRemoteATCommand(values) #DONE
    elif cmd == XBEE_CMD_OTA_FIRMWARE_UPDATE_STATUS:
        decodeFirmwareUpdate(values) #DONE
    elif cmd == XBEE_CMD_ROUTE_RECORD_INDICATOR:
        decodeRouteRecordIndicator(values) #DONE
    elif cmd == XBEE_CMD_DEVICE_AUTH_INDICATOR:
        decodeDeviceAuthIndicator(values) #DONE
    elif cmd == XBEE_CMD_MANY_TO_ONE_ROUTE_REQ_INDICATOR:
        decodeManyToOneRouteIndicator(values) #DONE
    else:
        print("[ERROR] Unknown or not-yet-supported frame type: " + getHex(values[3],2))
        return
    print(padText("Checksum") + getHex(checksum,2))


##########################################################################
# This section comprises starting points for specific XBee packet types. #
##########################################################################

def decodeSendATCommand(data):
    # The Xbee is sending an XBee AT command packet (frame ID 0x08)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing

    decodeATCommon(data, "Issue local AT command", "None")


def decodeParamQueueRequest(data):
    # The Xbee is queing an XBee AT command packet (frame ID 0x09)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing

    decodeATCommon(data, "Queue AT command parameter value", "Read queued")


def decodeZigbeeTransitRequest(data):
    # The Xbee has issues a basic Zigbee command (frame ID 0x10)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing

    printStandardHeader("Issue basic Zigbee request", data, 3)
    print(padText("Radius") + getHex(data[15],2))
    getSendOptions(data[16])
    
    ds = ""
    length = (data[1] << 8) + data[2] - 14
    if l > 0:
        for i in range(17, 17 + length):
            ds = ds + getHex(data[i],2)
        print(padText("Data bytes (" + str(l) + ")") + ds)


def decodeExplicitZigbeeCmdRequest(data):
    # The Xbee is sending an explicit Zigbee packet (frame ID 0x11)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing

    printStandardHeader("Issue explicit Zigbee request", data, 3)
    print(padText("Source endpoint") + getHex(data[15],2))
    print(padText("Destination endpoint") + getHex(data[16],2))
    
    cid = (data[17] << 8) + data[18]
    print(padText("Cluster ID") + getHex(cid,4))
    
    pid = (data[19] << 8) + data[20]
    print(padText("Profile ID") + getHex(pid,4))
    
    print(padText("Radius") + getHex(data[21],2))
    getSendOptions(data[22])
    
    length = (data[1] << 8) + data[2] - 20
    dv = printFrameData(data, 23, length)
    if len(dv) > 0:
        if pid == 0x0000:
            # ZDO operation
            decodeZDO(dv, cid)
        else:
            # ZCL operation
            decodeZCLFrame(dv)


def decodeRemoteCmdRequest(data):
    # The Xbee is sending a remote AT response packet (frame ID 0x17)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing
    
    printStandardHeader("Remote AT command request", data, 3)
    getSendOptions(data[15])
    print(padText("XBee AT command") + "\"" + chr(data[16]) + chr(data[17]) + "\"")
    decodeATParamCommon(data, 18, 15, "Read request")


def decodeCreateSourceRouteRequest(data):
    # The Xbee is sending a source route request (frame ID 0x21)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing
    
    printStandardHeader("Create source route request", data, 3)
    print(padText("Route Command Options") + getHex(data[15],2))
    
    n = data[16]
    print(padText("Number of addresses") + getHex(n,2))

    length = (data[1] << 8) + data[2] - 14
    if l > 0:
        a = 0
        c = 1
        for i in range(17, 17 + length, 2):
            a = (data[i] << 8) + data[i + 1]
            print(padText("  Address " + str(c)) + getHex(a,4))
            c = c + 1
    elif l < n * 2:
        print("[ERROR]: missing address data - " + str(l / 2) + " included, " + n + " expected")
        sys.exit(0)


def decodeATResponse(data):
    # The Xbee has received an XBee AT response packet (frame ID 0x88)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing
    
    cs = decodeATCommon(data, "Local AT command response")
    getATStatus(data[7])
    
    length = (data[1] << 8) + data[2] - 5
    dv = printFrameData(data, 8, length)

    # Trap ND packets
    if cs == "ND":
        decodeNIData(dv, 0)


def decodeModemStatus(data):
    # The Xbee has received an XBee model status packet (frame ID 0x8A)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing
    
    print(padText("XBee command ID") + getHex(data[3],2) + " \"Modem status\"" )
    getModemStatus(data[4])


def decodeZigbeeTransmitStatus(data):
    # The Xbee has received an Zigbee transmit status packet (frame ID 0x8B)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing
    
    print(padText("XBee command ID") + getHex(data[3],2) + " \"Zigbee transmit status\"")
    print(padText("XBee frame ID") + getHex(data[4],2))
    print(padText("Address (16-bit)") + getHex(((data[5] << 8) + data[6]),4))
    print(padText("Retries") + ("None" if data[7] == 0 else str(data[7])))
    getDeliveryStatus(data[8])
    getDiscoveryStatus(data[9])


def decodeZigbeeReceivePacket(data):
    # The Xbee has received a basic  packet (frame ID 0x90)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing
    
    printBasicHeader("Zigbee receive packet (basic)", data, 3)
    getPacketStatus(data[14])
    
    length = (data[1] << 8) + data[2] - 12
    dv = printFrameData(data, 15, length)


def decodeZigbeeRXIndicator(data):
    # The Xbee has received an explicit Zigbee ZCL packet (frame ID 0x91)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing
    
    printBasicHeader("Zigbee explicit RX indicator", data, 3)
    print(padText("Source endpoint") + getHex(data[14],2))
    print(padText("Destination endpoint") + getHex(data[15],2))
    
    cid = (data[16] << 8) + data[17]
    print(padText("Cluster ID") + getHex(cid,4))
    
    pid = (data[18] << 8) + data[19]
    print(padText("Profile ID") + getHex(pid,4))
    
    getPacketStatus(data[20])
    
    length = (data[1] << 8) + data[2] - 18
    dv = printFrameData(data, 21, length)
    if len(dv) > 0:
        if pid == 0x0000:
            decodeZDO(dv, cid)
        elif pid == 0xC105:
            # Trap Digi's *other* node descriptor, send on button press
            decodeNIData(dv, 0)
        else:
            decodeZCLFrame(dv)


def decodeZigbeeDataSampleRXIndicator(data):
    # The Xbee has received a Zigbee IO Data Sample RX Indicator (frame ID 0x92)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing

    printBasicHeader("Zigbee IO data sample", data, 3)
    getPacketStatus(data[14])

    print(padText("Number of samples") + str(data[15]))
    nd = (data[16] << 8) + data[17]
    start = 19
    if nd > 0:
        getDigitalChannelMask(data, 16)
        start = 21
    if data[18] > 0:
        getAnalogChannelMask(data, start)


def decodeXBeeSensorReadIndicator(data):
    # The Xbee has received an XBee sensor read response (frame ID 0x94)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing
    
    printBasicHeader("XBee sensor read indicator response", data, 3)
    getPacketStatus(data[14])
    getOneWireStatus(data[15])
    
    # Read the sensor data
    values = []
    noSensors = 0
    for i in range(16,24,2):
        a = (data[i] << 8) + data[i + 1]
        values.append(a)
        if a == 0xFF:
            noSensors = noSensors + 1
    if noSensors == 4:
        print("No AD sensors found")
    else:
        es = ""
        for i in range(0,4):
            es = es + getHex(values[i],4) + ", "
        es = es[0:len(es)-2]
        print(padText("AD sensor values") + es)
    
    # Read the thermometer data
    a = (data[24] << 8) + data[25]
    if a == 0xFFFF:
        print("No thermometer found")
    else:
        print(padText("Thermometer reading") + getHex(a,4))


def decodeNodeIDIndicator(data):
    # The Xbee has received an XBee remote AT response packet (frame ID 0x95)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing
    
    printBasicHeader("Node identification indicator response", data, 3)
    getPacketStatus(data[14])
    l = (data[1] << 8) + data[2] - 25
    decodeNIData(data, 15)


def decodeRemoteATCommand(data):
    # The Xbee has received an XBee remote AT response packet (frame ID 0x97)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing
    
    printStandardHeader("Remote AT command response", data, 3)
    print(padText("XBee AT command") + chr(data[15]) + chr(data[16]))
    getATStatus(data[17])
    
    length = (data[1] << 8) + data[2] - 15
    dv = printFrameData(data, 18, length)


def decodeFirmwareUpdate(data):
    # The Xbee has received an XBee firmware update packet (frame ID 0xA0)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing

    printBasicHeader("XBee firmware update", data, 3)
    getPacketStatus(data[14])
    getBootloaderMessage(data[15])

    print(padText("Block number") + str(data[16]))
    read64bitAddress(data, 17, "Target address (64-bit)")
    
    
def decodeRouteRecordIndicator(data):
    # The Xbee has received a routing info packet (frame ID 0xA1)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing

    printBasicHeader("Route record indicator response", data, 3)
    getPacketStatus(data[14])
    
    n = data[15]
    print(padText("Number of addresses") + getHex(n,2))

    l = (data[1] << 8) + data[2] - 13
    if l > 0:
        a = 0
        c = 1
        for i in range(16, 16 + l, 2):
            a = (data[i] << 8) + data[i + 1]
            print(padText("  Address " + str(c)) + getHex(a,4))
            c = c + 1
    elif l < n * 2:
        print("[ERROR]: missing address data - " + str(l / 2) + " included, " + n + " expected")
        sys.exit(0)


def decodeDeviceAuthIndicator(data):
    # The XBee has received a device-authenticated packet (frame ID 0xA2)
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing
    
    printBasicHeader("Device Authenticated Indicator", data, 3)
    
    
def decodeManyToOneRouteIndicator(data):
    # The Xbee has received a many-to-one routing info packet (frame ID 0xA3)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing
    
    printBasicHeader("Many-to-one routing information", data, 3)
    

###########################################################################
# This section comprises utilities access by the above decoder functions  #
###########################################################################

def decodeATCommon(data, cmd, noParamMessage = ""):
    # Code common to AT command-related decoders
    # Parameters:
    #   1. Array - the packet data
    #   2. String - the command information to print
    #   3. String - text to print if there is no parameter value. This
    #               is optional; if omitted, only the header info is
    #               printed
    # Returns:
    #   String - the AT command
    
    cs = chr(data[5]) + chr(data[6])
    print(padText("XBee command ID") + getHex(data[3],2) + " \"" + cmd + "\"")
    print(padText("XBee frame ID") + getHex(data[4],2))
    print(padText("XBee AT command") + "\"" + cs + "\"")
    if len(noParamMessage) > 0:
        decodeATParamCommon(data, 7, 4, noParamMessage)
    return cs

def decodeATParamCommon(data, startIndex, delta, noParamMessage):
    # Code used by the above function
    # Parameters:
    #   1. Array - the packet data
    #   2. Integer - the index of the start of the information in the packet
    #   3. Integer - the length of the header data
    #   4. String - the text to print if there are no parameters included
    # Returns:
    #   Nothing
    ds = ""
    l = (data[1] << 8) + data[2] - delta
    if l > 0:
        for i in range(startIndex, startIndex + l):
            ds = ds + getHex(data[i],2)
    else:
        ds = noParamMessage
    print(padText("Command parameter value") + ds)


def printBasicHeader(cmd, data, start):
    # Generic packet header decoding for a number of the above functions
    # Parameters:
    #   1. String - the command info to print
    #   2. Array - the packet data
    #   3. Integer - the start of the information in the frame data
    # Returns:
    #   Nothing
    
    print(padText("XBee command ID") + getHex(data[start],2) + " \"" + cmd + "\"")
    read64bitAddress(data, start + 1)
    print(padText("Address (16-bit)") + getHex(((data[start + 9] << 8) + data[start + 10]),4))
    
    
def printStandardHeader(cmd, data, start):
    # Generic packet header decoding for a number of the above functions
    # Parameters:
    #   1. String - the command info to print
    #   2. Array - the packet data
    #   3. Integer - the start of the information in the frame data
    # Returns:
    #   Nothing
    
    print(padText("XBee command ID") + getHex(data[start],2) + " \"" + cmd + "\"")
    print(padText("XBee frame ID") + getHex(data[start + 1],2))
    read64bitAddress(data, start + 2)
    print(padText("Address (16-bit)") + getHex(((data[start + 10] << 8) + data[start + 11]),4))
    

def printFrameData(data, start, length):
        
    ds = ""
    dv = []
    if length > 0:
        for i in range(start, start + length):
            ds = ds + getHex(data[i],2)
            dv.append(data[i])
        print(padText("Frame data") + ds)
    return dv
    
    
def decodeNIData(data, start):
    # Generic Node Ident data extrator
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    #   2. Integer - index of the start of the data
    # Returns:
    #   Nothing
    
    print(padText("Source address (16-bit)") + getHex(((data[start] << 8) + data[start + 1]),4))
    read64bitAddress(data, start + 2, "Source address (64-bit)")

    index = start + 10
    nis = ""
    done = False
    while done is False:
        if (data[index]) != 0x00:
            nis = nis + chr(data[index])
        else:
            done = True
        index = index + 1
    
    if len(nis) > 0 and nis[0] != " ":
        print(padText("NI string") + nis)
    else:
        print(padText("NI string") + "Default")

    print(padText("Parent address (16-bit)") + getHex(((data[index] << 8) + data[index + 1]),4))
    
    getDeviceType(data[index + 2])
    getSourceEvent(data[index + 3])

    print(padText("Digi Profile ID") + getHex(((data[index + 4] << 8) + data[index + 5]),4))
    print(padText("Manufacturer ID") + getHex(((data[index + 6] << 8) + data[index + 7]),4))


###########################################################################
# This section comprises decoders for Zigbee data sent or received via an #
# XBee. This covers Zigbee Cluster Library (ZCL) frames, and Zigbee       #
# Device Objects (ZDO) entities                                           #
###########################################################################

def decodeZCLFrame(frameData):
    # Decode a full ZCL frame
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing
    
    global ZCLCommmands
    
    manSpec = False
    globalCmd = True

    # Decode and display the frame control byte
    fc = frameData[0]
    fcs = getBinary(fc)
    print(padText("  Frame Control Byte") + getHex(fc,2) + " [b" + fcs + "]")
    
    if fc & 0x01 == 0x01:
        print(SPACE_STRING[0:TEXT_SIZE] + "  Command is specific to cluster")
        globalCmd = False
    else:
        print(SPACE_STRING[0:TEXT_SIZE] + "  Command is global to ZCL")

    if fc & 0x08 == 0:
        print(SPACE_STRING[0:TEXT_SIZE] + "  Direction: client to server")
    else:
        print(SPACE_STRING[0:TEXT_SIZE] + "  Direction: server to client")

    if fc & 0x04 == 0x04:
        print(SPACE_STRING[0:TEXT_SIZE] + "  Manufacturer-specific commands in data")
        manSpec = True
    else:
        print(SPACE_STRING[0:TEXT_SIZE] + "  No manufacturer-specific commands in data")

    if fc & 0x10 == 0x10:
        print(SPACE_STRING[0:TEXT_SIZE] + "  Default response disabled")
    else:
        print(SPACE_STRING[0:TEXT_SIZE] + "  Default response enabled")
    
    index = 1
    if manSpec is True:
        mc = (frameData[1] << 8) + frameData[2]
        print(padText("  Manufacturer code") + getHex(mc,4))
        index = 3
    
    # Decode and display the ZCL frame header's remaining two bytes
    tsn = frameData[index]
    cid = frameData[index + 1]
    print(padText("  Transaction seq. number") + getHex(tsn,2))
    
    if globalCmd is True:
        if cid < len(ZCLCommmands):
            print(padText("  Global command") + getHex(cid,2) + " - " + ZCLCommmands[cid])
        else:
            print(padText("  Global command") + getHex(cid,2) + " - Unknown")
    else:
        print(padText("  Cluster command") + getHex(cid,2))

    # Payload is at 'index' + 2
    if globalCmd is True and manSpec is False:
        # Only decode global commands for now
        decodeZCLCommand(cid, frameData, index + 2)
    else:
        # Dump the data, which contains Cluster-specific info
        ds = ""
        for i in range(index + 2, len(frameData)):
            ds = ds + getHex(frameData[i],2)
        print(padText("  Data") + ds)


def decodeZCLCommand(cmd, data, start):
    # Jump table for general ZCL commands
    
    if cmd == ZCL_GLOBAL_CMD_READ_ATTR_REQ:
        decodeZCLReadAttributeReq(data, start) #DONE
    elif cmd == ZCL_GLOBAL_CMD_READ_ATTR_RSP or cmd == ZCL_GLOBAL_CMD_WRITE_ATTR_NO:
        decodeAttributeList(data, start, ATT_TYPE_READ_RSP) #DONE
    elif cmd == ZCL_GLOBAL_CMD_WRITE_ATTR_REQ or cmd == ZCL_GLOBAL_CMD_WRITE_ATTR_UND:
        decodeAttributeList(data, start, ATT_TYPE_WRITE_REQ) #DONE
    elif cmd == ZCL_GLOBAL_CMD_WRITE_ATTR_RSP:
        decodeAttributeList(data, start, ATT_TYPE_WRITE_RSP) #DONE
    else:
        print("  [ERROR] General command " + getHex(cmd,2) + " not yet supported by this program")


def decodeZCLReadAttributeReq(data, start):
    # Decode a ZCL read attribute request
    # Parameters:
    #   1. Array - the frame data as a series of integer values
    #   2. Integer - index of the ZCL data start within the data
    # Returns:
    #   Nothing
    
    ms = ""
    es = ""
    for i in range(start, len(data), 2):
        v = data[i] + (data[i + 1] << 8)
        ms = ms + getHex(v,4) + ", "
    ms = ms[0:-2]
    if len(ms) > 4:
        es = "s"
    print(padText("  Attribute ID" + es) + ms)


def decodeAttributeList(data, start, attType):
    # Decode a ZCL read attribute response
    # Parameters:
    #   1. Array - the frame data as a series of integer values
    #   2. Integer - index of the ZCL data start within the data
    #   3. Integer - the attribute class we're investigating, eg. read response,
    #                write request
    # Returns:
    #   Nothing
    
    index = start
    done = False
    while done is False:
        # Get the next attribute record
        if attType == ATT_TYPE_READ_RSP:
            index = decodeAttribute(data, index)
        elif attType == ATT_TYPE_WRITE_REQ:
            index = decodeAttributeWriteReq(data, index)
        elif attType == ATT_TYPE_WRITE_RSP:
            index = decodeAttributeWriteRsp(data, index)
        if index >= len(data):
            done = True


def decodeAttribute(data, start):
    # Display an attribute's metadata
    # Parameters:
    #   1. Array - the frame data as a series of integer values
    #   2. Integer - index of the start of the attribute record within the data
    # Returns:
    #   The index of the next attribute in the data
    
    index = start
    
    print(padText("  Attribute ID") + getHex(((data[index] << 8) + data[index + 1]), 4))
    print(padText("  Attribute read status") + getZCLAttributeStatus(data[index + 2]))
    print(padText("  Attribute type") + getZCLAttributeType(data[index + 3]))
    
    if data[index + 2] == 0:
        # Now get the attribute data
        index = index + 4 + decodeAttributeData(data, index + 4, data[index + 3])
    else:
        # Attribute access unsuccessful - just skip it
        index = index + 4
        print("  [ERROR] Cannot read attribute data")
    return index


def decodeAttributeData(data, start, dataType):
    # Get the attribute's data
    # Parameters:
    #   1. Array - the frame data as a series of integer values
    #   2. Integer - index of the start of the attribute data within 
    #                the ZCL frame, not the start of the attribute record
    #   3. Integer - the data type of the index
    # Returns:
    #   The number of bytes of data read (ie. how far to move the pointer)
    
    # How many bytes hold the attribute's data?
    if getZCLAttributeSize(dataType) != -1:
        # The data is of a fixed size ('l')
        return decodeValue(data, start, dataType)
    else:
        # The data is not a fixed size
        return decodeCollection(data, start, dataType)
    

def decodeValue(data, start, dataType):
    # Extract and display a single, fixed-size value
    # Parameters:
    #   1. Array - the frame data as a series of integer values
    #   2. Integer - index of the start of the attribute data within the ZCL frame
    #   3. Integer - the data type of the index
    # Returns:
    #   The number of data bytes read
    
    size = 1
    if dataType == 0x10:
        # Handle Boolean values separately
        s = "FORBIDDEN"
        if data[start] == 0x00:
            s = "FALSE"
        else:
            s = "TRUE"
        print(padText("  Attribute value") + s)
    else:  
        # Handle all other numeric values
        size = getZCLAttributeSize(dataType)
        v = 0
        k = 0
        for j in range(start + size - 1, start - 1 , -1):
            v = v + (data[j] << k)
            k = k + 8
        print(padText("  Attribute value") + getHex(v,size))
    return size


def decodeCollection(data, start, dataType):
    # Decode and display a collection value
    # Parameters:
    #   1. Array - the frame data as a series of integer values
    #   2. Integer - index of the start of the attribute or sub-attribute 
    #                data start within the frame 
    #   3. Integer - the data type of the index
    # Returns:
    #   The number of bytes read for the data unit
    
    index = start
    if dataType == 0x41 or dataType == 0x42:
        # Octet or char string
        length = data[index]
        ds = ""
        for j in range(index + 1, index + 1 + length):
            ds = ds + chr(data[j])
        print(padText("  Attribute value") + ds)
        index = index + 1 + length
    elif dataType == 0x43 or dataType == 0x44:
        # Long octet or char string
        length = (data[index] << 8) + data[index + 1]
        ds = ""
        for j in range(index + 2, index + 2 + length):
            ds = ds + chr(data[j])
        print(padText("  Attribute value") + ds)
        index = index + 2 + length
    elif dataType == 0x48 or dataType == 0x50 or dataType == 0x51:
        # Array, Set or Bag - collections of the same type so we need
        # to iterate to read in all the element values
        length = 0
        subType = data[index]
        size = getZCLAttributeSize(data[subType])
        itemCount = (data[index + 1] << 8) + data[index + 2]
        for j in range(0, itemCount):
            # NOTE decodeAttribute() expects to receive the start of the attribute
            #      (ie. header + data) not the start of a collection sub-attribute
            #      (ie. data), so we need to adjust the index back to get the
            #      correct bytes
            # NOTE Ignore the nesting limit for now
            adjustedIndex = index + 3 + (j * size)
            length = length + decodeAttributeData(data, adjustedIndex, subType)
        index = index + 3 + length
    elif type == 0x52:
        # Struct - collection of mixed types, os this is more complex 
        itemCount = (data[index] << 8) + data[index + 1]
        length = 0
        itemLength = 0
        for j in range(0, itemCount):
            adjustedIndex = index + 2 + itemLength
            subType = data[adjustedIndex];
            itemLength = 1 + decodeAttributeData(data, adjustedIndex + 1, subType)
            length = length + itemLength
        index = index + 2 + length
    return index - start


def decodeAttributeWriteReq(data, start):
    # Display an attribute's metadata
    # Parameters:
    #   1. Array - the frame data as a series of integer values
    #   2. Integer - index of the start of the attribute record within the data
    # Returns:
    #   The index of the next attribute in the data
    
    index = start
    print(padText("  Attribute ID") + getHex(((data[index] << 8) + data[index + 1]), 4))
    print(padText("  Attribute type") + getZCLAttributeType(data[index + 2]))
    index = index + 3 + decodeAttributeData(data, index + 3, data[index + 2])
    return index


def decodeAttributeWriteRsp(data, start):
    # Get the attribute's write status and ID
    # Parameters:
    #   1. Array - the frame data as a series of integer values
    #   2. Integer - index of the start of the attribute data within 
    #                the ZCL frame, not the start of the attribute record
    # Returns:
    #   The number of bytes of data read (ie. how far to move the pointer)

    print(padText("  Attribute ID") + getHex(((data[start + 1] << 8) + data[start + 2]), 4))
    print(padText("  Attribute write status") + getZCLAttributeStatus(data[start]))
    return start + 3


def decodeZDO(data, cmd):
    # Decode a ZDO packet
    # Parameters:
    #   1. Array - the frame data as a series of integer values
    #   2. Integer - the 16-bit ZDO command code
    # Returns:
    #   Nothing
     
    cs = getZDOCommand(cmd)
    if cs[0:8] != "[ERROR]":
        print(padText("  ZDO command") + cs)
    else:
        print("[ERROR] ZDO command " + getHex(cmd,4) + " decoding not yet supported")
        return
    print(padText("  Transaction seq. number") + getHex(data[0],2))
    
    if cmd > 0x7FFF:
        # All responses have frame byte 1 set to status
        getZDOStatus(data[1])
    else:
        # All responses after 0x0000 have bytes 1 and 2 as a 16-bit address
        if cmd > 0x0000 and cmd < 0x8000 and cmd != 0x0031 and cmd != 0x0038:
            print(padText("  Address (16-bit)") + getHex(data[1] + (data[2] << 8),4))

    if cmd == 0x0000:
        # 16-bit Network Address Request
        read64bitSserdda(data, 1)
        getZDOType(data[9])
        print(padText("  Start index") + str(data[10]))
    elif cmd == 0x8000 or cmd == 0x8001:
        # 16-bit Address Response / 64-bit Address Response
        read64bitSserdda(data, 2)
        print(padText("  Address (16-bit)") + getHex(data[10] + (data[11] << 8),4))
        
        if len(data) > 12:
            print(padText("  No. of addresses") + getHex(data[12],2))
            print(padText("  Start index") + str(data[13]))
            count = 1
            for i in range(14, 14 + data[12] * 2, 2):
                print(padText("  Address " + str(count)) + getHex(data[i] + (data[i + 1] << 8),4))
    elif cmd == 0x0001:
        # 64-bit Address Request
        getZDOType(data[3])
        print(padText("  Start index") + str(data[4]))
    elif cmd == 0x8002:
        # Node Descriptor Response
        getNodeDescriptor(data, 3)
    elif cmd == 0x0004:
        # Simple descriptor Request
        print(padText("  Endpoint") + str(data[3]))
    elif cmd == 0x8004:
        # Simple Descriptor Response
        getSimpleDescriptor(data, 3)
    elif cmd == 0x0013:
        # ZDO Device Announce
        read64bitSserdda(data, 3)
        print(padText("  Capabilities") + getDeviceCapability(data[11]))
    elif cmd == 0x0031:
        # Management LQI (Neighbor Table) Request
        print(padText("  Start index") + str(data[1]))
    elif cmd == 0x0038:
        # Management Network Update Request
        sd = data[5]
        print(padText("  Scan Duration") + getHex(sd,2))
        if sd < 6:
            print(padText("  Scan Count") + getHex(data[6],2))
        if sd == 0xFE:
            print(padText("  Network update ID") + getHex(data[6],2))
        if sd == 0xFF:
            print(padText("  Network manager address") + getHex(data[6] + (data[7] << 8),2))

###########################################################################
# This section comprises utility functions used by the primary decoders   #
# listed above.                                                           #
###########################################################################

def read64bitAddress(data, start = 4, message = "Address (64-bit)"):
    # Reads the bytes representing a 64-bit address from the passed-in blob.
    # Parameters:
    #   1. Array - the frame data as a series of integer values
    #   2. Integer - the index in the array at which the data is to be found
    #   3. String - optional message prefix
    # Returns:
    #   The 64-bit address as a string of 8 octets
    
    ms = ""
    for i in range(start, start + 8):
        ms = ms + getHex(data[i], 2)
    print(padText(message) + ms)


def read64bitSserdda(data, start = 4):
    # As read64bitAddress(), but returning the address in little endian order
    
    ms = ""
    for i in range(start + 7, start - 1, -1):
        ms = ms + getHex(data[i], 2)
    print(padText("  Address (64-bit)") + ms)


###########################################################################
# This section comprises XBee and Zigbee enumeration decoders used by the #
# primary decoders  listed above.                                         #
###########################################################################

def getSendOptions(code):
    # Decode a Zigbee packet Send options byte and print a relevant status message
    # Parameters:
    #   1. Integer - the status code bitfield included in the packet
    # Returns:
    #   Nothing
    
    ms = ""
    
    if code & 0x01 == 0x01:
        ms = ms + "disable retries and route repair, "
    if code & 0x02 == 0x02:
        ms = ms + "apply changes, "
    if code & 0x20 == 0x20:
        ms = ms + "enable APS encryption, "
    if code & 0x40 == 0x40:
        ms = ms + "use the extended transmission timeout, "
    if len(ms) > 0:
        ms = ms[0:1].upper() + ms[1:-2]
    else:
        ms = "None"

    print(padText("Options") + ms)


def getATStatus(code):
    # Decode an AT command status packet's status byte and print a relevant status message
    # Parameters:
    #   1. Integer - the status code included in the packet
    # Returns:
    #   Nothing
    
    m = [ "OK", "ERROR", "Invalid Command", "Invalid Parameter", "TX Failure"]
    
    for i in range(0, len(m)):
        if code == i:
            print(padText("Command status") + m[code])
            return
    
    print("[Error] Unknown AT status code " + getHex(code,2))


def getModemStatus(code):
    # Decode a modem status packet's status byte and print a relevant status message
    # Parameters:
    #   1. Integer - the status code included in the packet
    # Returns:
    #   Nothing
    
    m = [0x00, "Hardware reset",
         0x01, "Watchdog timer reset",
         0x02, "Joined network",
         0x03, "Disassociated",
         0x06, "Coordinator started",
         0x07, "Network security updated",
         0x0D, "Voltage supply exceeded",
         0x11, "Modem config changed"]
    
    for i in range(0, len(m), 2):
        if code == m[i]:
            print(padText("Modem status") + m[i + 1])
            return
    
    if code >= 0x80:
        print(padText("Modem status") + "Stack Error")
        return
    
    print("[Error] Unknown modem status code " + getHex(code,2))


def getPacketStatus(code):
    # Decode the packet's status byte and print the relevant status message
    # Parameters:
    #   1. Integer - the status code included in the packet
    # Returns:
    #   Nothing
    
    ms = ""
    
    if code == 0x00:
        ms = "packet mot acknowledged, "
    if code & 0x01:
        ms = ms + "packet acknowledged, "
    if code & 0x02:
        ms = ms + "broadcast packet, "
    if code & 0x20:
        ms = ms + "APS-encrypted packet, "
    if code & 0x40:
        ms = ms + "End-Device sent packet, "
    
    ms = ms[0:1].upper() + ms[1:-2]
    print(padText("Status") + ms)


def getDeliveryStatus(code):
    # Decode the packet's address delivery status byte and print the relevant status message
    # Parameters:
    #   1. Integer - the status code included in the packet
    # Returns:
    #   Nothing
    
    m = [0x00, "Success",
         0x01, "MAC ACK Failure",
         0x02, "CCA Failure",
         0x15, "Invalid Destination Endpoint",
         0x21, "Network ACK Failure",
         0x22, "Not Joined to Network",
         0x23, "Self-addressed",
         0x24, "Address Not Found",
         0x25, "Route Not Found",
         0x26, "Broadcast Source Failed to Hear a Neighbour Relay the Message",
         0x2B, "Invalid Binding Table Index",
         0x2C, "Resource Error: Lack of Free Buffers, Timers etc",
         0x2D, "Attempted Broadcast with APS Transmission",
         0x2E, "Attempted Unicast with APS Transmission, but EE=0",
         0x32, "Resource Error: Lack of Free Buffers, Timers etc",
         0x74, "Data Payload Too Large",
         0x75, "Indirect Message Unrequested"]
    
    for i in range(0, len(m), 2):
        if code == m[i]:
            print(padText("Delivery status") + m[i + 1])
            return
    
    print("[ERROR] Unknown Delivery status code " + getHex(code,2))


def getDiscoveryStatus(code):
    # Decode the packet's address discovery status byte and print the relevant status message
    # Parameters:
    #   1. Integer - the status code included in the packet
    # Returns:
    #   Nothing
    
    m = [ "No Discovery Overhead", "Address Discovery", "Route Discovery", "Address and Route"]
    
    if code > -1 and code < 4:
        print(padText("Discovery status") + m[code])
    else:
        print("[ERROR] Unknown Discovery status code " + getHex(code,2))


def getZCLAttributeStatus(code):
    # Decode the status of a ZCL attribute access operation
    # Parameters:
    #   1. Integer - the status code included in the packet
    # Returns:
    #   The status message string
    
    m = [0x00, "Success",
         0x01, "Failure",
         0x7e, "Not authorized",
         0x7f, "Reserved field not zero",
         0x80, "Malformed command",
         0x81, "Unsupported cluster command",
         0x82, "Unsupported general command",
         0x83, "Unsupported manufacturer's cluster command",
         0x84, "Unsupported manufacturer's general command",
         0x85, "Invalid field",
         0x86, "Unsupported attribute",
         0x87, "Invalid value",
         0x88, "Read only",
         0x89, "Insufficient space",
         0x8a, "Duplicate exists",
         0x8b, "Not found",    
         0x8c, "Unreportable attribute", 
         0x8d, "Invalid data type",
         0x8e, "Invalid selector", 
         0x8f, "Write only", 
         0x90, "Not found", 
         0x91, "Not found",
         0x92, "Read only",
         0x93, "Insufficient space",
         0x94, "Duplicate exists",
         0x95, "Not found",    
         0x96, "Unreportable attribute", 
         0x97, "Invalid data type",
         0x98, "Invalid selector", 
         0x99, "Write only", 
         0x9a, "Not found", 
         0xc0, "Not found",   
         0xc1, "Not found",   
         0xc2, "Not found",   
         0xc3, "Not found"]
    
    for i in range(0, len(m), 2):
        if code == m[i]:
            return m[i + 1]
    return "Unknown"


def getZCLAttributeType(code):
    # Determine a ZCL attribute's data type from its type code
    # Parameters:
    #   1. Integer - the ZCL data type code included in the packet
    # Returns:
    #   The data type as a string
    
    m = [0x00, "NULL",
         0x08, "DATA8",
         0x09, "DATA16",
         0x0a, "DATA24",
         0x0b, "DATA32",
         0x0c, "DATA40",
         0x0d, "DATA48",
         0x0e, "DATA56",
         0x0f, "DATA64",
         0x10, "BOOL",
         0x18, "MAP8",
         0x19, "MAP16",
         0x1a, "MAP24",
         0x1b, "MAP32",
         0x1c, "MAP40",
         0x1d, "MAP48",    
         0x1e, "MAP56", 
         0x1f, "MAP64",
         0x20, "UINT8", 
         0x21, "UINT16", 
         0x22, "UINT24", 
         0x23, "UINT32",
         0x24, "UINT40",
         0x25, "UNIT48",
         0x26, "UNIT56",
         0x27, "UINT64",    
         0x28, "INT8", 
         0x29, "INT16", 
         0x2a, "INT24", 
         0x2b, "INT32",
         0x2c, "INT40",
         0x2d, "NIT48",
         0x2e, "NIT56",
         0x2f, "INT64", 
         0x30, "ENUM8", 
         0x31, "ENUM16", 
         0x38, "SEMI", 
         0x39, "SINGLE",
         0x3a, "DOUBLE",   
         0x41, "OCTSTR",   
         0x42, "STRING",   
         0x43, "OCTSTR16",
         0x44, "STRING16", 
         0x48, "ARRAY", 
         0x4c, "STRUCT",
         0x50, "SET",
         0x51, "BAG",
         0xe0, "ToD",
         0xe1, "DATE",    
         0xe2, "UTC", 
         0xe8, "CLUSTERID", 
         0xe9, "ATTRID", 
         0xea, "BACOID",
         0xf0, "EUI64",
         0xf1, "KEY128",
         0xff, "UNK"]
    
    for i in range(0, len(m), 2):
        if code == m[i]:
            return m[i + 1]
    return "OPAQUE"


def getZCLAttributeSize(code):
    # Determine the number of bytes a given ZCL attribute takes up
    # Parameters:
    #   1. Integer - the attribute size code included in the packet
    # Returns:
    #   The size of the attribute data in bytes, or -1 for error/no size
    
    m = [   0x00, 0,
            0x08, 1,
            0x09, 2,
            0x0a, 3,
            0x0b, 4,
            0x0c, 5,
            0x0d, 6,
            0x0e, 7,
            0x0f, 8,
            0x10, 1,
            0x18, 1,
            0x19, 2,
            0x1a, 3,
            0x1b, 4,
            0x1c, 5,
            0x1d, 6,    
            0x1e, 7, 
            0x1f, 8,
            0x20, 1, 
            0x21, 2, 
            0x22, 3, 
            0x23, 4,
            0x24, 5,
            0x25, 6,
            0x26, 7,
            0x27, 8,    
            0x28, 1, 
            0x29, 3, 
            0x2a, 3, 
            0x2b, 4,
            0x2c, 5,
            0x2d, 6,
            0x2e, 7,
            0x2f, 8, 
            0x30, 1, 
            0x31, 2, 
            0x38, 2,
            0x38, 4, 
            0x39, 8,   
            0x41, -1,   
            0x42, -1,   
            0x43, -1,
            0x44, -1, 
            0x48, -1, 
            0x4c, -1,
            0x50, -1,
            0x51, -1,
            0xe0, 4,
            0xe1, 4,    
            0xe2, 4, 
            0xe8, 2, 
            0xe9, 2, 
            0xea, 4,
            0xf0, 8,
            0xf1, 16,
            0xff, 0]
    
    for i in range(0, len(m), 2):
        if code == m[i]:
            return m[i + 1]
    return -1


def getZDOCommand(code):
    # Display a ZDO request or response command name
    # Parameters:
    #   1. Integer - the ZDO command code included in the packet
    # Returns:
    #   The command name string
    
    m = [ "16-bit Address", 0x0000,
          "64-bit Address", 0x0001,
          "Node Descriptor", 0x0002,
          "Simple Descriptor", 0x0004,
          "Active Endpoints", 0x0005,
          "Match Descriptor", 0x0006,
          "Complex Descriptor", 0x0010,
          "User Descriptor", 0x0011,
          "Device Announce", 0x0013,
          "User Descriptor Set", 0x0014,
          "Management Network Discovery", 0x0030,
          "Management LQI (Neighbor Table)", 0x0031,
          "Management RTG (Routing Table)", 0x0032,
          "Management Leave", 0x0034,
          "Management Permit Join", 0x0036,
          "Management Network Update", 0x0038 ]
    
    for i in range(0, len(m), 2):
        # Look at the lower bits for comparison as bit 15 is what
        # distinguishes responses (set) from requests (unset)
        if code & 0x7FFF == m[i + 1]:
            # Append the appropriate message type
            if code > 0x7FFF:
                return (m[i] + " Response")
            else:
                return (m[i] + " Request")
    return ("[ERROR] Unknown ZDO command " + getHex(code,4))


def getZDOType(code):
    # Display the ZDO request type as embedded in the request
    # Parameters:
    #   1. Integer - the request type code included in the packet
    # Returns:
    #   Nothing
    
    if code == 0x00:
        print(padText("  Request type") + "Single device response")
    elif code == 0x01:
        print(padText("  Request type") + "Extended response")
    else:
        print("[ERROR] Unknown ZDO request type " + getHex(code,2))


def getZDOStatus(code):
    # Display the ZDO status code embedded in the response
    # Parameters:
    #   1. Integer - the status code included in the packet
    # Returns:
    #   Nothing
    
    print(padText("  Response status") + getZCLAttributeStatus(code))


def getNodeDescriptor(data, start):
    # Display the ZDO Node Descriptor response
    # Parameters:
    #   1. Array - the packet data
    #   2. Integer - the index of the start of the descriptor
    # Returns:
    #   Nothing
    
    # Node Descriptor Byte 1
    logType = (data[start] & 0xE0) >> 5
    getDeviceType(logType)
    if data[start] & 0x10 == 0x10:
        print(padText("  Complex descriptor available") + "Yes")
    else:
        print(padText("  Complex descriptor available") + "No")
    if data[start] & 0x08 == 0x08:
        print(padText("  User descriptor available") + "Yes")
    else:
        print(padText("  User descriptor available") + "No")

    # Byte 2
    s = getBinary(data[start + 1])
    print(padText("  APS flags") + "b" + s[0:3])
    m = ["868MHz", "R", "900MHz", "2.4GHz", "R"]
    fs = ""
    for i in range(3,8):
        if s[i] == "1":
            fs = m[i - 3]
    if fs == "R":
        fs = "[ERROR] Reserved band indicated"
    print(padText("  Frequency band") + fs)

    # Byte 3
    fs = getDeviceCapability(data[start + 2])
    print(padText("  MAC capabilities") + fs)

    # Bytes 4 and 5
    print(padText("  Manufacturer ID") + getHex(data[start + 3] + (data[start + 4] << 8),4))

    # Byte 6
    print(padText("  Max. buffer size") + getHex(data[start + 5],2))

    # Bytes 7 and 8
    print(padText("  Max. incoming transfer size") + getHex(data[start + 6] + (data[start + 7] << 8)),4)

    # Bytes 9 and 10
    print(padText("  Server mask") + getHex(data[start + 8] + (data[start + 9] << 8)),4)

    # Bytes 11 and 12
    print(padText("  Max. outgoing transfer size") + getHex(data[start + 10] + (data[start + 11] << 8)),4)

    # Byte 13
    fs = ""
    if data[start + 12] & 0x80 == 0x80:
        fs = "extended active endpoint list available, "
    if data[start + 12] & 0x40 == 0x40:
        fs = fs + "extended simple descriptor list available, "
    fs = fs[0:1].upper() + fs[1:-2]
    if len(fs) > 0:
        print(padText("  Descriptor capability field") + fs)
    else:
        print(padText("  Descriptor capability field") + "No bits set")


def getSimpleDescriptor(data, start):
    # Display the ZDO Simple Descriptor response
    # Parameters:
    #   1. Array - the packet data
    #   2. Integer - the index of the start of the descriptor
    # Returns:
    #   Nothing

    print(padText("  Endpoint") + getHex(data[start],2))
    print(padText("  App profile ID") + getHex(data[start + 1] + (data[start + 2] << 8),4))
    print(padText("  App device ID") + getHex(data[start + 3] + (data[start + 4] << 8),4))
    print(padText("  App device version") + getHex((data[start + 5] >> 4),2))
    
    count = data[start + 6]
    print(padText("  Input cluster count") + getHex(count,2))
    if count != 0:
        # Display the list of input clusters
        fs = ""
        for i in range (7, 7 + (count * 2), 2):
            fs = fs + getHex(data[i] + (data[i + 1] << 8), 4) + ", "
        print(padText("  Input clusters") + fs[0:-2])
        start = start + (count * 2)
    
    count = data[start + 7]
    print(padText("  Output cluster count") + getHex(count,2))
    if count != 0:
        # Display the list of output clusters
        fs = ""
        for i in range (7, 7 + (count * 2), 2):
            fs = fs + getHex(data[i] + (data[i + 1] << 8), 4) + ", "
        print(padText("  Output clusters") + fs[0:-2])


def getDigitalChannelMask(data, start):
    # Determine and report which, if any, XBee digital IOs have been enabled
    # for sampling and include the sample digital data
    # Parameters:
    #   1. Array - the current frame data
    #   2. Integer - the index in the data of the digital channel info
    # Returns:
    #   Nothing

    nd = (data[start] << 8) + data[start + 1]
    sd = (data[start + 3] << 8) + data[start + 4]
    m = ["DIO0", "DIO1", "DIO3", "DIO4", "DIO5", "DIO6", "DIO7",
         "N/A", "N/A", "DIO10", "DIO11", "DIC12", "N/A", "N/A", "N/A"]
    ms = ""
    bad = False
    
    for i in range(0,16):
        v = int(math.pow(2,i))
        if nd & v == v:
            # Digital IO enabled
            ms = ms + m[i]
            
            # Is the IO permitted?
            if m[i] == "N/A":
                bad = True
            else:
                # Is the sample HIGH or LOW?
                if sd & v == v:
                    ms = ms + " (HIGH), "
                else:
                    ms = ms + " (LOW), "
    
    if len(ms) > 0:
        # Remove the final comma and space from the message string
        ms = ms[0:-2]
    else:
        ms = "None"
    
    print(padText("Enabled Digital IOs") + ms)
    if bad is True:
        print("[ERROR] Unavailable Digital IOs selected")


def getAnalogChannelMask(data, start):
    # Determine and report which, if any, XBee analog IOs have been enabled
    # for sampling and so have supplied data in the current frame
    # Parameters:
    #   1. Array - the current frame data
    #   2. Integer - the index in the data of the analog sample data
    # Returns:
    #   Nothing

    code = data[18]
    m = ["AD0", "AD1", "AD2", "AD3", "N/A", "N/A", "N/A", "VIN"]
    ms = ""
    bad = False
    count = 0
    
    for i in range(0,8):
        v = int(math.pow(2,i))
        if code & v == v:
            # Analog IO enabled
            ms = ms + m[i]
            if m[i] == "N/A":
                bad = True
            else:
                # Read the sample value and add to the display string
                s = (data[start + count] << 8) + data[start + 1 + count]
                ms = ms + " (" + getHex(s,4) + "), "
                count = count + 2
    
    if len(ms) > 0:
        # Remove the final comma and space from the message string
        ms = ms[0:-2]
    else:
        ms = "None"
    
    print(padText("Enabled Analog IOs") + ms)
    if bad is True:
        print("[ERROR] Unavailable Analog IOs selected")


def getOneWireStatus(code):
    # Determine and display an XBee's OneWire sensor status, if enabled
    # Parameters:
    #   1. Integer - the status code included in the packet
    # Returns:
    #   Nothing

    m = ["A/D sensor read", 0x01, "temperature sensor read", 0x02, "water present", 0x60]
    
    ms = ""
    for i in range(0, len(m), 2):
        if code & m[i + 1] == m[i + 1]:
            ms = ms + m[i] + ", "
    
    # Remove the final comma and space from the message string
    ms = ms[0:1].upper() + ms[1:-2]
    print(padText("OneWire sensor status") + ms)


def getDeviceType(code):
    # Determine the device type embedded in a Node Ident packet
    # Parameters:
    #   1. Integer - the type code included in the packet
    # Returns:
    #   Nothing

    m = ["Coordinator", "Router", "End Device"]
    if code < 0 or code > 2:
        print("[ERROR] Unknown Node Identification device type " + str(code))
    else:
        print(padText("Device type") + m[code])


def getSourceEvent(code):
    # Determine the device type embedded in a Node Ident packet
    # Parameters:
    #   1. Integer - the event source code included in the packet
    # Returns:
    #   Nothing

    m = ["AT command \"ND\" issued", "Button pushed", "Network join", "Device power-cycle"]
    if code < 0 or code > 3:
        print("[ERROR] Unknown Node Identification event type " + str(code))
    else:
        print(padText("Source event") + m[code])


def getBootloaderMessage(code):
    # Determine the bootloader message embedded in a firmware update packet
    # Parameters:
    #   1. Integer - the message code included in the packet
    # Returns:
    #   Nothing

    m = ["ACK", 0x06, "NACK", 0x15, "No MAC ACK", 0x40,
         "Query - Bootload not active", 0x51, "Query response", 0x52]
    for i in range(0, len(m), 2):
        if code == m[i + 1]:
            print(padText("Bootloader message") + m[i])
            return
    print("[ERROR] Unknown Firmware Update Bootloader message value " + getHex(code, 2))


def getDeviceCapability(code):
    # Determine the device capability data embedded in a device announce packet
    # Parameters:
    #   1. Integer - the message code included in the packet
    # Returns:
    #   String - the capability list

    m = ["alternate PAN Coordinator", "device type", "power source", "receiver on when idle", "R", "R", "security capable", "allocate address"]
    fs = ""
    for i in range(0,8):
        if (code & (1 << i)) == (1 << i):
            if m[i] == "R":
                fs = fs + "reserved function, "
            else:
                fs = fs + m[i] + ", "
    fs = fs[0:1].upper() + fs[1:-2]
    return fs
    
 
###########################################################################
# This section comprises generic utility functions used by all parts of   #
# the program                                                             #
###########################################################################

def getHex(v, d):
    # Convert the integer 'v' to a hex string of 'd' characters
    # prefix-padding as required
    # Parameters:
    #   1. Integer - the value to be converted
    #   2. Integer - the number of characters the final string should comprise
    # Returns:
    #   String - the hex characters

    s = "{:0" + str(d) + "X}"
    return s.format(v)


def prefix(s):
    # prefix-padding as required
    # Parameters:
    #   1. String - the source hex string
    # Returns:
    #   String - the hex string with or without a prefix
    
    global prefixed
    
    if prefixed is True:
        return "0x" + s
    else:
        return s


def padText(s, e = True):
    # Pad the end of the passed string 's' with spaces up to a maximum
    # indicated by 'TEXT_SIZE' and, if 'e' is True, append ": "
    # Parameters:
    #   1. String - the string to be padded
    #   2. Boolean - should the returned string be tailed with ": "
    # Returns:
    #   String
    
    l = TEXT_SIZE - len(s)
    t = s + SPACE_STRING[0:l]
    if e is True:
        t = t + ": "
    return t


def getBinary(value):
    # Convert an 8-bit value to a binary string of 1s and 0s
    # Parameters:
    #   1. Integer - the value to be converted
    # Returns:
    #   String
    
    bs = ""
    for i in range(0,8):
        bit = int(math.pow(2,i))
        bs = ("1" if (value & bit) == bit else "0") + bs
    return bs


def showHelp():
    showVersion()
    print("Usage:")
    print("  python xbp.py <XBee packet hex string>")
    print("\nThe XBee packet string must not contains spaces.\n")
    print("Options:")
    print("  -e / --escape <true/false> - Use escaping when decoding packets. Default: true")
    print("  -d / --debug <true/false>  - Show extra debug information. Default: false")
    print("  -v / --version             - Show version information")
    print("  -h / --help                - Show help information\n")


def showVersion():
    print("\nXBeeParser version " + APP_VERSION)
    print("Copyright (c) Tony Smith (@smittytone) 2018")
    print("Licence: MIT <https://github.com/smittytone/XBeeParser/blob/master/LICENSE>\n")
    

###########################################################################
# The main entry point. Here we decode the options (if any) selected by   #
# the user, and the Xbee packet data provided via the command line        #
###########################################################################

if __name__ == '__main__':    
    if len(sys.argv) > 1:
        # Run through the args to find options only
        i = 1
        fs = ""
        done = False
        while done is False:
            c = sys.argv[i]
            if c == "-v" or c == "--version":
                # Print the version
                showVersion()
                i = i + 1
            elif c == "-h" or c == "--help":
                # Print help
                showHelp()
                i = i + 1
            elif c == "-e" or c == "--escape":
                # Are we escaping?
                if i < len(sys.argv) - 1:
                    v = sys.argv[i + 1]
                    if v == "true" or v == "yes" or v == "1":
                        escaped = True
                        print("Packet decoding will use escaping")
                    elif v == "false" or v == "no" or v == "0":
                        escaped = False
                        print("Packet decoding will not use escaping")
                    else:
                        print("[ERROR] bad argument for -e/--escape: " + v)
                        sys.exit(0)
                    i = i + 2
                else:
                    print("[ERROR] missing argument for -e/--escape")
                    sys.exit(0)
            elif c == "-p" or c == "--prefix":
                # Are we prefixing?
                if i < len(sys.argv) - 1:
                    v = sys.argv[i + 1]
                    if v == "true" or v == "yes" or v == "1":
                        prefixed = True
                        print("Hex values will be prefixed with 0x")
                    elif v == "false" or v == "no" or v == "0":
                        prefixed = False
                        print("Hex values will not be prefixed with 0x")
                    else:
                        print("[ERROR] bad argument for -e/--escape: " + v)
                        sys.exit(0)
                    i = i + 2
                else:
                    print("[ERROR] missing argument for -p/--prefix")
                    sys.exit(0)
            elif c == "-d" or c == "--debug":
                # Are we debugging?
                if i < len(sys.argv) - 1:
                    v = sys.argv[i + 1]
                    if v == "true" or v == "yes" or v == "1":
                        debug = True
                        print("Extra debugging information will be printed during decoding")
                    elif v == "false" or v == "no" or v == "0":
                        debug = False
                    else:
                        print("[ERROR] bad argument for -d/--debug: " + v)
                        sys.exit(0)
                    i = i + 2
                else:
                    print("[ERROR] missing argument for -d/--debug")
                    sys.exit(0)
            elif c[0] == "-":
                # Mis-formed option
                print("[ERROR] unrecognized option: " + c)
                sys.exit(0)
            else:
                i = i + 1
            if i >= len(sys.argv):
                done = True
        
        # Run through the args to find the packet data and process it
        # NOTE We do it this was so that we take into account options
        #      placed after the packet
        skip = False
        for i in range(1, len(sys.argv)):
            if skip is False:
                c = sys.argv[i]
                if c[0] != "-":
                    fs = fs + c
                else:
                    skip = True
            else:
                skip = False
        if len(fs) > 8:
            # Frame has to have at least four octets
            processPacket(fs)
    else:
        print("[ERROR] No Data provided")
    sys.exit(0)
