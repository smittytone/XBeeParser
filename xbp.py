#!/usr/bin/env python

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
XBEE_CMD_ROUTE_RECORD_INDICATOR             = 0xA1
XBEE_CMD_MANY_TO_ONE_ROUTE_REQ_INDICATOR    = 0xA2
XBEE_CMD_OTA_FIRMWARE_UPDATE_STATUS         = 0xA0

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

##########################################################################
# Application-specific constants                                         #
##########################################################################

# App Constants
TEXT_SIZE = 30
SPACE_STRING = "                                                             "
APP_VERSION = "0.0.1"

# ZCL Global Commands
zclCmds = ["Read Attributes", "Read Attributes Response", "Write Attributes", "Write Attributes Undivided",
           "Write Attributes Response", "Write Attributes No Response", "Configure Reporting", "Configure Reporting Response",
           "Read Reporting Configuration", "Read Reporting Configuration Response", "Report Attributes", "Default Response",
           "Discover Attributes", "Discover Attributes Response"]


##########################################################################
# Application globals                                                    #
##########################################################################

escaped = True
debug = False


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
        print("[ERROR] Packet data does not contain an even number of characters")
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
        print("[ERROR] Packet data does not start with an XBee signature (" + getHex(values[0],2) + ")")
        return
    
    # Test the checksum value (the last byte in the packet)
    checksum = values[len(values) - 1]
    cs = 0
    for i in range(3, len(values)):
        cs = cs + values[i]
    cs = cs & 0xFF
    if cs != 0xFF:
        print("[ERROR] Packet checksum test failed")
        return

    # Display the frame data length
    length = values[1] * 256 + values[2]
    print(padText("Frame length") + str(length) + " bytes")

    # Look for XBee frame types and decode the data individually
    cmd = values[3]
    if cmd == XBEE_CMD_AT:
        decodeSendATCommand(values) #DONE
    elif cmd == XBEE_CMD_QUEUE_PARAM_VALUE:
        decodeParamQueue(values) #DONE
    elif cmd == XBEE_CMD_ZIGBEE_TRANSMIT_REQ:
        decodeZigbeeTransitReq(values) #DONE
    elif cmd == XBEE_CMD_EXP_ADDR_ZIGBEE_CMD_FRAME:
        decodeExplicitZigbeeCommand(values) #DONE
    elif cmd == XBEE_CMD_REMOTE_CMD_REQ:
        deviceRemoteCmdReq(values)
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
        decodeZigbeeDataSampleRXIndicator(values)
    elif cmd == XBEE_CMD_XBEE_SENSOR_READ_INDICATOR:
        decodeXBeeSensorReadIndicator(values)
    elif cmd == XBEE_CMD_NODE_ID_INDICATOR:
        decodeNodeIDIndicator(values)
    elif cmd == XBEE_CMD_REMOTE_CMD_RESPONSE:
        decodeRemoteATCommand(values) #DONE
    elif cmd == XBEE_CMD_ROUTE_RECORD_INDICATOR:
        decodeRouteRecordIndicator(values)
    elif cmd == XBEE_CMD_MANY_TO_ONE_ROUTE_REQ_INDICATOR:
        decodeManyToOneRouteIndicator(values) #DONE
    else:
        print("[ERROR] Unknown frame type: " + getHex(values[3],2))
        return


##########################################################################
# This section comprises starting points for specific XBee packet types. #
##########################################################################

def decodeSendATCommand(data):
    # The Xbee is sending an XBee AT command packet (frame ID 0x08)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing
    print(padText("XBee Command ID") + getHex(data[3],2) + " - \"Issue local AT command\"")
    print(padText("XBee Frame ID") + getHex(data[4],2))
    print(padText("XBee AT Command") + "\"" + chr(data[5]) + chr(data[6]) + "\"")
    
    ds = ""
    l = (data[1] << 8) + data[2] - 4
    if l > 0:
        for i in range(7, 7 + l):
            ds = ds + getHex(data[i],2)
    else:
        ds = "None"
    print(padText("Command parameter value") + ds)


def decodeParamQueue(data):
    # The Xbee is queing an XBee AT command packet (frame ID 0x09)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing
    print(padText("XBee Command ID") + getHex(data[3],2) + " - \"Queue parameter value\"")
    print(padText("XBee Frame ID") + getHex(data[4],2))
    print(padText("XBee AT Command") + "\"" + chr(data[5]) + chr(data[6]) + "\"")
    
    ds = ""
    l = (data[1] << 8) + data[2] - 4
    if l > 0:
        for i in range(7, 7 + l):
            ds = ds + getHex(data[i],2)
    else:
        ds = "Read queued"
    print(padText("Command parameter value") + ds)


def decodeZigbeeTransitReq(data):
    # The Xbee has issues a basic Zigbee command (frame ID 0x10)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   
    print(padText("XBee Command ID") + getHex(data[3],2) + " - \"Zigbee transmit request\"")
    print(padText("XBee Frame ID") + getHex(data[4],2))
    read64bitAddress(data, 5)
    print(padText("Address (16-bit)") + getHex(((data[13] << 8) + data[14]),4))
    print(padText("Radius") + getHex(data[15],2))
    getSendOptions(data[16])
    ds = ""
    l = (data[1] << 8) + data[2] - 14
    if l > 0:
        for i in range(17, 17 + l):
            ds = ds + getHex(data[i],2)
        print(padText("Data bytes (" + str(l) + ")") + ds)


def decodeExplicitZigbeeCommand(data):
    # The Xbee has received a many-to-one routing info packet (frame ID 0xA2)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   
    print(padText("XBee Command ID") + getHex(data[3],2) + " - \"Send Zigbee packet\"")
    print(padText("Frame ID") + getHex(data[4],2))
    read64bitAddress(data, 5)
    print(padText("Address (16-bit)") + getHex(((data[13] << 8) + data[14]),4))
    print(padText("Source endpoint") + getHex(data[15],2))
    print(padText("Destination endpoint") + getHex(data[16],2))
    
    cid = (data[17] << 8) + data[18]
    print(padText("ClusterID") + getHex(cid,4))
    
    pid = (data[19] << 8) + data[20]
    print(padText("ProfileID") + getHex(pid,4))
    
    print(padText("Radius") + getHex(data[21],2))
    getSendOptions(data[22])
    
    ds = ""
    dv = []
    l = (data[1] << 8) + data[2] - 20
    if l > 0:
        for i in range(23, 23 + l):
            ds = ds + getHex(data[i],2)
            dv.append(data[i])
        print(padText("Frame data") + ds)
        if pid == 0x0000:
            # ZDO operation
            decodeZDO(dv, cid)
        else:
            decodeZCLFrame(dv)

        
def decodeATResponse(data):
    # The Xbee has received an XBee AT response packet (frame ID 0x88)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing
    print(padText("XBee Command ID") + getHex(data[3],2) + " - \"Local AT command response\"")
    print(padText("XBee Frame ID") + getHex(data[4],2))
    print(padText("XBee AT Command") + chr(data[5]) + chr(data[6]))
    getATStatus(data[7])
    ds = ""
    dv = []
    l = (data[1] << 8) + data[2] - 5
    if l > 0:
        for i in range(8, 8 + l):
            ds = ds + getHex(data[i],2)
            dv.append(data[i])
        print(padText("Frame data") + ds)


def decodeRemoteATCommand(data):
    # The Xbee has received an XBee remote AT response packet (frame ID 0x97)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing
    print(padText("XBee Command ID") + getHex(data[3],2) + " - \"Remote AT command response\"")
    print(padText("XBee Frame ID") + getHex(data[4],2))
    print(padText("XBee AT Command") + chr(data[15]) + chr(data[16]))
    read64bitAddress(data, 5)
    print(padText("Address (16-bit)") + getHex(((data[13] << 8) + data[14]),4))
    getATStatus(data[17])
    ds = ""
    dv = []
    l = (data[1] << 8) + data[2] - 5
    if l > 0:
        for i in range(18, 18 + l):
            ds = ds + getHex(data[i],2)
            dv.append(data[i])
        print(padText("Frame data") + ds)


def decodeModemStatus(data):
    # The Xbee has received an XBee model status packet (frame ID 0x8A)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing
    print(padText("XBee Command ID") + getHex(data[3],2) + " - \"Modem status\"" )
    getModemStatus(data[4])


def decodeZigbeeReceivePacket(data):
    # The Xbee has received an XBee remote AT response packet (frame ID 0x97)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing
    print(padText("XBee Command ID") + getHex(data[3],2) + " - \"Remote Zigbee response\"")
    read64bitAddress(data, 4)
    print(padText("Address (16-bit)") + getHex(((data[13] << 8) + data[14]),4))
    getPacketStatus(data[14])
    ds = ""
    dv = []
    l = (data[1] << 8) + data[2] - 12
    if l > 0:
        for i in range(15, 15 + l):
            ds = ds + getHex(data[i],2)
            dv.append(data[i])
        print(padText("Frame data") + ds)


def decodeZigbeeTransmitStatus(data):
    # The Xbee has received an Zigbee transmit status packet (frame ID 0x8B)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing
    print(padText("XBee Command ID") + getHex(data[3],2) + " - \"Zigbee transmit status\"")
    print(padText("XBee Frame ID") + getHex(data[4],2))
    print(padText("Address (16-bit)") + getHex(((data[5] << 8) + data[6]),4))
    
    if data[7] == 0:
        print(padText("Retries") + "None")
    else:
        print(padText("Retries") + str(data[7]))

    getDeliveryStatus(data[8])
    getDiscoveryStatus(data[9])


def decodeZigbeeRXIndicator(data):
    # The Xbee has received a Zigbee ZCL packet (frame ID 0x91)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing
    print(padText("Frame command") + getHex(data[3],2))
    read64bitAddress(data, 4)
    print(padText("Address (16-bit)") + getHex(((data[12] << 8) + data[13]),4))
    print(padText("Source endpoint") + getHex(data[14],2))
    print(padText("Destination endpoint") + getHex(data[15],2))
    
    cid = (data[16] << 8) + data[17]
    print(padText("ClusterID") + getHex(cid,4))
    
    pid = (data[18] << 8) + data[19]
    print(padText("ProfileID") + getHex(pid,4))
    
    getPacketStatus(data[20])
    
    ds = ""
    dv = []
    l = (data[1] << 8) + data[2] - 18
    if l > 0:
        for i in range(21, 21 + l):
            ds = ds + getHex(data[i],2)
            dv.append(data[i])
        print(padText("Frame data") + ds)
        
        if pid == 0x0000:
            decodeZDO(dv, cid)
        else:
            decodeZCLFrame(dv)


def decodeManyToOneRouteIndicator(data):
    # The Xbee has received a many-to-one routing info packet (frame ID 0xA2)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing
    print(padText("Frame command") + getHex(data[3],2))
    read64bitAddress(data, 4)
    print(padText("Address (16-bit)") + getHex(((data[12] << 8) + data[13]),4))


###########################################################################
# This section comprises decoders for Zigbee data sent or received via an #
# XBee. This covers Zigbee Cluster Library (ZCL) frames, and Zigbee       #
# Device Objects (ZDO) entities
##########################################################################

def decodeZCLFrame(frameData):
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing
    
    global zclCmds
    
    manSpec = False
    globalCmd = True

    # Decode and display the frame control byte
    fc = frameData[0]
    fcs = ""
    for i in range(0,8):
        if i == 1 or i > 4:
            fcs = "0" + fcs
            continue
        v = int(math.pow(2,i))
        if fc & v == v:
            fcs = "1" + fcs
        else:
            fcs = "0" + fcs

    print(padText("  Frame Control Byte") + getHex(fc,2) + " [b" + fcs + "]")
    
    if fc & 0x01 == 0x01:
        print(SPACE_STRING[0:TEXT_SIZE] + "  Command is specific to cluster")
        globalCmd = False
    else:
        print(SPACE_STRING[0:TEXT_SIZE] + "  Command is global to ZCL")

    if fc & 0x08 == 0:
        print(SPACE_STRING[0:TEXT_SIZE] + "  Direction: Client to Server")
    else:
        print(SPACE_STRING[0:TEXT_SIZE] + "  Direction: Server to Client")

    if fc & 0x04 == 0x04:
        print(SPACE_STRING[0:TEXT_SIZE] + "  Manufacturer-specific commands in data")
        manSpec = True
    else:
        print(SPACE_STRING[0:TEXT_SIZE] + "  No manufacturer-specific commands in data")

    if fc & 0x10 == 0x10:
        print(SPACE_STRING[0:TEXT_SIZE] + "  Default Response disabled")
    else:
        print(SPACE_STRING[0:TEXT_SIZE] + "  Default Response enabled")
    
    index = 1
    if manSpec is True:
        mc = (frameData[3] << 8) + frameData[4]
        print(padText("  Manufacturer code") + getHex(mc,4))
        index = 5
    
    # Decode and display the ZCL frame header's remaining two bytes
    tr = frameData[index]
    ci = frameData[index + 1]

    print(padText("  Transaction Number") + getHex(tr,2))
    
    if fc & 0x01 == 0:
        print(padText("  Global Command") + getHex(ci,2) + " - " + zclCmds[ci])
    else:
        print(padText("  Cluster Command") + getHex(ci,2))

    # Payload is at 'index' + 2
    if globalCmd is True:
        # Only decode global commands for now
        decodeZCLCommand(ci, index + 2, frameData)
    else:
        # Dump the data, which contains Cluster-specific info
        ds = ""
        for i in range(index, len(frameData)):
            ds = ds + getHex(frameData[i],2)
        print(padText("  Data") + ds)


def decodeZCLCommand(cmd, start, data):
    # Jump table for general ZCL commands
    if cmd == ZCL_GLOBAL_CMD_READ_ATTR_REQ:
        decodeZCLReadAttReq(start, data)
    elif cmd == ZCL_GLOBAL_CMD_READ_ATTR_RSP:
        decodeZCLReadAttRsp(start, data)
    elif cmd == ZCL_GLOBAL_CMD_WRITE_ATTR_REQ:
        decodeZCLWriteAttReq(start, data)
    elif cmd == ZCL_GLOBAL_CMD_WRITE_ATTR_RSP:
        decodeZCLWriteAttRsp(start, data)


def decodeZCLReadAtts(start, data):
    for i in range(start, len(data), 2):
        v = (data[i] << 8) + data[i + 1]
        print(padText("  Attribute ID") + getHex(v,4))


def decodeZCLReadAttRsp(start, data):
    i = start
    done = False
    while done is False:
        id = data[i] + (data[i + 1] << 8)
        print(padText("  Attribute ID") + getHex(id,4))
        print(padText("  Attribute Status") + getZCLAttributeStatus(data[i + 2]))
        if data[i + 2] == 0:
            print(padText("  Attribute Type") + getZCLAttributeType(data[i + 3]))
            l = getZCLAttributeSize(data[i + 3])
            if l != -1:
                # The data is of a fixed size ('l')
                if data[i + 3] == 0x10:
                    # Handle Boolean values separately
                    s = "FORBIDDEN"
                    if data[i + 4] == 0x00:
                        s = "FALSE"
                    else:
                        s = "TRUE"
                    print(padText("  Attribute Value") + s)
                    i = i + 5  
                else:  
                    # Handle all other numeric values
                    i = i + 4 + l
                    v = 0
                    k = 0
                    for j in range(i, i - l, -1):
                        v = v + (data[j] << k)
                        k = k + 8
                    print(padText("  Attribute Value") + getHex(v,l))
            else:
                if data[i + 3] == 0x41 or data[i + 3] == 0x42:
                    l = data[i + 4]
                    ds = ""
                    for j in range(i + 5, i + 5 + l):
                        ds = ds + chr(data[j])
                    print(padText("  Attribute Value") + ds)
                    i = i + 4 + l
                elif data[i + 3] == 0x43 or data[i + 3] == 0x44:
                    l = (data[i + 4] << 8) + data[i + 5]
                    ds = ""
                    for j in range(i + 6, i + 6 + l):
                        ds = ds + chr(data[j])
                    print(padText("  Attribute Value") + ds)
                    i = i + 5 + l
                else:
                    # TODO
                    print(padText("  Attribute Value") + "TBD")
                    i = i + 3
        else:
            # Attribute access unsuccessful
            i = i + 3
        if i >= len(data):
            done = True


def decodeZDO(data, cmd):
    print(padText("  Transaction Number") + getHex(data[0],2))
    getZDOCommand(cmd)

    if cmd == 0x0000:
        # Network Address Request
        read64bitSserdda(data, 1)
        getZDOType(data[9])
        if data[9] == 0x01:
            # Type value indicates an extended device response requested
            print(padText("  Start Index") + getHex(data[10]))
    elif cmd == 0x8000:
        # Network Address Response
        getZDOStatus(data[1])
        read64bitSserdda(data, 2)
        print(padText("  Address (16-bit)") + getHex(data[10] + (data[11] << 8),4))
        if len(data) > 12:
            print(padText("  No. of addresses") + getHex(data[12],2))
            print(padText("  Start Index") + getHex(data[13],2))
            count = 1
            for i in range(14,14  + data[12] * 2,2):
                print(padText("  Address" + str(count)) + getHex((data[i] << 8) + data[i + 1],4))


###########################################################################
# This section comprises utility functions used by the primary decoders   #
# listed above.                                                           #
###########################################################################

def read64bitAddress(frameData, start = 4):
    # Reads the bytes representing a 64-bit address from the passed-in blob.
    # Parameters:
    #   1. Array - the frame data as a series of integer values
    #   2. Integer - the index in the array at which the data is to be found
    # Returns:
    #   The 64-bit address as a string of 8 octets
    s = ""
    for i in range(start, start + 8):
        s = s + getHex(frameData[i], 2)
    print(padText("Address (64-bit)") + s)


def read64bitSserdda(frameData, start = 4):
    # As read64bitAddress(), but returning the address in little endian order
    s = ""
    for i in range(start + 7, start - 1, -1):
        s = s + getHex(frameData[i], 2)
    print(padText("  Address (64-bit)") + s)


###########################################################################
# This section comprises XBee and Zigbee enumeration decoders used by the #
# primary decoders  listed above.                                         #
###########################################################################

def getSendOptions(code):
    # Decode a Zigbee packet Send options byte and print a relevant status message
    # Parameters:
    #   1. Integer - the status code included in the packet
    # Returns:
    #   Nothing
    os = ""
    if code & 0x01 == 0x01:
        os = os + "Disable retries and route repair, "
    if code & 0x20 == 0x20:
        os = os + "Enable APS encryption (if EE=1), "
    if code & 0x40 == 0x40:
        os = os + "Use the extended transmission timeout, "
    l = len(os)
    if l > 0:
        os = os[0:l - 2]
    else:
        os = "None"
    print(padText("Options") + os)


def getATStatus(code):
    # Decode an AT command status packet's status byte and print a relevant status message
    # Parameters:
    #   1. Integer - the status code included in the packet
    # Returns:
    #   Nothing
    m = [ "OK", "ERROR", "Invalid Command", "Invalid Parameter", "TX Failure"]
    print(padText("Command status") + m[code])


def getModemStatus(code):
    # Decode a modem status packet's status byte and print a relevant status message
    # Parameters:
    #   1. Integer - the status code included in the packet
    # Returns:
    #   Nothing
    m = [0x00, "Hardware Reset",
         0x01, "Watchdog Timer Reset",
         0x02, "Joined Network",
         0x03, "Disassociated",
         0x06, "Coordinator Started",
         0x07, "Network Security Updated",
         0x0D, "Voltage Supply Exceeded",
         0x11, "Modem Config Changed"]
    for i in range(0, len(m), 2):
        if code == m[i]:
            print(padText("Modem status") + m[i + 1])
            return
    if code >= 0x80:
        print(padText("Modem status") + "Stack Error")
        return
    print(padText("Modem status") + "[Error] " + getHex(code,2))


def getPacketStatus(code):
    # Decode the packet's status byte and print the relevant status message
    # Parameters:
    #   1. Integer - the status code included in the packet
    # Returns:
    #   Nothing
    s = ""
    if code == 0x00:
        s = "Packet Not Acknowledged; "
    if code & 0x01:
        s = s + "Packet Acknowledged; "
    if code & 0x02:
        s = s + "Packet a Broadcast Packet; "
    if code & 0x20:
        s = s + "Packet Encrypted with APS; "
    if code & 0x40:
        s = s + "Packet Sent By End-Device; "
    print(padText("Status") + s[0:-2])


def getDeliveryStatus(code):
    # Decode the packet's address delivery status byte and print the relevant status message
    # Parameters:
    #   1. Integer - the status code included in the packet
    # Returns:
    #   Nothing
    m = [   0x00, "Success",
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
    print(padText("Delivery status") + "[ERROR] " + getHex(code,2))


def getDiscoveryStatus(code):
    # Decode the packet's address discovery status byte and print the relevant status message
    # Parameters:
    #   1. Integer - the status code included in the packet
    # Returns:
    #   Nothing
    m = [ "No Discovery Overhead", "Address Discovery",
          "Route Discovery", "Address and Route"]
    if code < 0x04:
        print(padText("Discovery status") + m[code])
    else:
        print(padText("Discovery status") + "[ERROR] " + getHex(code,2))


def getZCLAttributeStatus(code):
    m = [   0x00, "Success",
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
    m = [   0x00, "NULL",
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
    m = [ "16-bit Address", 0x0000,
          "64-bit Address", 0x0001,
          "Node Descriptor", 0x0002,
          "Simple Descriptor", 0x0004,
          "Active Endpoints", 0x0005,
          "Match Descriptor", 0x0006,
          "Complex Descriptor", 0x0010,
          "User Descriptor", 0x0011,
          "User Descriptor Set", 0x0014,
          "Management Network Discovery", 0x0030,
          "Management LQI (Neighbor Table)", 0x0031,
          "Management RTG (Routing Table)", 0x0032,
          "Management Leave", 0x0034,
          "Management Permit Join", 0x0036,
          "Management Network Update", 0x0038 ]
    for i in range(0, len(m), 2):
        if code == m[i + 1]:
            if code > 0x8000:
                return (m[i] + " Response")
            else:
                return (m[i] + " Request")
    return "Unknown ZDO command"


def getZDOType(code):
    if code == 0x00:
        print(padText("  Request type") + "Single device response")
    else:
        print(padText("  Request type") + "Extended response")


def getZDOStatus(code):
    print(padText("  Response status") + getZCLAttributeStatus(code))


###########################################################################
# This section comprises generic utility functions used by all parts of   #
# the program                                                             #
###########################################################################

def getHex(v,d):
    # Convert the integer 'v' to a hex string of 'd' characters
    # prefix-padding as required
    # Parameters:
    #   1. Integer - the value to be converted
    #   2. Integer - the number of characters the final string should comprise
    # Returns:
    #   String - the hex characters
    s = "{:0" + str(d) + "X}"
    return s.format(v)


def padText(s,e=True):
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


def showHelp():
    print("ZigbeeParser version " + APP_VERSION + "\n")
    print("Usage:")
    print("  python xbp.py <XBee packet hex string>")
    print("\nThe XBee packet string must not contains spaces.\n")
    print("Options:")
    print("  -e / --escape <true/false> - Use escaping when decoding packets")
    print("  -d / --debug <true/false>  - Show extra debug information")
    print("  -v / --version             - Show version information")
    print("  -h / --help                - Show help information")


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
                print("ZigbeeParser version " + APP_VERSION)
                i = i + 1
            elif c == "-h" or c == "--help":
                # Print help
                showHelp()
                i = i + 1
            elif c == "-e" or c == "--escape":
                # Are we escaping
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
            elif c == "-d" or c == "--debug":
                # Are we escaping
                if i < len(sys.argv) - 1:
                    v = sys.argv[i + 1]
                    if v == "true" or v == "yes" or v == "1":
                        escaped = True
                        print("Extra debugging information will be printed during decoding")
                    elif v == "false" or v == "no" or v == "0":
                        escaped = False
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
        for i in range(1, len(sys.argv)):
            c = sys.argv[i]
            if c[0] != "-":
                fs = fs + c
        if len(fs) > 8:
            # Frame has to have at least four octets
            processPacket(fs)
    else:
        print("[ERROR] No Data provided")
    sys.exit(0)
