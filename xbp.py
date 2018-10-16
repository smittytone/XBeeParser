#!/usr/bin/env python

# Imports
import sys

# 'Constants'
# XBee Request Commands
XBEE_CMD_AT = 0x08
XBEE_CMD_QUEUE_PARAM_VALUE = 0x09
XBEE_CMD_ZIGBEE_TRANSMIT_REQ = 0x10
XBEE_CMD_EXP_ADDR_ZIGBEE_CMD_FRAME = 0x11
XBEE_CMD_REMOTE_CMD_REQ = 0x17
XBEE_CMD_CREATE_SOURCE_ROUTE = 0x21

# XBee Response Frame IDs
XBEE_CMD_AT_RESPONSE = 0x88
XBEE_CMD_MODEM_STATUS = 0x8A
XBEE_CMD_ZIGBEE_TRANSMIT_STATUS = 0x8B
XBEE_CMD_ZIGBEE_RECEIVE_PACKET = 0x90
XBEE_CMD_ZIGBEE_EXP_RX_INDICATOR = 0x91
XBEE_CMD_ZIGBEE_IO_DATA_SAMPLE_RX_INDICATOR = 0x92
XBEE_CMD_XBEE_SENSOR_READ_INDICATOR = 0x94
XBEE_CMD_NODE_ID_INDICATOR = 0x95
XBEE_CMD_REMOTE_CMD_RESPONSE = 0x97
XBEE_CMD_ROUTE_RECORD_INDICATOR = 0xA1
XBEE_CMD_MANY_TO_ONE_ROUTE_REQ_INDICATOR = 0xA2
# NOT YET SUPPORTED
XBEE_CMD_OTA_FIRMWARE_UPDATE_STATUS = 0xA0

# App Constants
TEXT_SIZE = 30
SPACE_STRING = "                                                             "

# ZCL Global Commands
zclCmds = ["Read Attributes", "Read Attributes Response", "Write Attributes", "Write Attributes Undivided",
           "Write Attributes Response", "Write Attributes No Response", "Configure Reporting", "Configure Reporting Response",
           "Read Reporting Configuration", "Read Reporting Configuration Response", "Report Attributes", "Default Response",
           "Discover Attributes", "Discover Attributes Response"]

# Global App Variables
escaped = True
debug = True


def processPacket(packet):
    # Process a string of hex bytes received or sent via an XBee
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
    
    # Does the data contain an even number of characters?
    if len(packet) % 2 != 0:
        print("[ERROR] Packet data does not contain an even number of characters")
        return

    # Convert each pair of characters (which represent a single byte)
    # to integer values in an array
    # NOTE 'escaped' indicates whether the packet contains escaped
    #      characters
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
    cs = cs & 0xFF;
    if cs != 0xFF:
        print("[ERROR] Packet checksum test failed")
        return

    # Display the frame data length
    length = values[1] * 256 + values[2]
    print(padText("Frame length") + str(length) + " bytes")

    # Look for XBee frame types and decode the data individually
    if values[3] == XBEE_CMD_AT_RESPONSE:
        decodeATResponse(values)
    elif values[3] == XBEE_CMD_MODEM_STATUS:
        decodeModemStatus(values)
    elif values[3] == XBEE_CMD_ZIGBEE_TRANSMIT_STATUS:
        decodeZigbeeTransmitStatus(values)
    elif values[3] == XBEE_CMD_ZIGBEE_RECEIVE_PACKET:
        decodeZigbeeReceivePacket(values)
    elif values[3] == XBEE_CMD_ZIGBEE_EXP_RX_INDICATOR:
        decodeZigbeeRXIndicator(values)
    elif values[3] == XBEE_CMD_ZIGBEE_IO_DATA_SAMPLE_RX_INDICATOR:
        decodeZigbeeDataSampleRXIndicator(values)
    elif values[3] == XBEE_CMD_XBEE_SENSOR_READ_INDICATOR:
        decodeXBeeSensorReadIndicator(values)
    elif values[3] == XBEE_CMD_NODE_ID_INDICATOR:
        decodeNodeIDIndicator(values)
    elif values[3] == XBEE_CMD_REMOTE_CMD_RESPONSE:
        decodeRemoteATCommand(values)
    elif values[3] == XBEE_CMD_ROUTE_RECORD_INDICATOR:
        decodeRouteRecordIndicator(values)
    elif values[3] == XBEE_CMD_MANY_TO_ONE_ROUTE_REQ_INDICATOR:
        decodeManyToOneRouteIndicator(values)
    else:
        print("[ERROR] Unknown frame type")
        return


def decodeATResponse(data):
    # The Xbee has received an XBee AT response packet (frame ID 0x88)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing
    print(padText("XBee Command ID") + getHex(data[3],2))
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
    print(padText("XBee Command ID") + getHex(data[3],2))
    print(padText("XBee Frame ID") + getHex(data[4],2))
    print(padText("XBee AT Command") + chr(data[15]) + chr(data[16]))
    read64bitAddress(data, 5)
    print(padText("Address (16)") + getHex(((data[13] << 8) + data[14]),4))
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
    print(padText("XBee Command ID") + getHex(data[3],2))
    getModemStatus(data[4])


def decodeZigbeeRXIndicator(data):
    # The Xbee has received a Zigbee ZCL packet (frame ID 0x91)
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing
    print(padText("Frame command") + getHex(data[3],2))
    read64bitAddress(data, 4)
    print(padText("Address (16)") + getHex(((data[12] << 8) + data[13]),4))
    print(padText("Source endpoint") + getHex(data[14],2))
    print(padText("Destination endpoint") + getHex(data[15],2))
    print(padText("ClusterID") + getHex(((data[16] << 8) + data[17]),4))
    print(padText("ProfileID") + getHex(((data[18] << 8) + data[19]),4))
    getPacketStatus(data[20])
    ds = ""
    dv = []
    l = (data[1] << 8) + data[2] - 18
    if l > 0:
        for i in range(21, 21 + l):
            ds = ds + getHex(data[i],2)
            dv.append(data[i])
        print(padText("Frame data") + ds)
        decodeZCLFrame(dv)


def decodeZCLFrame(frameData):
    # Parameters:
    #   1. Array - the packet data as a collection of integers
    # Returns:
    #   Nothing
    
    global zclCmds
    
    fc = frameData[0]
    tr = frameData[1]
    ci = frameData[2]

    print(padText("  Frame Control Byte") + getHex(fc,2))
    print(padText("  Transaction Number") + getHex(tr,2))
    
    if fc & 0x01 == 0:
        print(padText("  Global Command") + getHex(ci,2) + " - " + zclCmds[ci])
    else:
        print(padText("  Cluster Command") + getHex(ci,2))

    if fc & 0x08 == 0:
        print(padText("  Direction") + "Client to Server")
    else:
        print(padText("  Direction") + "Server to Client")


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
    print(padText("Address (64)") + s)


# Display status code messages

def getATStatus(code):
    # Decode an AT command status packet's status byte and print the relevant status message
    # Parameters:
    #   1. Integer - the status code included in the packet
    # Returns:
    #   Nothing
    m = [ "OK", "ERROR", "Invalid Command", "Invalid Parameter", "TX Failure"]
    print(padText("Command status") + m[code])


def getModemStatus(code):
    # Decode a modem status packet's status byte and print the relevant status message
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




if __name__ == '__main__':
    if len(sys.argv) > 1:
        processPacket(sys.argv[1])
    else:
        print("[ERROR] No Data provided")
        processPacket("7e 00 17 91 00 17 88 01 01 92 07 60 cb d1 40 30 00 06 01 04 00 18 6f 0b 00 00 2b")
    sys.exit(0)




