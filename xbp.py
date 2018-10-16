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
TEXT_SIZE = 24

# ZCL Global Commands
zclCmds = ["Read Attributes", "Read Attributes Response", "Write Attributes", "Write Attributes Undivided",
           "Write Attributes Response", "Write Attributes No Response", "Configure Reporting", "Configure Reporting Response",
           "Read Reporting Configuration", "Read Reporting Configuration Response", "Report Attributes", "Default Response",
           "Discover Attributes", "Discover Attributes Response"]

# Global App Variables
escaped = True


def processPacket(packet):
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
    
    # Does the data contain an even number of characters?
    if len(packet) % 2 != 0:
        print("[ERROR] Packet data does not contain an even number of characters")
        return

    # Convert each pair of characters (which represent a single byte)
    # to integer values in an array
    # NOTE 'escaped' indicates whether the packet contains escaped
    #      charactrers
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
    print("Frame length         : " + str(length) + " bytes")

    # Look for XBee frame types
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
        print("Unknown frame type")
        return



def decodeModemStatus(data):
    print("XBee Command ID         : " + getHex(data[3],2))
    getModemStatus(data[4])


def decodeZigbeeRXIndicator(data):
    # The Xbee has received a Zigbee CL packet (frame ID 0x91)
    print("Frame command           : " + getHex(data[3],2))
    read64bitAddress(data, 4)
    print("Address (16)            : " + getHex(((data[12] << 8) + data[13]),4))
    print("Source endpoint         : " + getHex(data[14],2))
    print("Destination endpoint    : " + getHex(data[15],2))
    print("ClusterID               : " + getHex(((data[16] << 8) + data[17]),4))
    print("ProfileID               : " + getHex(((data[18] << 8) + data[19]),4))
    getPacketStatus(data[20])
    ds = ""
    dv = []
    l = (data[1] << 8) + data[2] - 18
    if l > 0:
        for i in range(21, 21 + l):
            ds = ds + getHex(data[i],2)
            dv.append(data[i])
        print("Frame data           : " + ds)
        decodeZCLFrame(dv)


def decodeZCLFrame(frameData):
    global zclCmds
    
    fc = frameData[0]
    tr = frameData[1]
    ci = frameData[2]

    print("  Frame Control Byte : " + getHex(fc,2))
    print("  Transaction Number : " + getHex(tr,2))
    
    if fc & 0x01 == 0:
        print("  Global Command     : " + getHex(ci,2) + " - " + zclCmds[ci])
    else:
        print("  Cluster Command    : " + getHex(ci,2))

    if fc & 0x08 == 0:
        print("  Direction          : Client to Server")
    else:
        print("  Direction          : Server to Client")


def read64bitAddress(frameData, start = 4):
    # Reads the bytes representing a 64-bit address from the passed-in blob.
    # Returns:
    #   The 64-bit address as a string of 8 octets headed by '0x'
    s = ""
    for i in range(start, start + 8):
        s = s + getHex(frameData[i], 2)
    print("Address (64)         : " + s)


def getModemStatus(code):
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
            print("Modem status        :" + m[i + 1])
            return
    if code >= 0x80:
        print("Modem status        : Stack Error")
        return
    print("Modem status        : Error (" + getHex(code,2) + ")");


def getPacketStatus(code):
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
    print("Status               : " + s[0:-2])


def getHex(v,d):
    s = "{:0" + str(d) + "X}"
    return s.format(v)

def doPrint(s,v,d):
    l = TEXT_SIZE - len(s)
    t = s + "                          "[0:l] + ": " + getHex(v,d)
    print(t)


processPacket("7e 00 17 91 00 17 88 01 01 92 07 60 cb d1 40 30 00 06 01 04 00 18 6f 0b 00 00 2b")

