#!/usr/bin/env python

"""

XBeeParser 1.0.5
Copyright 2018-19, Tony Smith (@smittytone)
License: MIT (terms attached to this repo)

"""


##########################################################################
# Program library imports                                                #
##########################################################################

import sys
import math

##########################################################################
# Constants covering key XBee and Zigbee commands, data types, etc.      #
##########################################################################

# XBee Request Commands
XBEE_CMD_AT                                 = 0x08 # pylint: disable=C0326; DONE
XBEE_CMD_QUEUE_PARAM_VALUE                  = 0x09 # pylint: disable=C0326; DONE
XBEE_CMD_ZIGBEE_TRANSMIT_REQ                = 0x10 # pylint: disable=C0326; DONE
XBEE_CMD_EXP_ADDR_ZIGBEE_CMD_FRAME          = 0x11 # pylint: disable=C0326; DONE
XBEE_CMD_REMOTE_CMD_REQ                     = 0x17 # pylint: disable=C0326; DONE
XBEE_CMD_REMOTE_CMD_SECURE_REQ              = 0x18 # pylint: disable=C0326;
XBEE_CMD_CREATE_SOURCE_ROUTE                = 0x21 # pylint: disable=C0326; DONE
XBEE_CMD_REGISTER_DEVICE_JOIN               = 0x24 # pylint: disable=C0326;

# XBee Response Frame IDs
XBEE_CMD_AT_RESPONSE                        = 0x88 # pylint: disable=C0326; DONE
XBEE_CMD_MODEM_STATUS                       = 0x8A # pylint: disable=C0326; DONE
XBEE_CMD_ZIGBEE_TRANSMIT_STATUS             = 0x8B # pylint: disable=C0326; DONE
XBEE_CMD_ZIGBEE_RECEIVE_PACKET              = 0x90 # pylint: disable=C0326; DONE
XBEE_CMD_ZIGBEE_EXP_RX_INDICATOR            = 0x91 # pylint: disable=C0326; DONE
XBEE_CMD_ZIGBEE_IO_DATA_SAMPLE_RX_INDICATOR = 0x92 # pylint: disable=C0326; DONE
XBEE_CMD_XBEE_SENSOR_READ_INDICATOR         = 0x94 # pylint: disable=C0326; DONE
XBEE_CMD_NODE_ID_INDICATOR                  = 0x95 # pylint: disable=C0326; DONE
XBEE_CMD_REMOTE_CMD_RESPONSE                = 0x97 # pylint: disable=C0326; DONE
XBEE_CMD_EXTENDED_MODEM_STATUS              = 0x98 # pylint: disable=C0326;
XBEE_CMD_OTA_FIRMWARE_UPDATE_STATUS         = 0xA0 # pylint: disable=C0326; DONE
XBEE_CMD_ROUTE_RECORD_INDICATOR             = 0xA1 # pylint: disable=C0326; DONE
XBEE_CMD_DEVICE_AUTH_INDICATOR              = 0xA2 # pylint: disable=C0326; DONE
XBEE_CMD_MANY_TO_ONE_ROUTE_REQ_INDICATOR    = 0xA3 # pylint: disable=C0326; DONE
XBEE_CMD_REGISTER_DEVICE_JOIN_STATUS        = 0xA4 # pylint: disable=C0326; DONE
XBEE_CMD_JOIN_NOTIFICATION_STATUS           = 0xA5 # pylint: disable=C0326; DONE

# ZCL Global Commands
ZCL_GLOBAL_CMD_READ_ATTR_REQ                = 0x00 # pylint: disable=C0326; DONE
ZCL_GLOBAL_CMD_READ_ATTR_RSP                = 0x01 # pylint: disable=C0326; DONE
ZCL_GLOBAL_CMD_WRITE_ATTR_REQ               = 0x02 # pylint: disable=C0326; DONE
ZCL_GLOBAL_CMD_WRITE_ATTR_UND               = 0x03 # pylint: disable=C0326; DONE
ZCL_GLOBAL_CMD_WRITE_ATTR_RSP               = 0x04 # pylint: disable=C0326; DONE
ZCL_GLOBAL_CMD_WRITE_ATTR_NO                = 0x05 # pylint: disable=C0326; DONE
ZCL_GLOBAL_CMD_CONF_REPT_REQ                = 0x06 # pylint: disable=C0326;
ZCL_GLOBAL_CMD_CONF_REPT_RSP                = 0x07 # pylint: disable=C0326;
ZCL_GLOBAL_CMD_READ_REPT_REQ                = 0x08 # pylint: disable=C0326;
ZCL_GLOBAL_CMD_READ_REPT_RSP                = 0x09 # pylint: disable=C0326;
ZCL_GLOBAL_CMD_REPT_ATTR                    = 0x0A # pylint: disable=C0326;
ZCL_GLOBAL_CMD_DEFAULT_RSP                  = 0x0B # pylint: disable=C0326;
ZCL_GLOBAL_CMD_DISC_ATTR_REQ                = 0x0C # pylint: disable=C0326;
ZCL_GLOBAL_CMD_DISC_ATTR_RSP                = 0x0D # pylint: disable=C0326;
ZCL_GLOBAL_CMD_READ_ATTR_STR_REQ            = 0x0E # pylint: disable=C0326;
ZCL_GLOBAL_CMD_WRITE_ATTR_STR_REQ           = 0x0F # pylint: disable=C0326;
ZCL_GLOBAL_CMD_WRITE_ATTR_STR_RSP           = 0x10 # pylint: disable=C0326;
ZCL_GLOBAL_CMD_DISC_RCMDS_REQ               = 0x11 # pylint: disable=C0326; #DONE
ZCL_GLOBAL_CMD_DISC_RCMDS_RSP               = 0x12 # pylint: disable=C0326; #DONE
ZCL_GLOBAL_CMD_DISC_GCMDS_REQ               = 0x13 # pylint: disable=C0326; #DONE
ZCL_GLOBAL_CMD_DISC_GCMDS_RSP               = 0x14 # pylint: disable=C0326; #DONE
ZCL_GLOBAL_CMD_DISC_ATTR_EXT_REQ            = 0x15 # pylint: disable=C0326;
ZCL_GLOBAL_CMD_DISC_ATTR_EXT_RSP            = 0x16 # pylint: disable=C0326;

# Internal ZCL frame types
ATT_TYPE_READ_RSP                           = 0x00 # pylint: disable=C0326;
ATT_TYPE_WRITE_REQ                          = 0x01 # pylint: disable=C0326;
ATT_TYPE_WRITE_RSP                          = 0x02 # pylint: disable=C0326;


##########################################################################
# Application-specific constants                                         #
##########################################################################

# App Constants
TEXT_SIZE = 30
SPACE_STRING = "                                                             "
APP_VERSION = "1.0.5"

# ZCL Global Command names
ZCL_CMDS = ("Read Attributes", "Read Attributes Response", "Write Attributes", "Write Attributes Undivided",
            "Write Attributes Response", "Write Attributes No Response", "Configure Reporting", "Configure Reporting Response",
            "Read Reporting Configuration", "Read Reporting Configuration Response", "Report Attributes", "Default Response",
            "Discover Attributes", "Discover Attributes Response", "Read Attributes Structured", "Write Attributes Structured",
            "Write Attributes Structured Response", "Discover Commands Received", "Discover Commands Received Response",
            "Discover Commands Generated", "Discover Commands Generated Response", "Discover Attributes Extended",
            "Discover Attributes Extended Response")


##########################################################################
# Application globals                                                    #
##########################################################################

escaped = True
debug = False
prefixed = False


##########################################################################
# Packet-processing entry point                                          #
##########################################################################

def process_packet(packet_str):
    """
    Process a string of hex bytes received or sent via an XBee.

    Args:
        packet_str (str): The packet data as a hexadecimal string as passed in via
                          the command line.
    """

    global escaped

    # Convert hex string to upper case
    packet_str = packet_str.upper()

    # Run through the string and remove spaces, if any, between codes
    done = False
    i = 0
    while done is False:
        if packet_str[i] == " ":
            packet_str = packet_str[0:i] + packet_str[i + 1:]
        else:
            i += 1
        if i >= len(packet_str): done = True

    if debug is True: print(packet_str)

    # Does the data contain an even number of characters? It should
    # TODO Should this just pad the end with 0?
    if len(packet_str) % 2 != 0:
        print("[ERROR] Packet data does not contain an even number of octets")
        return

    # Convert each pair of characters (which represent a single byte)
    # to integer values in an array
    # NOTE 'escaped' indicates whether the packet contains escaped
    #      characters, an XBee feature
    values = []
    done = False
    escape_next_char = False
    i = 0
    while done is False:
        hex_byte = packet_str[i:i+2]
        if hex_byte == "7D" and escaped is True and escape_next_char is False:
            escape_next_char = True
        elif escape_next_char is True:
            values.append(int(hex_byte, 16) ^ 0x20)
            escape_next_char = False
        else:
            values.append(int(hex_byte, 16))

        i += 2
        if i >= len(packet_str): done = True

    # Is the first character the XBee packet marker?
    if values[0] == 0x7E:
        print("XBee frame found")
    else:
        print("[ERROR] Packet data does not start with an XBee signature (" + get_hex(values[0]) + ", should be 7E)")
        return

    # Test the checksum value (the last byte in the packet)
    read_check_sum = values[len(values) - 1]
    calc_check_sum = 0
    for i in range(3, len(values) - 1): calc_check_sum += values[i]
    calc_check_sum = (0xFF - (calc_check_sum & 0xFF)) & 0xFF
    if calc_check_sum != read_check_sum:
        print("[ERROR] Packet checksum test failed (" + get_hex(calc_check_sum) + " should be " + get_hex(read_check_sum) + ")")
        return

    # Display the frame data length
    length = values[1] * 256 + values[2]
    print(pad_text("Frame length") + str(length) + " bytes")

    # Look for XBee frame types and decode the data individually
    x_cmd = values[3]
    if x_cmd == XBEE_CMD_AT:
        decode_send_at_cmd(values)
    elif x_cmd == XBEE_CMD_QUEUE_PARAM_VALUE:
        decode_param_queue_req(values)
    elif x_cmd == XBEE_CMD_ZIGBEE_TRANSMIT_REQ:
        decode_zb_tx_req(values)
    elif x_cmd == XBEE_CMD_EXP_ADDR_ZIGBEE_CMD_FRAME:
        decode_explicit_cmd_req(values)
    elif x_cmd == XBEE_CMD_REMOTE_CMD_REQ:
        decode_remote_cmd_req(values)
    elif x_cmd == XBEE_CMD_CREATE_SOURCE_ROUTE:
        decode_create_source_route_req(values)
    elif x_cmd == XBEE_CMD_AT_RESPONSE:
        decode_at_rsp(values)
    elif x_cmd == XBEE_CMD_MODEM_STATUS:
        decode_modem_status(values)
    elif x_cmd == XBEE_CMD_ZIGBEE_TRANSMIT_STATUS:
        decode_zb_tx_status(values)
    elif x_cmd == XBEE_CMD_ZIGBEE_RECEIVE_PACKET:
        decode_zb_rx_packet(values)
    elif x_cmd == XBEE_CMD_ZIGBEE_EXP_RX_INDICATOR:
        decode_zb_rx_indicator(values)
    elif x_cmd == XBEE_CMD_ZIGBEE_IO_DATA_SAMPLE_RX_INDICATOR:
        decode_zb_sample_rx_indicator(values)
    elif x_cmd == XBEE_CMD_XBEE_SENSOR_READ_INDICATOR:
        decode_xb_sensor_read_indicator(values)
    elif x_cmd == XBEE_CMD_NODE_ID_INDICATOR:
        decode_node_id_indicator(values)
    elif x_cmd == XBEE_CMD_REMOTE_CMD_RESPONSE:
        decode_remote_at_cmd(values)
    elif x_cmd == XBEE_CMD_OTA_FIRMWARE_UPDATE_STATUS:
        decode_firmware_update(values)
    elif x_cmd == XBEE_CMD_ROUTE_RECORD_INDICATOR:
        decode_route_record_indicator(values)
    elif x_cmd == XBEE_CMD_DEVICE_AUTH_INDICATOR:
        decode_dev_auth_indicator(values)
    elif x_cmd == XBEE_CMD_MANY_TO_ONE_ROUTE_REQ_INDICATOR:
        decode_many_one_route_indicator(values)
    elif x_cmd == XBEE_CMD_REGISTER_DEVICE_JOIN_STATUS:
        decode_dev_join_status(values)
    elif x_cmd == XBEE_CMD_JOIN_NOTIFICATION_STATUS:
        decode_join_notification(values)
    else:
        print("[ERROR] Unknown or not-yet-supported frame type: " + get_hex(values[3]))
        return
    print(pad_text("Checksum") + get_hex(calc_check_sum))


##########################################################################
# This section comprises starting points for specific XBee packet types. #
##########################################################################

def decode_send_at_cmd(data):
    """
    The Xbee is sending an XBee AT command packet (frame ID 0x08).

    Args:
        data (list): The packet data as a collection of integers.
    """

    decode_at_common(data, "Issue local AT command", "None")


def decode_param_queue_req(data):
    """
    The Xbee is queing an XBee AT command packet (frame ID 0x09).

    Args:
        data (list): The packet data as a collection of integers.
    """

    decode_at_common(data, "Queue AT command parameter value", "Read queued")


def decode_zb_tx_req(data):
    """
    The Xbee has issues a basic Zigbee command (frame ID 0x10).

    Args:
        data (list): The packet data as a collection of integers.
    """

    print_standard_header("Issue basic Zigbee request", data, 3)
    print(pad_text("Radius") + get_hex(data[15]))
    get_send_options(data[16])

    data_str = ""
    char_str = ""
    length = (data[1] << 8) + data[2] - 14
    if length > 0:
        for i in range(17, 17 + length):
            data_str += get_hex(data[i])
            char_str += chr(data[i])
        print(pad_text("Data bytes (" + str(length) + ")") + data_str + " (Ascii: " + char_str + ")")


def decode_explicit_cmd_req(data):
    """
    The Xbee is sending an explicit Zigbee packet (frame ID 0x11)

    Args:
        data (list): The packet data as a collection of integers.
    """

    print_standard_header("Issue explicit Zigbee request", data, 3)
    print(pad_text("Source endpoint") + get_hex(data[15]))
    print(pad_text("Destination endpoint") + get_hex(data[16]))

    cluster_id = (data[17] << 8) + data[18]
    print(pad_text("Cluster ID") + get_hex(cluster_id, 4))

    profile_id = (data[19] << 8) + data[20]
    print(pad_text("Profile ID") + get_hex(profile_id, 4))

    print(pad_text("Radius") + get_hex(data[21]))
    get_send_options(data[22])

    length = (data[1] << 8) + data[2] - 20
    zb_data = print_frame_data(data, 23, length)
    if zb_data:
        if profile_id == 0x0000:
            # ZDO operation
            decode_zdo(zb_data, cluster_id)
        else:
            # ZCL operation
            decode_zcl_frame(zb_data)


def decode_remote_cmd_req(data):
    """
    The Xbee is sending a remote AT response packet (frame ID 0x17).

    Args:
        data (list): The packet data as a collection of integers.
    """

    print_standard_header("Remote AT command request", data, 3)
    get_send_options(data[15])
    print(pad_text("XBee AT command") + "\"" + chr(data[16]) + chr(data[17]) + "\"")
    decode_at_param_common(data, 18, 15, "Read request")


def decode_create_source_route_req(data):
    """
    The Xbee is sending a source route request (frame ID 0x21).

    Args:
        data (list): The packet data as a collection of integers.
    """

    print_standard_header("Create source route request", data, 3)
    print(pad_text("Route Command Options") + get_hex(data[15]))

    address_num = data[16]
    print(pad_text("Number of addresses") + get_hex(address_num))

    length = (data[1] << 8) + data[2] - 14
    if length > 0:
        address = 0
        item_count = 1
        for i in range(17, 17 + length, 2):
            address = (data[i] << 8) + data[i + 1]
            print(pad_text("  Address " + str(item_count)) + get_hex(address, 4))
            item_count += 1
    elif length < address_num * 2:
        print("[ERROR]: missing address data - " + str(length / 2) + " included, " + str(address_num) + " expected")
        sys.exit(1)


def decode_at_rsp(data):
    """
    The Xbee has received an XBee AT response packet (frame ID 0x88).

    Args:
        data (list): The packet data as a collection of integers.
    """

    cmd_str = decode_at_common(data, "Local AT command response")
    get_at_status(data[7])
    length = (data[1] << 8) + data[2] - 5
    payload = print_frame_data(data, 8, length)

    # Trap ND packets
    if cmd_str == "ND": decode_node_data(payload, 0)


def decode_modem_status(data):
    """
    The Xbee has received an XBee model status packet (frame ID 0x8A).

    Args:
        data (list): The packet data as a collection of integers.
    """

    print(pad_text("XBee command ID") + get_hex(data[3]) + " \"Modem status\"")
    get_modem_status(data[4])


def decode_zb_tx_status(data):
    """
    The Xbee has received an Zigbee transmit status packet (frame ID 0x8B).

    Args:
        data (list): The packet data as a collection of integers.
    """

    print(pad_text("XBee command ID") + get_hex(data[3]) + " \"Zigbee transmit status\"")
    print(pad_text("XBee frame ID") + get_hex(data[4]))
    print(pad_text("Address (16-bit)") + get_hex(((data[5] << 8) + data[6]), 4))
    print(pad_text("Retries") + ("None" if data[7] == 0 else str(data[7])))
    get_delivery_status(data[8])
    get_discovery_status(data[9])


def decode_zb_rx_packet(data):
    """
    The Xbee has received a basic  packet (frame ID 0x90).

    Args:
        data (list): The packet data as a collection of integers.
    """

    print_basic_header("Zigbee receive packet (basic)", data, 3)
    get_packet_status(data[14])

    length = (data[1] << 8) + data[2] - 12
    _ = print_frame_data(data, 15, length)


def decode_zb_rx_indicator(data):
    """
    The Xbee has received an explicit Zigbee ZCL packet (frame ID 0x91).

    Args:
        data (list): The packet data as a collection of integers.
    """

    print_basic_header("Zigbee explicit RX indicator", data, 3)
    print(pad_text("Source endpoint") + get_hex(data[14]))
    print(pad_text("Destination endpoint") + get_hex(data[15]))

    cluster_id = (data[16] << 8) + data[17]
    print(pad_text("Cluster ID") + get_hex(cluster_id, 4))

    profile_id = (data[18] << 8) + data[19]
    print(pad_text("Profile ID") + get_hex(profile_id, 4))

    get_packet_status(data[20])

    length = (data[1] << 8) + data[2] - 18
    payload = print_frame_data(data, 21, length)
    if payload:
        if profile_id == 0x0000:
            decode_zdo(payload, cluster_id)
        elif profile_id == 0xC105:
            # Trap Digi's *other* node descriptor, send on button press
            decode_node_data(payload, 0)
        else:
            decode_zcl_frame(payload)


def decode_zb_sample_rx_indicator(data):
    """
    The Xbee has received a Zigbee IO Data Sample RX Indicator (frame ID 0x92).

    Args:
        data (list): The packet data as a collection of integers.
    """

    print_basic_header("Zigbee IO data sample", data, 3)
    get_packet_status(data[14])

    print(pad_text("Number of samples") + str(data[15]))
    node_desc = (data[16] << 8) + data[17]
    start = 19
    if node_desc > 0:
        get_digital_channel_mask(data, 16)
        start = 21
    if data[18] > 0: get_analog_channel_mask(data, start)


def decode_xb_sensor_read_indicator(data):
    """
    The Xbee has received an XBee sensor read response (frame ID 0x94).

    Args:
        data (list): The packet data as a collection of integers.
    """

    print_basic_header("XBee sensor read indicator response", data, 3)
    get_packet_status(data[14])
    get_onewire_status(data[15])

    # Read the sensor data
    values = []
    num_sensors = 0
    for i in range(16, 24, 2):
        value = (data[i] << 8) + data[i + 1]
        values.append(value)
        if value == 0xFF: num_sensors += 1
    if num_sensors == 4:
        print("No AD sensors found")
    else:
        sensor_str = ""
        for i in range(0, 4): sensor_str += (get_hex(values[i], 4) + ", ")
        if sensor_str is True: sensor_str = sensor_str[0:len(sensor_str)-2]
        print(pad_text("AD sensor values") + sensor_str)

    # Read the thermometer data
    value = (data[24] << 8) + data[25]
    if value == 0xFFFF:
        print("No thermometer found")
    else:
        print(pad_text("Thermometer reading") + get_hex(value, 4))


def decode_node_id_indicator(data):
    """
    The Xbee has received an XBee remote AT response packet (frame ID 0x95).

    Args:
        data (list): The packet data as a collection of integers.
    """

    print_basic_header("Node identification indicator response", data, 3)
    get_packet_status(data[14])
    #length = (data[1] << 8) + data[2] - 25
    decode_node_data(data, 15)


def decode_remote_at_cmd(data):
    """
    The Xbee has received an XBee remote AT response packet (frame ID 0x97).

    Args:
        data (list): The packet data as a collection of integers.
    """

    print_standard_header("Remote AT command response", data, 3)
    print(pad_text("XBee AT command") + chr(data[15]) + chr(data[16]))
    get_at_status(data[17])
    length = (data[1] << 8) + data[2] - 15
    _ = print_frame_data(data, 18, length)


def decode_firmware_update(data):
    """
    The Xbee has received an XBee firmware update packet (frame ID 0xA0).

    Args:
        data (list): The packet data as a collection of integers.
    """

    print_basic_header("XBee firmware update", data, 3)
    get_packet_status(data[14])
    get_bootloader_msg(data[15])
    print(pad_text("Block number") + str(data[16]))
    read_64_bit_address(data, 17, "Target address (64-bit)")


def decode_route_record_indicator(data):
    """
    The Xbee has received a routing info packet (frame ID 0xA1)

    Args:
        data (list): The packet data as a collection of integers.
    """

    print_basic_header("Route record indicator response", data, 3)
    get_packet_status(data[14])

    num_address = data[15]
    print(pad_text("Number of addresses") + get_hex(num_address))

    length = (data[1] << 8) + data[2] - 13
    if length > 0:
        address = 0
        address_count = 1
        for i in range(16, 16 + length, 2):
            address = (data[i] << 8) + data[i + 1]
            print(pad_text("  Address " + str(address_count)) + get_hex(address, 4))
            address_count += 1
    elif length < num_address * 2:
        print("[ERROR]: missing address data - " + str(length / 2) + " included, " + num_address + " expected")
        sys.exit(1)


def decode_dev_auth_indicator(data):
    """
    The XBee has received a device-authenticated packet (frame ID 0xA2).

    Args:
        data (list): The packet data as a collection of integers.
    """

    print_basic_header("Device Authenticated Indicator", data, 3)


def decode_many_one_route_indicator(data):
    """
    The Xbee has received a many-to-one routing info packet (frame ID 0xA3).

    Args:
        data (list): The packet data as a collection of integers.
    """

    print_basic_header("Many-to-one routing information", data, 3)


def decode_dev_join_status(data):
    """
    The Xbee has received a join notification status packet (frame ID 0xA5).

    Args:
        data (list): The packet data as a collection of integers.
    """

    print(pad_text("XBee command ID") + get_hex(data[3]) + " \"Join notification status\"")
    print(pad_text("XBee frame ID") + get_hex(data[4]))
    get_device_join_status(data[5])


def decode_join_notification(data):
    """
    The Xbee has received a join notification status packet (frame ID 0xA5).

    Args:
        data (list): The packet data as a collection of integers.
    """

    print(pad_text("XBee command ID") + get_hex(data[3]) + " \"Register joining device status\"")
    print("Parent:")
    print(pad_text("  Address (16-bit)") + get_hex(((data[4] << 8) + data[5]), 4))
    print("Joining Device:")
    print(pad_text("  Address (16-bit)") + get_hex(((data[6] << 8) + data[7]), 4))
    read_64_bit_address(data, 8, "  Address (64-bit)")
    get_join_status(data[16])


###########################################################################
# This section comprises utilities access by the above decoder functions  #
###########################################################################

def decode_at_common(data, x_cmd, no_param_message=""):
    """
    Code common to AT command-related decoders.

    Args:
        data             (list): The packet data as a collection of integers.
        x_cmd            (str):  The command information to print
        no_param_message (str):  Text to print if there is no parameter value. This
                                 is optional; if omitted, only the header info is
                                 printed.

    Returns:
        str: The AT command
    """

    cmd_str = chr(data[5]) + chr(data[6])
    print(pad_text("XBee command ID") + get_hex(data[3]) + " \"" + x_cmd + "\"")
    print(pad_text("XBee frame ID") + get_hex(data[4]))
    print(pad_text("XBee AT command") + "\"" + cmd_str + "\"")
    if no_param_message is True: decode_at_param_common(data, 7, 4, no_param_message)
    return cmd_str


def decode_at_param_common(data, start, delta, no_param_message):
    """
    Code used by 'decode_at_common()'.

    Args:
        data             (list): The packet data as a collection of integers.
        start            (int):  The index of the start of the information in the packet.
        delta            (int):  The length of the header data.
        no_param_message (str):  Text to print if there is no parameter value. This
                                 is optional; if omitted, only the header info is
                                 printed.
    """

    data_str = ""
    length = (data[1] << 8) + data[2] - delta
    if length > 0:
        for i in range(start, start + length): data_str += get_hex(data[i])
    else:
        data_str = no_param_message
    print(pad_text("Command parameter value") + data_str)


def print_basic_header(x_cmd, data, start):
    """
    Generic packet header decoding for a number of the above functions.

    Args:
        x_cmd (str):  The XBee command.
        data  (list): The packet data as a collection of integers.
        start (int):  The index of the start of the information in the packet.
    """

    print(pad_text("XBee command ID") + get_hex(data[start]) + " \"" + x_cmd + "\"")
    read_64_bit_address(data, start + 1)
    print(pad_text("Address (16-bit)") + get_hex(((data[start + 9] << 8) + data[start + 10]), 4))


def print_standard_header(x_cmd, data, start):
    """
    Generic packet header decoding for a number of the above functions.

    Args:
        x_cmd (str):  The XBee command.
        data  (list): The packet data as a collection of integers.
        start (int):  The index of the start of the information in the packet.
    """

    print(pad_text("XBee command ID") + get_hex(data[start]) + " \"" + x_cmd + "\"")
    print(pad_text("XBee frame ID") + get_hex(data[start + 1]))
    read_64_bit_address(data, start + 2)
    print(pad_text("Address (16-bit)") + get_hex(((data[start + 10] << 8) + data[start + 11]), 4))


def print_frame_data(data, start, length):
    """
    Display a packet's data bytes.

    Args:
        data   (list): The packet data as a collection of integers.
        start  (int):  The index in the packet of the data payload's first byte.
        length (int):  The number of bytes in the payload.

    Returns:
        list: The extracted data.
    """

    data_str = ""
    data_values = []
    if length > 0:
        for i in range(start, start + length):
            data_str += get_hex(data[i])
            data_values.append(data[i])
        print(pad_text("Frame data") + data_str)
    return data_values


def decode_node_data(data, start):
    """
    Generic Node Ident data extrator.

    Args:
        data (list): The packet data as a collection of integers.
        start (int): The index of the start of the data.
    """

    print(pad_text("Source address (16-bit)") + get_hex(((data[start] << 8) + data[start + 1]), 4))
    read_64_bit_address(data, start + 2, "Source address (64-bit)")

    index = start + 10
    node_str = ""
    done = False
    while done is False:
        if (data[index]) != 0x00:
            node_str += chr(data[index])
        else:
            done = True
        index += 1

    if node_str is True and node_str[0] != " ":
        print(pad_text("NI string") + node_str)
    else:
        print(pad_text("NI string") + "Default")

    print(pad_text("Parent address (16-bit)") + get_hex(((data[index] << 8) + data[index + 1]), 4))

    get_device_type(data[index + 2])
    get_source_event(data[index + 3])

    print(pad_text("Digi Profile ID") + get_hex(((data[index + 4] << 8) + data[index + 5]), 4))
    print(pad_text("Manufacturer ID") + get_hex(((data[index + 6] << 8) + data[index + 7]), 4))


###########################################################################
# This section comprises decoders for Zigbee data sent or received via an #
# XBee. This covers Zigbee Cluster Library (ZCL) frames, and Zigbee       #
# Device Objects (ZDO) entities                                           #
# NOTE Multi-byte ZCL frame entities are stored in little endian order,   #
#      ie. LSB first, MSB last                                            #
###########################################################################

def decode_zcl_frame(frame_data):
    """
    Decode a full ZCL frame.

    Args:
        frame_data (list): The packet data as a collection of integers.
    """

    has_man_spec = False
    is_global_cmd = True

    # Decode and display the frame control byte
    frame_ctrl = frame_data[0]
    frame_ctrl_str = get_binary(frame_ctrl)
    print(pad_text("  Frame Control Byte") + get_hex(frame_ctrl) + " [b" + frame_ctrl_str + "]")

    if frame_ctrl & 0x01 == 0x01:
        print(SPACE_STRING[0:TEXT_SIZE] + "  Command is specific to cluster")
        is_global_cmd = False
    else:
        print(SPACE_STRING[0:TEXT_SIZE] + "  Command is global to ZCL")

    if frame_ctrl & 0x08 == 0:
        print(SPACE_STRING[0:TEXT_SIZE] + "  Direction: client to server")
    else:
        print(SPACE_STRING[0:TEXT_SIZE] + "  Direction: server to client")

    if frame_ctrl & 0x04 == 0x04:
        print(SPACE_STRING[0:TEXT_SIZE] + "  Manufacturer-specific commands in data")
        has_man_spec = True
    else:
        print(SPACE_STRING[0:TEXT_SIZE] + "  No manufacturer-specific commands in data")

    if frame_ctrl & 0x10 == 0x10:
        print(SPACE_STRING[0:TEXT_SIZE] + "  Default response disabled")
    else:
        print(SPACE_STRING[0:TEXT_SIZE] + "  Default response enabled")

    index = 1
    if has_man_spec is True:
        manu_code = frame_data[1] + (frame_data[2] << 8)
        print(pad_text("  Manufacturer code") + get_hex(manu_code, 4))
        index = 3

    # Decode and display the ZCL frame header's remaining two bytes
    tran_seq_num = frame_data[index]
    cmd_id = frame_data[index + 1]
    print(pad_text("  Transaction seq. number") + get_hex(tran_seq_num))

    if is_global_cmd is True:
        if cmd_id < len(ZCL_CMDS):
            print(pad_text("  Global command") + get_hex(cmd_id) + " - " + ZCL_CMDS[cmd_id])
        else:
            print(pad_text("  Global command") + get_hex(cmd_id) + " - Unknown")
    else:
        print(pad_text("  Cluster command") + get_hex(cmd_id))

    # Payload is at 'index' + 2
    if is_global_cmd is True and has_man_spec is False:
        # Only decode global commands for now
        decode_zcl_cmd(cmd_id, frame_data, index + 2)
    else:
        # Dump the data, which contains Cluster-specific info
        data_str = ""
        for i in range(index + 2, len(frame_data)): data_str += get_hex(frame_data[i])
        print(pad_text("  Data") + data_str)


def decode_zcl_cmd(z_cmd, frame_data, start):
    """
    Jump table for general ZCL commands.

    Args:
        z_cmd      (int):  The ZCL command.
        frame_data (list): The packet data as a collection of integers.
        start      (int):  The start byte of the payload.
    """

    if z_cmd == ZCL_GLOBAL_CMD_READ_ATTR_REQ:
        decode_zcl_read_attribute_req(frame_data, start)
    elif z_cmd in (ZCL_GLOBAL_CMD_READ_ATTR_RSP, ZCL_GLOBAL_CMD_WRITE_ATTR_NO):
        decode_zcl_attribute_list(frame_data, start, ATT_TYPE_READ_RSP)
    elif z_cmd in (ZCL_GLOBAL_CMD_WRITE_ATTR_REQ, ZCL_GLOBAL_CMD_WRITE_ATTR_UND):
        decode_zcl_attribute_list(frame_data, start, ATT_TYPE_WRITE_REQ)
    elif z_cmd == ZCL_GLOBAL_CMD_WRITE_ATTR_RSP:
        decode_zcl_attribute_list(frame_data, start, ATT_TYPE_WRITE_RSP)
    elif z_cmd in (ZCL_GLOBAL_CMD_DISC_RCMDS_REQ, ZCL_GLOBAL_CMD_DISC_GCMDS_REQ):
        decode_cmds_req(frame_data, start)
    elif z_cmd in (ZCL_GLOBAL_CMD_DISC_RCMDS_RSP, ZCL_GLOBAL_CMD_DISC_GCMDS_RSP):
        decode_cmds_rsp(frame_data, start)
    else:
        print("  [ERROR] General command " + get_hex(z_cmd) + " not yet supported by this program")


def decode_zcl_read_attribute_req(frame_data, start):
    """
    Decode a ZCL read attribute request.

    Args:
        frame_data (list): The packet data as a collection of integers.
        start      (int):  The start byte of the payload.
    """

    att_str = ""
    plural_str = ""
    for i in range(start, len(frame_data), 2):
        value = frame_data[i] + (frame_data[i + 1] << 8)
        att_str += get_hex(value, 4) + ", "
    att_str = att_str[0:-2]
    if len(att_str) > 4: plural_str = "s"
    print(pad_text("  Attribute ID" + plural_str) + att_str)


def decode_zcl_attribute_list(frame_data, start, att_type):
    """
    Decode a ZCL read attribute response

    Args:
        frame_data (list): The packet data as a collection of integers.
        start      (int):  The start byte of the payload.
        att_type   (int):  The attribute ID.
    """

    index = start
    done = False
    while done is False:
        # Get the next attribute record
        if att_type == ATT_TYPE_READ_RSP:
            index = decode_zcl_attribute(frame_data, index)
        elif att_type == ATT_TYPE_WRITE_REQ:
            index = decode_zcl_attribute_write_req(frame_data, index)
        elif att_type == ATT_TYPE_WRITE_RSP:
            index = decode_zcl_attribute_write_rsp(frame_data, index)
        if index >= len(frame_data): done = True


def decode_zcl_attribute(frame_data, start):
    """
    Display an attribute's metadata.

    Args:
        frame_data (list): The packet data as a collection of integers.
        start      (int):  The start byte of the payload.
        att_type   (int):  The attribute ID.

    Returns:
        int: The updated index ('start' + attribute data length)
    """

    index = start

    print(pad_text("  Attribute ID") + get_hex(frame_data[index] + (frame_data[index + 1] << 8), 4))
    print(pad_text("  Attribute read status") + get_zcl_attribute_status(frame_data[index + 2]))
    print(pad_text("  Attribute type") + get_zcl_attribute_type(frame_data[index + 3]))

    if frame_data[index + 2] == 0:
        # Now get the attribute data
        index += (4 + decode_zcl_attribute_data(frame_data, index + 4, frame_data[index + 3]))
    else:
        # Attribute access unsuccessful - just skip it
        index += 4
        print("  [ERROR] Cannot read attribute data")
    return index


def decode_zcl_attribute_data(frame_data, start, data_type):
    """
    Get the attribute's data.

    Args:
        frame_data (list): The packet data as a collection of integers.
        start      (int):  The start byte of the payload.
        data_type  (int):  The data type of the index.

    Returns:
        int: The number of bytes of data read (ie. how far to move the pointer).
    """

    # How many bytes hold the attribute's data?
    if get_zcl_attribute_size(data_type) != -1:
        # The data is of a fixed size ('l')
        return decode_zcl_attribute_value(frame_data, start, data_type)
    # The data is not a fixed size
    return decode_zcl_attribute_collection(frame_data, start, data_type)


def decode_zcl_attribute_value(frame_data, start, data_type):
    """
    Extract and display a single, fixed-size value.

    Args:
        frame_data (list): The packet data as a collection of integers.
        start      (int):  The start byte of the payload.
        data_type  (int):  The data type of the index.

    Returns:
        int: The number of bytes of data read (ie. how far to move the pointer).
    """

    size = 1
    if data_type == 0x10:
        # Handle Boolean values separately
        val_str = "FALSE" if frame_data[start] == 0x00 else "TRUE"
        print(pad_text("  Attribute value") + val_str)
    else:
        # Handle all other numeric values
        size = get_zcl_attribute_size(data_type)
        value = 0
        bits = 0
        for j in range(start + size - 1, start - 1, -1):
            value += (frame_data[j] << bits)
            bits += 8
        print(pad_text("  Attribute value") + get_hex(value, size))
    return size


def decode_zcl_attribute_collection(frame_data, start, data_type):
    """
    Decode and display a collection value.

    Args:
        frame_data (list): The frame data as a series of integer values.
        start      (int):  The index of the start of the attribute or sub-attribute
                           data start within the frame
        data_type  (int):  The data type of the index.

    Returns:
        int: The number of bytes read for the data unit.
    """

    index = start
    data_str = ""
    if data_type in (0x41, 0x42):
        # Octet or char string
        length = frame_data[index]
        for j in range(index + 1, index + 1 + length): data_str += chr(frame_data[j])
        print(pad_text("  Attribute value") + data_str)
        index += (1 + length)
    elif data_type in (0x43, 0x44):
        # Long octet or char string
        length = frame_data[index] + (frame_data[index + 1] << 8)
        for j in range(index + 2, index + 2 + length): data_str += chr(frame_data[j])
        print(pad_text("  Attribute value") + data_str)
        index += (2 + length)
    elif data_type in (0x48, 0x50, 0x51):
        # Array, Set or Bag - collections of the same type so we need
        # to iterate to read in all the element values
        length = 0
        sub_type = frame_data[index]
        data_size = get_zcl_attribute_size(frame_data[sub_type])
        item_count = frame_data[index + 1] + (frame_data[index + 2] << 8)
        for j in range(0, item_count):
            # NOTE decode_zcl_attribute() expects to receive the start of the attribute
            #      (ie. header + data) not the start of a collection sub-attribute
            #      (ie. data), so we need to adjust the index back to get the
            #      correct bytes
            # NOTE Ignore the nesting limit for now
            adjusted_index = index + 3 + (j * data_size)
            length += decode_zcl_attribute_data(frame_data, adjusted_index, sub_type)
        index += (3 + length)
    elif data_type == 0x52:
        # Structure - collection of mixed types, so this is more complex
        item_count = frame_data[index] + (frame_data[index + 1] << 8)
        length = 0
        item_length = 0
        for j in range(0, item_count):
            adjusted_index = index + 2 + item_length
            sub_type = frame_data[adjusted_index]
            item_length = 1 + decode_zcl_attribute_data(frame_data, adjusted_index + 1, sub_type)
            length += item_length
        index += (2 + length)
    return index - start


def decode_zcl_attribute_write_req(frame_data, start):
    """
    Display an attribute's metadata

    Args:
        frame_data (list): The frame data as a series of integer values.
        start      (int):  The index of the start of the attribute or sub-attribute
                           data start within the frame

    Returns:
        int: The index of the next attribute in the data.
    """

    index = start
    print(pad_text("  Attribute ID") + get_hex(frame_data[index] + (frame_data[index + 1] << 8), 4))
    print(pad_text("  Attribute type") + get_zcl_attribute_type(frame_data[index + 2]))
    index += (3 + decode_zcl_attribute_data(frame_data, index + 3, frame_data[index + 2]))
    return index


def decode_zcl_attribute_write_rsp(frame_data, start):
    """
    Get the attribute's write status and ID

    Args:
        frame_data (list): The frame data as a series of integer values.
        start      (int):  The index of the start of the attribute or sub-attribute
                           data start within the frame
        data_type  (int):  The data type of the index.

    Returns:
        int: The number of bytes read for the data unit.
    """

    print(pad_text("  Attribute ID") + get_hex(frame_data[start] + (frame_data[start + 1] << 8), 4))
    print(pad_text("  Attribute write status") + get_zcl_attribute_status(frame_data[start]))
    return start + 3


def decode_cmds_req(frame_data, start):
    """
    Get Received or Generated Commands request.

    Args:
        frame_data  (list): The frame data as a series of integer values.
        start       (int):  The index of the start of the attribute data within
                            the ZCL frame, not the start of the attribute record.
    """

    print(pad_text("  First command ID") + get_hex(frame_data[start] + (frame_data[start + 1] << 8), 4))
    print(pad_text("  Max. command IDs returned") + str(frame_data[start + 2]))


def decode_cmds_rsp(frame_data, start):
    """
    Get Received or Generated Commands response.

    Args:
        frame_data (list): The frame data as a series of integer values.
        start      (int):  The index of the start of the attribute data within
                           the ZCL frame, not the start of the attribute record.
    """

    print(pad_text("  Command discovery complete?") + ("No" if frame_data[start] == 0 else "Yes"))
    for i in range(start + 1, len(frame_data)):
        print(pad_text("  Command ID " + str(i - start)) + get_hex(frame_data[i]))


def decode_zdo(frame_data, z_cmd):
    """
    Decode a ZDO packet.

    Args:
        frame_data (list): The frame data as a series of integer values.
        z_cmd      (int):  The 16-bit ZDO command code.
    """

    cmd_str = get_zdo_command(z_cmd)
    if cmd_str[0:8] != "[ERROR]":
        print(pad_text("  ZDO command") + cmd_str)
    else:
        print("[ERROR] ZDO command " + get_hex(z_cmd, 4) + " decoding not yet supported")
        return
    print(pad_text("  Transaction seq. number") + get_hex(frame_data[0]))

    if z_cmd > 0x7FFF:
        # All responses have frame byte 1 set to status
        get_zdo_status(frame_data[1])
    else:
        # All responses after 0x0000 have bytes 1 and 2 as a 16-bit address
        if 0x0000 < z_cmd < 0x8000 and z_cmd not in (0x0031, 0x0038):
            print(pad_text("  Address (16-bit)") + get_hex(frame_data[1] + (frame_data[2] << 8), 4))

    if z_cmd == 0x0000:
        # 16-bit Network Address Request
        read_64_bit_sserdda(frame_data, 1)
        get_zdo_type(frame_data[9])
        if frame_data[9] == 0x01: print(pad_text("  Start index") + str(frame_data[10]))
    elif z_cmd in (0x8000, 0x8001):
        # 16-bit Address Response / 64-bit Address Response
        read_64_bit_sserdda(frame_data, 2)
        print(pad_text("  Address (16-bit)") + get_hex(frame_data[10] + (frame_data[11] << 8), 4))

        if len(frame_data) > 12:
            print(pad_text("  No. of addresses") + get_hex(frame_data[12]))
            print(pad_text("  Start index") + str(frame_data[13]))
            count = 1
            for i in range(14, 14 + frame_data[12] * 2, 2):
                print(pad_text("  Address " + str(count)) + get_hex(frame_data[i] + (frame_data[i + 1] << 8), 4))
    elif z_cmd == 0x0001:
        # 64-bit Address Request
        get_zdo_type(frame_data[3])
        print(pad_text("  Start index") + str(frame_data[4]))
    elif cmd == 0x8002:
        # Node Descriptor Response
        get_node_desc(frame_data, 3)
    elif z_cmd == 0x0004:
        # Simple descriptor Request
        print(pad_text("  Endpoint") + str(frame_data[3]))
    elif z_cmd == 0x8004:
        # Simple Descriptor Response
        get_simple_desc(frame_data, 3)
    elif z_cmd == 0x0013:
        # ZDO Device Announce
        read_64_bit_sserdda(frame_data, 3)
        print(pad_text("  Capabilities") + get_device_capability(frame_data[11]))
    elif z_cmd == 0x0031:
        # Management LQI (Neighbor Table) Request
        print(pad_text("  Start index") + str(frame_data[1]))
    elif z_cmd == 0x0038:
        # Management Network Update Request
        scan_dur = frame_data[5]
        print(pad_text("  Scan Duration") + get_hex(scan_dur))
        if scan_dur < 6: print(pad_text("  Scan Count") + get_hex(frame_data[6]))
        if scan_dur == 0xFE: print(pad_text("  Network update ID") + get_hex(frame_data[6]))
        if scan_dur == 0xFF: print(pad_text("  Network manager address") + get_hex(frame_data[6] + (frame_data[7] << 8)))


###########################################################################
# This section comprises utility functions used by the primary decoders   #
# listed above.                                                           #
###########################################################################

def read_64_bit_address(frame_data, start=4, message="Address (64-bit)"):
    """
    Reads the bytes representing a 64-bit address from the passed-in blob.

    Args:
        frame_data (list): The frame data as a series of integer values.
        start      (int):  The index in the array at which the data is to be found.
        message    (str):  Optional message prefix.

    Returns:
        str: The 64-bit address as a string of 8 octets.
    """

    text = ""
    for i in range(start, start + 8): text += get_hex(frame_data[i])
    print(pad_text(message) + text)


def read_64_bit_sserdda(frame_data, start=4):
    """
    As read_64_bit_address(), but returning the address in little endian order.
    """

    text = ""
    for i in range(start + 7, start - 1, -1): text += get_hex(frame_data[i])
    print(pad_text("  Address (64-bit)") + text)


###########################################################################
# This section comprises XBee and Zigbee enumeration decoders used by the #
# primary decoders  listed above.                                         #
###########################################################################

def get_send_options(code):
    """
    Decode a Zigbee packet Send options byte and print a relevant status message.

    Args:
        code (int): The status code bitfield included in the packet.
    """

    text = ""
    if code & 0x01 == 0x01: text += "disable retries and route repair, "
    if code & 0x02 == 0x02: text += "apply changes, "
    if code & 0x20 == 0x20: text += "enable APS encryption, "
    if code & 0x40 == 0x40: text += "use the extended transmission timeout, "
    text = text[0:1].upper() + text[1:-2] if text else "None"
    print(pad_text("Options") + text)


def get_at_status(code):
    """
    Decode an AT command status packet's status byte and print a relevant status message.

    Args:
        code (int): The status code included in the packet.
    """

    opts = ("OK", "ERROR", "Invalid command", "Invalid parameter", "TX failure")
    for i in range(0, len(opts)):
        if code == i:
            print(pad_text("Command status") + opts[code])
            return
    print("[Error] Unknown AT status code " + get_hex(code))


def get_modem_status(code):
    """
    Decode a modem status packet's status byte and print a relevant status message.

    Args:
        code (int): The status code included in the packet.
    """

    opts = (0x00, "Hardware reset",
            0x01, "Watchdog reset",
            0x02, "Joined network",
            0x03, "Left network",
            0x04, "Configuration error or sync lost",
            0x05, "Coordinator realigned",
            0x06, "Coordinator started",
            0x07, "Network security updated",
            0x0B, "Network awoke",
            0x0C, "Network went to sleep",
            0x0D, "Voltage supply exceeded",
            0x0E, "Device cloud connected",
            0x0F, "Device cloud disconnected",
            0x11, "Modem configuration changed",
            0x12, "Access fault",
            0x13, "Fatal stack error",
            0x14, "PLKE table initiated",
            0x15, "PLKE table success",
            0x16, "PLKE table full",
            0x17, "PLKE not authorized",
            0x18, "PLKE invalid Trust Center request",
            0x19, "PLKE Trust Center update failure",
            0x1A, "PLKE bad EUI address",
            0x1B, "PLKE Link Key rejected",
            0x1C, "PLKE update occurred",
            0x1D, "PLKE Link Key table clear",
            0x1E, "Zigbee frequency agility requested channel change",
            0x1F, "Zigbee no joinable beacons; execute ATFR",
            0x20, "Zigbee token space recovered",
            0x21, "Zigbee token space unrecoverable",
            0x22, "Zigbee token space corrupt",
            0x23, "Zigbee dual-mode metaframe error",
            0x24, "BLE connect",
            0x25, "BLE disconnect",
            0x34, "Bandmask configuration failed",
            0x80, "Stack reset",
            0x81, "FIB bootloader reset",
            0x82, "Send or join command issued with connect from AP",
            0x83, "AP not found",
            0x84, "PSK not configured",
            0x87, "SSID not found",
            0x88, "Failed to join with security enabled",
            0x89, "Core lockup or crystal reset failure",
            0x8A, "Invalid channel",
            0x8B, "Low VCC reset",
            0x8E, "Failed to join AP")

    if code in opts:
        print(pad_text("Modem status") + opts[opts.index(code) + 1])
        return

    if code >= 0x80:
        print(pad_text("Modem status") + "Stack Error")
        return

    print("[Error] Unknown modem status code " + get_hex(code))


def get_packet_status(code):
    """
    Decode the packet's status byte and print the relevant status message.

    Args:
        code (int): The status code included in the packet.
    """

    text = ""
    if code == 0x00: text = "packet not acknowledged, "
    if code & 0x01: text += "packet acknowledged, "
    if code & 0x02: text += "broadcast packet, "
    if code & 0x20: text += "APS-encrypted packet, "
    if code & 0x40: text += "End-Device sent packet, "
    text = text[0:1].upper() + text[1:-2]
    print(pad_text("Status") + text)


def get_delivery_status(code):
    """
    Decode the packet's address delivery status byte and print the relevant status message.

    Args:
        code (int): The status code included in the packet.
    """

    opts = (0x00, "Success",
            0x01, "MAC ACK failure",
            0x02, "CCA failure",
            0x03, "Packet not transmitted and purged",
            0x04, "Physical error on the interface",
            0x15, "Invalid destination endpoint",
            0x18, "No buffers available",
            0x21, "Network ACK failure",
            0x22, "Not joined to network",
            0x23, "Self-addressed",
            0x24, "Address not found",
            0x25, "Route not found",
            0x26, "Broadcast relay not heard",
            0x2B, "Invalid binding table index",
            0x2C, "Invalid endpoint",
            0x2D, "Attempted broadcast with APS transmission",
            0x2E, "Attempted unicast with APS transmission, but EE=0",
            0x31, "Software error occurred",
            0x32, "Resource error: lack of free buffers, timers etc.",
            0x74, "Data payload too large",
            0x75, "Indirect message unrequested",
            0x76, "Client socket creation attempt failed",
            0xBB, "Key not authorized")

    if code in opts:
        print(pad_text("Delivery status") + opts[opts.index(code) + 1])
        return

    print("[ERROR] Unknown Delivery status code " + get_hex(code))


def get_discovery_status(code):
    """
    Decode the packet's address discovery status byte and print the relevant status message.

    Args:
        code (int): The status code included in the packet.
    """

    opts = ("No Discovery Overhead", "Address Discovery", "Route Discovery", "Address and Route", "Extended timeout discovery")

    if -1 < code < 4:
        print(pad_text("Discovery status") + opts[code])
    elif code == 0x40:
        print(pad_text("Discovery status") + opts[4])
    else:
        print("[ERROR] Unknown Discovery status code " + get_hex(code))


def get_zcl_attribute_status(code):
    """
    Decode the status of a ZCL attribute access operation.

    Args:
        code (int): The status code included in the packet.

    Returns:
        str: The ZCL attribute status.
    """

    opts = (0x00, "Success",
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
            0xc3, "Not found")

    if code in opts: return opts[opts.index(code) + 1]
    return "Unknown"


def get_zcl_attribute_type(code):
    """
    Determine a ZCL attribute's data type from its type code.

    Args:
        code(int): The ZCL data type code included in the packet.

    Returns:
        str: The ZCL attribute type.
    """

    opts = (0x00, "NULL",
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
            0xff, "UNK")

    if code in opts: return opts[opts.index(code) + 1]
    return "OPAQUE"


def get_zcl_attribute_size(code):
    """
    Determine the number of bytes a given ZCL attribute takes up.

    Args:
        code (int): The attribute size code included in the packet.

    Returns:
        int: size of the attribute data in bytes, or -1 for error/no size.
    """

    opts = (0x00, 0,
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
            0xff, 0)

    for i in range(0, len(opts), 2):
        if code == opts[i]: return opts[i + 1]
    return -1


def get_zdo_command(code):
    """
    Display a ZDO request or response command name.

    Args:
        code (int): The ZDO command code included in the packet.

    Returns:
        str: The command name.
    """

    opts = ("16-bit Address", 0x0000,
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
            "Management Network Update", 0x0038)

    for i in range(0, len(opts), 2):
        # Look at the lower bits for comparison as bit 15 is what
        # distinguishes responses (set) from requests (unset)
        if code & 0x7FFF == opts[i + 1]:
            # Append the appropriate message type
            return opts[i] + (" Response" if code > 0x7FFF else " Request")
    return "[ERROR] Unknown ZDO command " + get_hex(code, 4)


def get_zdo_type(code):
    """
    Display the ZDO request type as embedded in the request.

    Args:
        code (int): The request type code included in the packet.
    """

    if code == 0x00:
        print(pad_text("  Request type") + "Single device response")
    elif code == 0x01:
        print(pad_text("  Request type") + "Extended response")
    else:
        print("[ERROR] Unknown ZDO request type " + get_hex(code))


def get_zdo_status(code):
    """
    Display the ZDO status code embedded in the response.

    Args:
        code (int): The status code included in the packet.
    """

    print(pad_text("  Response status") + get_zcl_attribute_status(code))


def get_node_desc(frame_data, start):
    """
    Display the ZDO Node Descriptor response.

    Args:
        frame_data (list): The packet data.
        start      (int):  The index of the start of the descriptor.
    """

    # Node Descriptor Byte 1
    get_device_type((frame_data[start] & 0xE0) >> 5)
    if frame_data[start] & 0x10 == 0x10:
        print(pad_text("  Complex descriptor available") + "Yes")
    else:
        print(pad_text("  Complex descriptor available") + "No")
    if frame_data[start] & 0x08 == 0x08:
        print(pad_text("  User descriptor available") + "Yes")
    else:
        print(pad_text("  User descriptor available") + "No")

    # Byte 2
    flags = get_binary(frame_data[start + 1])
    print(pad_text("  APS flags") + "b" + flags[0:3])
    opts = ("868MHz", "R", "900MHz", "2.4GHz", "R")
    text = ""
    for i in range(3, 8):
        if flags[i] == "1": text = opts[i - 3]
    if text == "R": text = "[ERROR] Reserved band indicated"
    print(pad_text("  Frequency band") + text)

    # Byte 3
    text = get_device_capability(frame_data[start + 2])
    print(pad_text("  MAC capabilities") + text)

    # Bytes 4 and 5
    print(pad_text("  Manufacturer ID") + get_hex(frame_data[start + 3] + (frame_data[start + 4] << 8), 4))

    # Byte 6
    print(pad_text("  Max. buffer size") + get_hex(frame_data[start + 5]))

    # Bytes 7 and 8
    print(pad_text("  Max. incoming transfer size") + get_hex(frame_data[start + 6] + (frame_data[start + 7] << 8)), 4)

    # Bytes 9 and 10
    print(pad_text("  Server mask") + get_hex(frame_data[start + 8] + (frame_data[start + 9] << 8)), 4)

    # Bytes 11 and 12
    print(pad_text("  Max. outgoing transfer size") + get_hex(frame_data[start + 10] + (frame_data[start + 11] << 8)), 4)

    # Byte 13
    text = ""
    if frame_data[start + 12] & 0x80 == 0x80: text += "extended active endpoint list available, "
    if frame_data[start + 12] & 0x40 == 0x40: text += "extended simple descriptor list available, "
    text = text[0:1].upper() + text[1:-2] if text else "No bits set"
    print(pad_text("  Descriptor capability field") + text)


def get_simple_desc(frame_data, start):
    """
    Display the ZDO Simple Descriptor response.

    Args:
        frame_data (list): The packet data.
        start      (int):  The index of the start of the descriptor.
    """

    print(pad_text("  Endpoint") + get_hex(frame_data[start]))
    print(pad_text("  App profile ID") + get_hex(frame_data[start + 1] + (frame_data[start + 2] << 8), 4))
    print(pad_text("  App device ID") + get_hex(frame_data[start + 3] + (frame_data[start + 4] << 8), 4))
    print(pad_text("  App device version") + get_hex(frame_data[start + 5] >> 4))

    count = frame_data[start + 6]
    print(pad_text("  Input cluster count") + get_hex(count))
    if count != 0:
        # Display the list of input clusters
        text = ""
        for i in range(7, 7 + (count * 2), 2): text += (get_hex(frame_data[i] + (frame_data[i + 1] << 8), 4) + ", ")
        print(pad_text("  Input clusters") + text[0:-2])
        start += (count * 2)

    count = frame_data[start + 7]
    print(pad_text("  Output cluster count") + get_hex(count))
    if count != 0:
        # Display the list of output clusters
        text = ""
        for i in range(7, 7 + (count * 2), 2): text += (get_hex(frame_data[i] + (frame_data[i + 1] << 8), 4) + ", ")
        print(pad_text("  Output clusters") + text[0:-2])


def get_digital_channel_mask(frame_data, start):
    """
    Determine and report which, if any, XBee digital IOs have been enabled
    for sampling and include the sample digital data.

    Args:
        frame_data (list): The current frame data.
        start      (int):  The index in the data of the digital channel info.
    """

    n_dig = (frame_data[start] << 8) + frame_data[start + 1]
    s_dig = (frame_data[start + 3] << 8) + frame_data[start + 4]
    opts = ("DIO0", "DIO1", "DIO3", "DIO4", "DIO5", "DIO6", "DIO7",
            "N/A", "N/A", "DIO10", "DIO11", "DIC12", "N/A", "N/A", "N/A")
    text = ""
    bad = False

    for i in range(0, 16):
        num = int(math.pow(2, i))
        if n_dig & num == num:
            # Digital IO enabled
            text += opts[i]

            # Is the IO permitted?
            if opts[i] == "N/A":
                bad = True
            else:
                # Is the sample HIGH or LOW?
                text += (" (HIGH), " if s_dig & num == num else " (LOW), ")

    # Remove the final comma and space from the message string
    text = text[0:-2] if text else "None"
    print(pad_text("Enabled Digital IOs") + text)
    if bad is True: print("[ERROR] Unavailable Digital IOs selected")


def get_analog_channel_mask(frame_data, start):
    """
    Determine and report which, if any, XBee analog IOs have been enabled
    for sampling and so have supplied data in the current frame.

    Args:
        frame_data (list): The current frame data.
        start      (int):  The index in the data of the analog sample data.
    """

    code = frame_data[18]
    opts = ("AD0", "AD1", "AD2", "AD3", "N/A", "N/A", "N/A", "VIN")
    text = ""
    bad = False
    count = 0

    for i in range(0, 8):
        num = int(math.pow(2, i))
        if code & num == num:
            # Analog IO enabled
            text += opts[i]
            if opts[i] == "N/A":
                bad = True
            else:
                # Read the sample value and add to the display string
                sample = (frame_data[start + count] << 8) + frame_data[start + count + 1]
                text += " (" + get_hex(sample, 4) + "), "
                count += 2

    # Remove the final comma and space from the message string
    text = text[0:-2] if text else "None"
    print(pad_text("Enabled Analog IOs") + text)
    if bad is True: print("[ERROR] Unavailable Analog IOs selected")


def get_onewire_status(code):
    """
    Determine and display an XBee's OneWire sensor status, if enabled.

    Args:
        code (int): The status code included in the packet.
    """

    opts = ("A/D sensor read", 0x01, "temperature sensor read", 0x02, "water present", 0x60)
    text = ""
    for i in range(0, len(opts), 2):
        if code & opts[i + 1] == opts[i + 1]: text += opts[i] + ", "

    # Remove the final comma and space from the message string
    text = text[0:1].upper() + text[1:-2]
    print(pad_text("OneWire sensor status") + text)


def get_device_type(code):
    """
    Determine the device type embedded in a Node Ident packet.

    Args:
        code (int): The type code included in the packet.
    """

    opts = ("Coordinator", "Router", "End Device")
    if code < 0 or code > 2:
        print("[ERROR] Unknown Node Identification device type " + str(code))
    else:
        print(pad_text("Device type") + opts[code])


def get_source_event(code):
    """
    Determine the device type embedded in a Node Ident packet.

    Args:
        code (int): The event source code included in the packet.
    """

    opts = ("AT command \"ND\" issued", "Button pushed", "Network join", "Device power-cycle")
    if code < 0 or code > 3:
        print("[ERROR] Unknown Node Identification event type " + str(code))
    else:
        print(pad_text("Source event") + opts[code])


def get_bootloader_msg(code):
    """
    Determine the bootloader message embedded in a firmware update packet.

    Args:
        code (int): The message code included in the packet.
    """

    opts = (0x06, "ACK", 0x15, "NACK", 0x40, "No MAC ACK",
            0x51, "Query - Bootload not active", 0x52, "Query response")
    if code in opts:
        print(pad_text("Bootloader message") + opts[opts.index(code) + 1])
        return
    print("[ERROR] Unknown Firmware Update Bootloader message value " + get_hex(code))


def get_device_capability(code):
    """
    Determine the device capability data embedded in a device announce packet.

    Args:
        code (int): The message code included in the packet.

    Returns:
        str: The capability list.
    """

    opts = ("alternate PAN Coordinator", "device type", "power source", "receiver on when idle",
            "R", "R", "security capable", "allocate address")
    cap_list = ""
    for i in range(0, 8):
        if (code & (1 << i)) == (1 << i):
            if opts[i] == "R":
                cap_list += "reserved function, "
            else:
                cap_list += opts[i] + ", "
    cap_list = cap_list[0:1].upper() + cap_list[1:-2]
    return cap_list


def get_join_status(code):
    """
    Determine a join notification status embedded in a join notification packet.

    Args:
        code (int): The message code included in the packet.
    """

    opts = (0x00, "Standard security secured rejoin", 0x01, "Standard security unsecured join",
            0x02, "Device left", 0x03, "Standard security unsecured rejoin",
            0x04, "High security secured rejoin", 0x05, "High security unsecured join",
            0x07, "High security unsecured rejoin")
    if code in opts:
        print(pad_text("Join status") + opts[opts.index(code) + 1])
        return
    print("[ERROR] Unknown join status value " + get_hex(code))


def get_device_join_status(code):
    """
    Determine the device joining status data embedded in a device joining packet.

    Args:
        code (int): The message code included in the packet.
    """

    opts = (0x00, "Success", 0x01, "Key too long", 0xB1, "Address not found in key table",
            0xB2, "Invalid key value", 0xB3, "Invalid address",
            0xB4, "Key table full", 0xBD, "Invalid install code",
            0x07, "Key not found")
    if code in opts:
        print(pad_text("Device join status") + opts[opts.index(code) + 1])
        return
    print("[ERROR] Unknown device joining status value " + get_hex(code))


###########################################################################
# This section comprises generic utility functions used by all parts of   #
# the program                                                             #
###########################################################################

def get_hex(num, digits=2):
    """
    Convert an integer to a hex string of 'digit' characters.

    Args:
        num    (int): The value to be converted.
        digits (int): The number of characters the final string should comprise. Default: 2.

    Returns:
        str: The hex string.
    """

    format_str = "{:0" + str(digits) + "X}"
    return format_str.format(num)


def prefix(a_str):
    """
    Pad a hex string with 0x if required.

    Args:
        a_str (str): The source hex string.

    Returns:
        str: The hex string with or without a prefix.
    """

    return "0x" + a_str if prefixed is True else a_str


def pad_text(a_str, do_tail=True):
    """
    Pad the end of the passed string 's' with spaces up to a maximum
    indicated by 'TEXT_SIZE' and, if 'e' is True, append ": ".

    Args:
        a_str   (str):  The string to be padded.
        do_tail (bool): Should the returned string be tailed with ": ".

    Returns:
        str: The padded text.
    """

    text = a_str + SPACE_STRING[0:(TEXT_SIZE - len(a_str))]
    if do_tail is True: text += ": "
    return text


def get_binary(num):
    """
    Convert an 8-bit value to a binary string of 1s and 0s.

    Args:
        num (int): The value to be converted.

    Returns:
        str: The binary string.
    """

    bin_str = ""
    for i in range(0, 8):
        bit = int(math.pow(2, i))
        bin_str = ("1" if (num & bit) == bit else "0") + bin_str
    return bin_str


def decode_endian(value_array, is_little_endian=True):
    """
    Return a 16-bit value from two 8-bit values, to the specified endianism.

    Args:
        value_array      (list): The two 8-bit values to be processed.
        is_little_endian (bool): Is the final value little endian or not. Default: True.

    Returns:
        int: The 16-bit value.
    """

    if is_little_endian is True: return value_array[0] + (value_array[1] << 8)
    return (value_array[0] << 8) + value_array[1]


def show_help():
    """
    Display app help info.
    """

    show_version()
    print("Usage:")
    print("  python xbp.py <XBee packet hex string>")
    print("\nThe XBee packet string must not contains spaces.\n")
    print("Options:")
    print("  -e / --escape <true/false> - Use escaping when decoding packets. Default: true")
    print("  -d / --debug <true/false>  - Show extra debug information. Default: false")
    print("  -v / --version             - Show version information")
    print("  -h / --help                - Show help information\n")


def show_version():
    """
    Display app version number.
    """

    print("Version " + APP_VERSION)
    print("Copyright (c) 2018-19 Tony Smith (@smittytone)")
    print("Licence: MIT <https://github.com/smittytone/XBeeParser/blob/master/LICENSE>\n")


###########################################################################
# The main entry point. Here we decode the options (if any) selected by   #
# the user, and the Xbee packet data provided via the command line        #
###########################################################################

if __name__ == '__main__':
    print("XBeeParser -- the XBee Packet Decoder")
    if len(sys.argv) > 1:
        # Run through the args to find options only
        arg_idx = 1
        packet = ""
        done = False
        while done is False:
            cmd = sys.argv[arg_idx]
            if cmd in ("-v", "--version"):
                # Print the version
                show_version()
                arg_idx += 1
            elif cmd in ("-h", "--help"):
                # Print help
                show_help()
                arg_idx += 1
                sys.exit(0)
            elif cmd in ("-e", "--escape"):
                # Are we escaping?
                if arg_idx < len(sys.argv) - 1:
                    value = sys.argv[arg_idx + 1].lower()
                    if value in ("true", "yes", "1"):
                        escaped = True
                        print("Packet decoding will use escaping")
                    elif value in ("false", "no", "0"):
                        escaped = False
                        print("Packet decoding will not use escaping")
                    else:
                        print("[ERROR] bad argument for -e/--escape: " + value)
                        sys.exit(1)
                    arg_idx += 2
                else:
                    print("[ERROR] missing argument for -e/--escape")
                    sys.exit(1)
            elif cmd in ("-p", "--prefix"):
                # Are we prefixing?
                if arg_idx < len(sys.argv) - 1:
                    value = sys.argv[arg_idx + 1].lower()
                    if value in ("true", "yes", "1"):
                        prefixed = True
                        print("Hex values will be prefixed with 0x")
                    elif value in ("false", "no", "0"):
                        prefixed = False
                        print("Hex values will not be prefixed with 0x")
                    else:
                        print("[ERROR] bad argument for -p/--prefix: " + value)
                        sys.exit(1)
                    arg_idx += 2
                else:
                    print("[ERROR] missing argument for -p/--prefix")
                    sys.exit(1)
            elif cmd in ("-d", "--debug"):
                # Are we debugging?
                if arg_idx < len(sys.argv) - 1:
                    value = sys.argv[arg_idx + 1].lower()
                    if value in ("true", "yes", "1"):
                        debug = True
                        print("Extra debugging information will be printed during decoding")
                    elif value in ("false", "no", "0"):
                        debug = False
                    else:
                        print("[ERROR] bad argument for -d/--debug: " + value)
                        sys.exit(1)
                    arg_idx += 2
                else:
                    print("[ERROR] missing argument for -d/--debug")
                    sys.exit(1)
            elif cmd[0] == "-":
                # Mis-formed option
                print("[ERROR] unrecognized option: " + cmd)
                sys.exit(1)
            else:
                arg_idx += 1
            if arg_idx >= len(sys.argv): done = True

        # Run through the args to find the packet data and process it
        # NOTE We do it this was so that we take into account options
        #      placed after the packet
        skip = False
        for oct_idx in range(1, len(sys.argv)):
            if skip is False:
                octet = sys.argv[oct_idx]
                if octet[0] != "-":
                    packet += octet
                else:
                    skip = True
            else:
                skip = False
        if len(packet) > 8:
            # Frame has to have at least four octets
            process_packet(packet)
    else:
        print("[ERROR] No Data provided")
    sys.exit(0)
