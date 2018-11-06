# XBeeParser 1.0.2 #

This is an XBee packet decoder written in Python 3.

It is a work in progress. Version 1.0.2 decodes all the standard XBee packets, and provides further decoding of a limited (but growing) selection of Zigbee Device Object (ZDO) commands (eg. 16-bit network address request) and general (aka ‘global’) Zigbee Cluster Library commands (eg. Read Attribute).

## Usage ##

Run XBeeParser at the command line and provide a code XBee packet as a string of hexadecimal octets:

```bash
python xbp.py 7e0020950013a20040522baa7d84027d840013a20040522baa2000fffe0101c105101e1b
```

The XBee packet string need not be a single string; you can also include spaces:

```bash
python xbp.py 7e 00 20 95 00 13 a2 00 40 52 2b aa 7d 84 02 7d 84 00 13 a2 00 40 52 2b aa 20 00 
    ff fe 01 01 c1 05 10 1e 1b
```

### Make XBeeParser Global ###

To simplify usage of XBeeParser, run the following commands:

1. `mv xbp.py /usr/local/bin/xbp`
2. `chmod +x /usr/local/bin/xbp`

Then you run XBeeParser from any location in your filesystem:

```bash
xbp 7e 00 05 88 05 45 45 00 e8
```

### Escaping ###

By default, XBeeParser assumes packets have been escaped, but this can be disabled with the `-e` or `--escape` switch. Follow this with `false` to disable escaping (or `true` to be explicit about enabling escaping.

## Options ##

XBeeParser has the following options:

| Short | Long | Values | Description |
| :-: | --- | :-: | --- |
| `-e` | `--escape` | `true` or `false` | Use escaping when decoding packets. Default: `true` |
| `-d` | `--debug` | `true` or `false` | Show extra debug information. Default: `false` |
| `-v` | `--version` | N/A | Show version information |
| `-h` | `--help` | N/A | Show help information |

## Examples ##

#### Using Options ####

```bash
python xbp.py -d true -e false 7e0020950013a20040522baa7d84027d840013a20040522baa2000fffe0101c105101e1b
```

This generates the following output:

```bash
Extra debugging information will be printed during decoding
Packet decoding will not use escaping
7E0020950013A20040522BAA7D84027D840013A20040522BAA2000FFFE0101C105101E1B
XBee frame found
Frame length                  : 32 bytes
XBee command ID               : 95 "Node identification indicator response"
Address (64-bit)              : 0013A20040522BAA
Address (16-bit)              : 7D84
Status                        : Packet a Broadcast Packet
Address (16-bit)              : 7D84
Address (64-bit)              : 0013A20040522BAA
NI string                     : Default
Parent address (16-bit)       : FFFE
Device type                   : Router
Source event                  : Pushbutton
Digi Profile ID               : C105
Manufacturer ID               : 101E
Checksum                      : 1B
```

#### Zigbee ####

```bash
python xbp.py 7E 002D 91 0013A200 40522BAA 06FC 00 00 8038 0000 01 01 00 00F8FF07 1D00 0000 10 54 5E 69 5B 4B 48 44 48 55 55 57 46 51 41 44 4B 6E
```

This generates the following output:

```bash
XBee frame found
Frame length                  : 45 bytes
XBee command ID               : 91 "Zigbee explicit RX indicator"
Address (64-bit)              : 0013A20040522BAA
Address (16-bit)              : 06FC
Source endpoint               : 00
Destination endpoint          : 00
Cluster ID                    : 8038
Profile ID                    : 0000
Status                        : Packet acknowledged
Frame data                    : 010000F8FF071D00000010545E695B4B484448555557465141444B
  ZDO command                 : Management Network Update Response
  Transaction seq. number     : 01
  Response status             : Success
Checksum                      : 6E
```

## Release Notes ##

- 1.0.2
    - Update help, version info
- 1.0.1 *November 5, 2018*
    - Fix incorrect attribute type display
    - Fix attribute value display bug
- 1.0.0 *November 2, 2018*
    - Initial release
## Licence and Copyright ##

XBeeParser's source code is issued under the [MIT license](LICENSE).

XBeeParser source code is copyright &copy; 2018, Tony Smith.

XBee is a brand of Digi International.