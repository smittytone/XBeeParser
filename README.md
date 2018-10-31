# XBeeParser #

This is an XBee packet decoder written in Python 3.

### Usage ###

Run XBeeParser at the command line, providing a code XBee packet as a string of hexadecimal octets:

```bash
python xbp.py 7e0020950013a20040522baa7d84027d840013a20040522baa2000fffe0101c105101e1b
```

The XBee packet string need not be a single string; you can also include spaces:

```bash
python xbp.py 7e 00 20 95 00 13 a2 00 40 52 2b aa 7d 84 02 7d 84 00 13 a2 00 40 52 2b aa 20 00 
    ff fe 01 01 c1 05 10 1e 1b
```

### Escaping ###

By default, XBeeParser assumes packets have been escaped, but this can be disabled with the `-e` or `--escape` switch. Follow this with `false` to disable escaping (or `true` to be explicit about enabling escaping.

### Options ###

XBeeParser has the following options:

| Short | Long | Values | Description |
| :-: | --- | :-: | --- |
| `-e` | `--escape` | `true` or `false` | Use escaping when decoding packets |
| `-d` | `--debug` | `true` or `false` | Show extra debug information |
| `-v` | `--version` | N/A | Show version information |
| `-h` | `--help` | N/A | Show help information |

### Examples ###

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
```

```bash
python xbp.py 7e 00 14 08 09 4b 59 5a 69 67 42 65 65 41 6c 6c 69 61 6e 63 65 30 39 92
```

This generates the following output:

```bash
XBee frame found
Frame length                  : 20 bytes
XBee command ID               : 08 "Issue local AT command"
XBee frame ID                 : 09
XBee AT command               : "KY"
Command parameter value       : 5A6967426565416C6C69616E63653039
```

## Licence and Copyright ##

XBeeParser's source code is issued under the MIT license.

XBeeParser source code is copyright &copy; 2018, Tony Smith.
