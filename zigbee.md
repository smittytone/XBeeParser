# Zigbee Cluster Library Crib #

Being a selection of tables outlining key aspects of the ZCL data structure.

## General ZCL Frame Format ##

| Byte i | i+0/+1 | i+0/+2 | i+1/+3 | i+2/+4 | i+3/+5... |
| :-: | :-: | :-: | :-: | :-: | :-: |
| Frame&nbsp;Control | Manufacturer&nbsp;Code<br />LSB | Manufacturer&nbsp;Code<br />MSB | Transaction&nbsp;Sequence<br />Number | Command | Payload |

### Frame Control Field ###

| Bits 7-5 | Bit 4 | Bit 3 | Bit 2 | Bits  1-0 |
| :-: | :-: | :-: | :-: | :-: |
| Reserved | Disable&nbsp;Default<br />Response | Direction | Manufacturer-specific | Frame&nbsp;Type |

#### Frame Type Sub-field ####

| Bit 1 | Bit 0 | Meaning |
| --- | --- | :-- |
| 0 | 0 | Command is global to all clusters |
| 0 | 1 | Command is cluster-specific |

#### Manufacturer Specific Sub-field ####

| Bit 2 | Meaning |
| --- | :-- |
| 0 | Not a manufacturer-specific command |
| 1 | A manufacturer-specific commands, ie. frame contains a Manufacturer Code  |

#### Direction Sub-field ####

| Bit 3 | Meaning |
| --- | :-- |
| 0 | Client -> Server |
| 1 | Server -> client |

#### Disable Default Response Sub-field ####

| Bit 4 | Meaning |
| --- | :-- |
| 0 | The Default Response command will be returned |
| 1 | The Default Response command will only be returned if there is an error |

### Global Commands ###

| Command | Description |
| :-: | :-- |
| 0x00 | [Read Attributes](#read-attributes-request) |
| 0x01 | [Read Attributes Response](#read-attributes-response) |
| 0x02 | [Write Attributes](#write-attributes-request) |
| 0x03 | [Write Attributes Undivided](#write-attributes-request) |
| 0x04 | [Write Attributes Response](#write-attributes-request) |
| 0x05 | [Write Attributes No Response](#write-attributes-request) |
| 0x06 | [Configure Reporting](#configure-reporting-request) |
| 0x07 | [Configure Reporting Response](#configure-reporting-response) |
| 0x08 | [Read Reporting Configuration](#read-reporting-configuration-request) |
| 0x09 | [Read Reporting Configuration Response](#configure-reporting-response) |
| 0x0A | [Report attributes](#report-attributes-request) |
| 0x0B | [Default Response](#default-response) |
| 0x0C | [Discover Attributes](#discover-attributes-request) |
| 0x0D | [Discover Attributes Response](#discover-attributes-response) |
| 0x0E | [Read Attributes Structured](#read-attributes-structured-request) |
| 0x0F | [Write Attributes Structured](#write-attributes-structured-request) |
| 0x10 | [Write Attributes Structured response](#write-attributes-structured-response) |
| 0x11 | [Discover Commands Received](#discover-commands-received-request) |
| 0x12 | [Discover Commands Received Response](#discover-commands-received-response) |
| 0x13 | [Discover Commands Generated](#discover-commands-received-request) |
| 0x14 | [Discover Commands Generated Response](#discover-commands-received-response) |
| 0x15 | [Discover Attributes Extended](#discover-attributes-extended-request) |
| 0x16 | [Discover Attributes Extended Response](#discover-attributes-extended-response) |

#### Read Attributes Request ###

| Octets: Variable | 1 | 1 | ... | 1  | 1 |
| :-: | :-: | :-: | :-: | :-: | :-: |
| ZCL Header | Attribute ID 1<br />LSB | Attribute ID 1<br />MSB | ... | Attribute ID n<br />LSB | Attribute ID n<br />MSB |  

#### Read Attributes Response ####

| Octets: Variable | Variable | Variable | ... | Variable |
| :-: | :-: | :-: | :-: | :-: |
| ZCL Header | Attribute 1 | Attribute 2 | ... | Attribute n |

##### Attribute x Record #####

| Octets: 2 | 1 | 0/1 | 0/Variable |
| :-: | :-: | :-: | :-: |
| Attribute ID | Status | Data Type<br />(is status == SUCCESS) | Value<br />(is status == SUCCESS) |

##### Value Field - Type: Array, Set, Bag #####

| Octets: 1 | 1 | 1 | Variable | ... | Variable |
| :-: | :-: | :-: | :-: | :-: | :-: |
| Type | No. of Elements<br />LSB | No. of Elements<br />MSB | Element 1 Value | ... | Element m Value |

##### Value Field - Type: Structure #####

| Octets: 1 | 1 | 1 | Variable | ... | 1 | Variable |
| :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| No. of Elements<br />LSB | No. of Elements<br />MSB | Element 1 Type | Element 1 Value | ... | Element m Type | Element m Value |

#### Write Attributes Request ####
#### Write Attributes Undivided Request ####
#### Write Attributes No Response Request ####

| Octets: Variable | Variable | Variable | ... | Variable |
| :-: | :-: | :-: | :-: | :-: |
| ZCL Header | Attribute 1 | Attribute 2 | ... | Attribute n |

##### Attribute x Record #####

| Octets: 2 | 1 | Variable |
| :-: | :-: | :-: |
| Attribute ID | Data Type | Value |

#### Configure Reporting Request ####

| Octets: Variable | Variable | Variable | ... | Variable |
| :-: | :-: | :-: | :-: | :-: |
| ZCL Header | Attribute 1 | Attribute 2 | ... | Attribute n |

##### Attribute x Record #####

| Octets: 1 | 1 | 1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/1 | 0/Variable | 0/1 | 0/1 |
| :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| Direction | Attribute ID<br />LSB | Attribute ID<br />MSB | Data Type | Min. Reporting<br />Interval LSB | Min. Reporting<br />Interval MSB | Max. Reporting<br />Interval LSB | Max. Reporting<br />Interval MSB | Reportable<br />change | Timeout<br />LSB | Timeout<br />MSB |

#### Configure Reporting Response ####
#### Read Reporting Configuration Response ####

| Octets: Variable | 4 | 4 | ... | 4 |
| :-: | :-: | :-: | :-: | :-: |
| ZCL Header | Attribute 1 | Attribute 2 | ... | Attribute n |

##### Attribute x Record #####

| Octets: 1 | 1 | 1 | 1 |
| :-: | :-: | :-: | :-: |
| Status | Direction | Attribute ID<br />LSB | Attribute ID<br />MSB |

#### Read Reporting Configuration Request ####

| Octets: Variable | 3 | 3 | ... | 3 |
| :-: | :-: | :-: | :-: | :-: |
| ZCL Header | Attribute 1 | Attribute 2 | ... | Attribute n |

##### Attribute x Record #####

| Octets: 1 | 1 | 1 |
| :-: | :-: | :-: |
| Direction | Attribute ID<br />LSB | Attribute ID<br />MSB |

#### Report Attributes Request ####

| Octets: Variable | Variable | Variable | ... | Variable |
| :-: | :-: | :-: | :-: | :-: |
| ZCL Header | Attribute 1 | Attribute 2 | ... | Attribute n |

##### Attribute x Record #####

| Octets: 1 | 1 | 1 | Variable |
| :-: | :-: | :-: | :-: |
| Attribute ID<br />LSB | Attribute ID<br />MSB | Data Type | Data |

#### Default Response ####

| Octets: Variable | 1 | 1 |
| :-: | :-: | :-: |
| ZCL Header | Command ID | Status |

#### Discover Attributes Request ####

| Octets: Variable | 1 | 1 | 1 |
| :-: | :-: | :-: | :-: |
| ZCL Header | Start Attribute ID<br />LSB | Start Attribute ID<br />MSB | Max. Attribute IDs<br />to be returned |

#### Discover Attributes Response ####

| Octets: Variable | 1 | 3 | 3 | ... | 3 |
| :-: | :-: | :-: | :-: | :-: | :-: |
| ZCL Header | Discovery complete | Attribute 1 | Attribute 2 | ... | Attribute n |

##### Attribute x Record #####

| Octets: 1 | 1 | 1 |
| :-: | :-: | :-: |
| Attribute ID<br />LSB | Attribute ID<br />MSB | Data Type |

#### Read Attributes Structured Request ####

| Octets: Variable | 1 | 1 | Variable | ... | 1 | 1 | Variable |
| :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| ZCL Header | Attribute 1 ID<br />LSB | Attribute 1 ID<br />MSB | Selector | ... | Attribute n ID<br />LSB | Attribute n ID<br />MSB | Selector |

##### Selector Record #####

| Octets: 1 | 1 | 1 | ... | 1 | 1 |
| :-: | :-: | :-: | :-: | :-: | :-: |
| Indicator (m) | Index 1<br />LSB | Index 1<br />MSB | ... | Index m<br />LSB | Index m<br />MSB |

#### Write Attributes Structured Request #### 

| Octets: Variable | Variable | Variable | ... | Variable |
| :-: | :-: | :-: | :-: | :-: |
| ZCL Header | Attribute 1 | Attribute 2 | ... | Attribute n |

##### Attribute x Record #####

| Octets: 1 | 1 | Variable | 1 | Variable |
| :-: | :-: | :-: | :-: | :-: |
| Attribute ID<br />LSB | Attribute ID<br />MSB | Selector | Data Type | Value |

##### Selector Record #####

| Octets: 1 | 1 | 1 | ... | 1 | 1 |
| :-: | :-: | :-: | :-: | :-: | :-: |
| Indicator (m) | Index 1<br />LSB | Index 1<br />MSB | ... | Index m<br />LSB | Index m<br />MSB |

#### Write Attributes Structured Response ####

| Octets: Variable | Variable | Variable | ... | Variable |
| :-: | :-: | :-: | :-: | :-: |
| ZCL Header | Attribute 1 | Attribute 2 | ... | Attribute n |

##### Attribute x Record #####

| Octets: 1 | 1 | 1 | Variable |
| :-: | :-: | :-: | :-: |
| Status | Attribute ID<br />LSB | Attribute ID<br />MSB | Selector |

#### Discover Commands Received Request ####
#### Discover Commands Generated Request ####

| Octets: Variable | 1 | 1 |
| :-: | :-: | :-: |
| ZCL Header | Start Command ID | Max. Command IDs<br />to be returned |

#### Discover Commands Received Response ####
#### Discover Commands Generated Response ####

| Octets: Variable | 1 | 1 | 1 | ... | 1 |
| :-: | :-: | :-: | :-: | :-: | :-: |
| ZCL Header | Discovery complete | Command 1 | Command 2 | ... | Command n |

#### Discover Attributes Extended Request ####

| Octets: Variable | 1 | 1 | 1 |
| :-: | :-: | :-: | :-: |
| ZCL Header | Start Attribute ID<br />LSB | Start Attribute ID<br />MSB | Max. Attribute IDs<br />to be returned |

#### Discover Attributes Extended Response ####

| Octets: Variable | 1 | 4 | 4 | ... | 4 |
| :-: | :-: | :-: | :-: | :-: | :-: |
| ZCL Header | Discovery complete | Attribute 1<br />Extended Info | Attribute 2<br />Extended Info | ... | Attribute n<br />Extended Info |

##### Extended Info #####

| Octets: 1 | 1 | 1 | 1 |
| :-: | :-: | :-: | :-: |
| Attribute ID<br />LSB | Attribute ID<br />MSB | Data Type | Attribute Access<br />Control |

##### Attribute Access Control #####

| Bit 7(0) | Bit 6(1) | Bit 5(2) | ... |
| :-: | :-: | :-: | :-: |
| Readable | Writeable | Reportable | Ignored |

**Note** Bits in the bitfield are in little endian order (shown in brackets)