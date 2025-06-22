#!/usr/bin/env python3
#
#

import argparse
from lxml import etree
import json
import sys
import struct

categorys = {
    0: "nop",
    10: "strings",
    20: "datatypes",
    30: "general",
    40: "fmmu",
    41: "syncm",
    50: "txpdo",
    51: "rxpdo",
    60: "dclock",
}

datatypes = {
    0x00: "UNDEF",
    0x01: "BOOL",
    0x02: "SINT",
    0x03: "INT",
    0x04: "DINT",
    0x05: "USINT",
    0x06: "UINT",
    0x07: "UDINT",
    0x08: "REAL",
    0x09: "STRING",
    0x0A: "OF BYTE",
    0x0B: "OF UINT",
    0x10: "INT24",
    0x11: "LREAL",
    0x12: "INT40",
    0x13: "INT48",
    0x14: "INT56",
    0x15: "INT64",
    0x16: "UINT24",
    0x18: "UINT40",
    0x19: "UINT48",
    0x1A: "UINT56",
    0x1B: "UINT64",
}


class Base:
    def __init__(self, parent):
        self.parent = parent
        self.strings = parent.strings
        self.bindata = []
        self.offset = 0
        self.startpos = 0

    def bytes2ee(self, value):
        return (value - 0x80) >> 7

    def binVarRead(self, bindata, size):
        if size == 2:
            vtype = "H"
        elif size == 4:
            vtype = "I"
        else:
            vtype = "B"
        value = struct.unpack(f"<{vtype}", bindata[self.offset : self.offset + size])[0]
        self.offset += size
        return value

    def binVarWrite(self, value, size):
        if size == 2:
            vtype = "H"
        elif size == 4:
            vtype = "I"
        else:
            vtype = "B"
        bindata = struct.pack(f"<{vtype}", value)
        self.offset += size
        return bindata

    def stringSet(self, text):
        if text not in self.parent.strings:
            self.parent.strings.append(text)
        string_index = self.parent.strings.index(text)
        return string_index

    def datatypeSet(self, datatype):
        dlist = list(datatypes.values())
        datatype = datatype.replace("UINT16", "UINT").replace("UINT8", "UINT").replace("UINT32", "UINT")
        if datatype in dlist:
            datatype_index = dlist.index(datatype)
            return datatype_index
        return 0

    def printKeyDatatype(self, key, value, prefix=""):
        datatype = datatypes.get(value, "UNSET")
        print(f"{prefix}   {key:23} {value:6d} ({datatype})")

    def printKeyString(self, key, value, prefix=""):
        if value < len(self.parent.strings):
            text = self.parent.strings[value]
            print(f"{prefix}   {key:23} {value:6d} ('{text}')")
        else:
            print(f"{prefix}   {key:23} {value:6d}")

    def printKeyValue(self, key, value, prefix="", fmt=None):
        if isinstance(value, int):
            print(f"{prefix}   {key:23} 0x{value:04x} ({value})")
        else:
            print(f"{prefix}   {key:23} {value:6s}")

    def value2xmlText(self, value):
        if value < len(self.parent.strings):
            text = self.parent.strings[value]
            return text
        return str(value)

    def value2xmlBool(self, value):
        if value:
            return "true"
        return "false"

    def value2xmlDatatype(self, value):
        value = datatypes.get(value, value)
        return str(value)

    def value2xml(self, value, size):
        if size == 2:
            return f"#x{value:02x}"
        elif size == 4:
            return f"#x{value:04x}"
        elif size == 8:
            return f"#x{value:08x}"
        return str(value)

    def xml_value_parse(self, value):
        if value and value.startswith("#x"):
            value = int(value.replace("#x", "0x"), 0)
        return value

    def xml_value(self, base_element, xpath, attribute=None, default=0):
        values = []
        result = base_element.findall(xpath)
        if result:
            for element in result:
                if attribute:
                    value = element.get(attribute)
                else:
                    value = element.text
                value = self.xml_value_parse(value)
                values.append(value)
        return values or [default]


class preamble(Base):
    def crc8byte(self, crc, b):
        crc = crc ^ b
        for i in range(8):
            if (crc & 0x80) == 0x80:
                crc = (crc << 1) ^ 0x07
            else:
                crc <<= 1
        while crc > 255:
            crc -= 256
        return crc

    def csum(self, bindata):
        crc = 255
        for byte in bindata:
            crc = self.crc8byte(crc, byte)
        return crc

    def binRead(self, bindata):
        self.startpos = self.parent.startpos
        self.bindata = bindata
        self.offset = 0
        self.pdi_ctrl = self.binVarRead(bindata, 2)  # 0
        self.pdi_conf = self.binVarRead(bindata, 2)  # 2
        self.sync_impulse = self.binVarRead(bindata, 2)  # 4
        self.pdi_conf2 = self.binVarRead(bindata, 2)  # 6
        self.alias = self.binVarRead(bindata, 2)  # 8
        self.reserved1 = self.binVarRead(bindata, 4)  # 10
        self.checksum = self.binVarRead(bindata, 2)  # 14
        if self.offset != self.size():
            print("SIZE ERROR:", self, self.offset, self.size())

        crc = self.csum(bindata[:14])
        if crc != self.checksum:
            self.checksum_ok = True
            print("CSUM ERROR:", crc, self.checksum)

        return self.offset

    def binWrite(self):
        bindata = []
        bindata += self.binVarWrite(self.pdi_ctrl, 2)  # 0
        bindata += self.binVarWrite(self.pdi_conf, 2)  # 2
        bindata += self.binVarWrite(self.sync_impulse, 2)  # 4
        bindata += self.binVarWrite(self.pdi_conf2, 2)  # 6
        bindata += self.binVarWrite(self.alias, 2)  # 8
        bindata += self.binVarWrite(self.reserved1, 4)  # 10
        self.checksum = self.csum(bindata[:14])
        bindata += self.binVarWrite(self.checksum, 2)  # 14
        return bindata

    def size(self):
        return 16

    def xmlRead(self, base_element):
        self.pdi_ctrl = 0
        self.pdi_conf = 0
        self.sync_impulse = 0
        self.pdi_conf2 = 0
        self.alias = 0
        self.reserved1 = 0
        self.checksum = 0

        configDataElement = base_element.find("./Descriptions/Devices/Device/Eeprom/ConfigData")
        if configDataElement is not None:
            configData = bytearray.fromhex(configDataElement.text)
            cpos = 0
            if len(configData) >= cpos + 2:
                self.pdi_ctrl = struct.unpack(f"<H", configData[cpos : cpos + 2])[0]
            cpos += 2
            if len(configData) >= cpos + 2:
                self.pdi_conf = struct.unpack(f"<H", configData[cpos : cpos + 2])[0]
            cpos += 2
            if len(configData) >= cpos + 2:
                self.sync_impulse = struct.unpack(f"<H", configData[cpos : cpos + 2])[0]
            cpos += 2
            if len(configData) >= cpos + 2:
                self.pdi_conf2 = struct.unpack(f"<H", configData[cpos : cpos + 2])[0]
            cpos += 2
            if len(configData) >= cpos + 2:
                self.alias = struct.unpack(f"<H", configData[cpos : cpos + 2])[0]
            cpos += 2

    def xmlWrite(self, prefix=""):
        pass

    def Info(self, prefix=""):
        print(f"{prefix}preamble: {self.startpos}")
        print(f"{prefix}   bin:", list(self.bindata))
        if list(self.bindata) != list(self.binWrite()):
            print(f"{prefix}   bin:", list(self.bindata))
            print(f"{prefix}   bak:", list(self.binWrite()))
        else:
            print(f"{prefix}   bin: RW_OK")
        self.printKeyValue("pdi_ctrl", self.pdi_ctrl, prefix)
        self.printKeyValue("pdi_conf", self.pdi_conf, prefix)
        self.printKeyValue("sync_impulse", self.sync_impulse, prefix)
        self.printKeyValue("pdi_conf2", self.pdi_conf2, prefix)
        self.printKeyValue("alias", self.alias, prefix)
        self.printKeyValue("checksum", self.checksum, prefix)
        print("")


class stdconfig(Base):
    def binRead(self, bindata):
        self.startpos = self.parent.startpos
        self.bindata = bindata
        self.offset = 0
        self.vendor_id = self.binVarRead(bindata, 4)  # 0
        self.product_id = self.binVarRead(bindata, 4)  # 4
        self.revision_id = self.binVarRead(bindata, 4)  # 8
        self.serial = self.binVarRead(bindata, 4)  # 12
        self.offset += 8  # 16
        self.bs_rec_mbox_offset = self.binVarRead(bindata, 2)  # 24
        self.bs_rec_mbox_size = self.binVarRead(bindata, 2)  # 26
        self.bs_snd_mbox_offset = self.binVarRead(bindata, 2)  # 28
        self.bs_snd_mbox_size = self.binVarRead(bindata, 2)  # 30
        self.std_rec_mbox_offset = self.binVarRead(bindata, 2)  # 32
        self.std_rec_mbox_size = self.binVarRead(bindata, 2)  # 34
        self.std_snd_mbox_offset = self.binVarRead(bindata, 2)  # 36
        self.std_snd_mbox_size = self.binVarRead(bindata, 2)  # 38
        self.mailbox_protocol = self.binVarRead(bindata, 2)  # 40
        self.offset += 66  # 42
        self.eeprom_size = self.binVarRead(bindata, 2)  # 108
        self.version = self.binVarRead(bindata, 2)  # 110
        if self.offset != self.size():
            print("SIZE ERROR:", self, self.offset, self.size())
        return self.offset

    def binWrite(self):
        bindata = []
        bindata += self.binVarWrite(self.vendor_id, 4)  # 0
        bindata += self.binVarWrite(self.product_id, 4)  # 4
        bindata += self.binVarWrite(self.revision_id, 4)  # 8
        bindata += self.binVarWrite(self.serial, 4)  # 12
        bindata += [0] * 8  # 16
        bindata += self.binVarWrite(self.bs_rec_mbox_offset, 2)  # 24
        bindata += self.binVarWrite(self.bs_rec_mbox_size, 2)  # 26
        bindata += self.binVarWrite(self.bs_snd_mbox_offset, 2)  # 28
        bindata += self.binVarWrite(self.bs_snd_mbox_size, 2)  # 30
        bindata += self.binVarWrite(self.std_rec_mbox_offset, 2)  # 32
        bindata += self.binVarWrite(self.std_rec_mbox_size, 2)  # 34
        bindata += self.binVarWrite(self.std_snd_mbox_offset, 2)  # 36
        bindata += self.binVarWrite(self.std_snd_mbox_size, 2)  # 38
        bindata += self.binVarWrite(self.mailbox_protocol, 2)  # 40
        bindata += [0] * 66  # 42
        bindata += self.binVarWrite(self.eeprom_size, 2)  # 108
        bindata += self.binVarWrite(self.version, 2)  # 110
        return bindata

    def size(self):
        return 112

    def xmlRead(self, base_element):
        self.vendor_id = int(self.xml_value(base_element, "./Vendor/Id")[0])
        self.product_id = int(self.xml_value(base_element, "./Descriptions/Devices/Device/Type", "ProductCode")[0])
        self.revision_id = int(self.xml_value(base_element, "./Descriptions/Devices/Device/Type", "RevisionNo")[0])
        self.serial = 0
        self.bs_rec_mbox_offset = 0
        self.bs_rec_mbox_size = 0
        self.bs_snd_mbox_offset = 0
        self.bs_snd_mbox_size = 0
        self.std_rec_mbox_offset = 0
        self.std_rec_mbox_size = 0
        self.std_snd_mbox_offset = 0
        self.std_snd_mbox_size = 0
        self.mailbox_protocol = 0
        self.eeprom_size = 0
        self.version = 1

        for sm in base_element.findall(f"./Descriptions/Devices/Device/Sm"):
            name = sm.text
            if name == "MBoxOut":
                self.std_rec_mbox_size = int(self.xml_value_parse(sm.get("DefaultSize", 0)))
                self.std_rec_mbox_offset = int(self.xml_value_parse(sm.get("StartAddress", 0)))
            if name == "MBoxIn":
                self.std_snd_mbox_size = int(self.xml_value_parse(sm.get("DefaultSize", 0)))
                self.std_snd_mbox_offset = int(self.xml_value_parse(sm.get("StartAddress", 0)))

        eeprom_size = int(self.xml_value(base_element, "./Descriptions/Devices/Device/Eeprom/ByteSize")[0])
        if eeprom_size:
            self.eeprom_size = self.bytes2ee(eeprom_size)

        coe = 0
        eoe = 0
        foe = 0
        voe = 0
        for mb in base_element.findall(f"./Descriptions/Devices/Device/Mailbox"):
            for element in mb:
                if element.tag == "CoE":
                    coe = 0x0004
                elif element.tag == "EoE":
                    eoe = 0x0002
                elif element.tag == "FoE":
                    foe = 0x0008
                elif element.tag == "VoE":
                    voe = 0x0020
        self.mailbox_protocol = coe | eoe | foe | voe

    def xmlWrite(self, base_element):
        Vendor = base_element.find("./Vendor")
        etree.SubElement(Vendor, "Id").text = str(self.vendor_id)
        Device = base_element.find("./Descriptions/Devices/Device")
        Type = Device.find("./Type")
        if Type is not None:
            Type.set("ProductCode", self.value2xml(self.product_id, 8))
            Type.set("RevisionNo", self.value2xml(self.revision_id, 8))

    def Info(self, prefix=""):
        print(f"{prefix}stdconfig: {self.startpos}")
        print(f"{prefix}   bin:", list(self.bindata))
        if list(self.bindata) != list(self.binWrite()):
            print(f"{prefix}   bin:", list(self.bindata))
            print(f"{prefix}   bak:", list(self.binWrite()))
        else:
            print(f"{prefix}   bin: RW_OK")
        self.printKeyValue("vendor_id", self.vendor_id, prefix)
        self.printKeyValue("product_id", self.product_id, prefix)
        self.printKeyValue("revision_id", self.revision_id, prefix)
        self.printKeyValue("serial", self.serial, prefix)
        self.printKeyValue("bs_rec_mbox_offset", self.bs_rec_mbox_offset, prefix)
        self.printKeyValue("bs_rec_mbox_size", self.bs_rec_mbox_size, prefix)
        self.printKeyValue("bs_snd_mbox_offset", self.bs_snd_mbox_offset, prefix)
        self.printKeyValue("bs_snd_mbox_size", self.bs_snd_mbox_size, prefix)
        self.printKeyValue("std_rec_mbox_offset", self.std_rec_mbox_offset, prefix)
        self.printKeyValue("std_rec_mbox_size", self.std_rec_mbox_size, prefix)
        self.printKeyValue("std_snd_mbox_offset", self.std_snd_mbox_offset, prefix)
        self.printKeyValue("std_snd_mbox_size", self.std_snd_mbox_size, prefix)
        self.printKeyValue("mailbox_protocol", self.mailbox_protocol, prefix)
        self.printKeyValue("eeprom_size", self.eeprom_size, prefix)
        self.printKeyValue("version", self.version, prefix)
        print("")


class general(Base):
    cat_type = 30

    def binRead(self, bindata):
        self.startpos = self.parent.startpos
        self.bindata = bindata
        self.offset = 0
        self.groupindex = self.binVarRead(bindata, 1)  # 0
        self.imageindex = self.binVarRead(bindata, 1)  # 1
        self.orderindex = self.binVarRead(bindata, 1)  # 2
        self.nameindex = self.binVarRead(bindata, 1)  # 3
        self.unknown1 = self.binVarRead(bindata, 1)  # 4
        # Bit 0: Enable SDO
        # Bit 1: Enable SDO Info
        # Bit 2: Enable PDO Assign
        # Bit 3: Enable PDO Configuration
        # Bit 4: Enable Upload at startup
        # Bit 5: Enable SDO complete acces
        self.coe_details = self.binVarRead(bindata, 1)  # 5
        self.foe_details = self.binVarRead(bindata, 1)  # 6
        self.eoe_enabled = self.binVarRead(bindata, 1)  # 7
        self.soe_channels = self.binVarRead(bindata, 1)  # 8 - reserved
        self.ds402_channels = self.binVarRead(bindata, 1)  # 9 - reserved
        self.sysman_class = self.binVarRead(bindata, 1)  # 10 - reserved
        # Bit 0: Enable SafeOp
        # Bit 1: Enable notLRW
        # Bit 2: MboxDataLinkLayer
        # Bit 3,4: Selection of identification method as defined in Table 22
        self.flags = self.binVarRead(bindata, 1)  # 11
        self.current_ebus = self.binVarRead(bindata, 2)  # 12
        self.unknown2 = self.binVarRead(bindata, 1)  # 14
        self.phys_port01 = self.binVarRead(bindata, 1)  # 15
        self.phys_port23 = self.binVarRead(bindata, 1)  # 16
        self.physical_address = self.binVarRead(bindata, 2)  # 17
        self.offset += 13  # 19
        if self.offset != self.size():
            print("SIZE ERROR:", self, self.offset, self.size())
        return self.offset

    def binWrite(self):
        bindata = []
        bindata += self.binVarWrite(self.groupindex, 1)  # 0
        bindata += self.binVarWrite(self.imageindex, 1)  # 1
        bindata += self.binVarWrite(self.orderindex, 1)  # 2
        bindata += self.binVarWrite(self.nameindex, 1)  # 3
        bindata += self.binVarWrite(self.unknown1, 1)  # 4
        bindata += self.binVarWrite(self.coe_details, 1)  # 5
        bindata += self.binVarWrite(self.foe_details, 1)  # 6
        bindata += self.binVarWrite(self.eoe_enabled, 1)  # 7
        bindata += self.binVarWrite(self.soe_channels, 1)  # 8
        bindata += self.binVarWrite(self.ds402_channels, 1)  # 9
        bindata += self.binVarWrite(self.sysman_class, 1)  # 10
        bindata += self.binVarWrite(self.flags, 1)  # 11
        bindata += self.binVarWrite(self.current_ebus, 2)  # 12
        bindata += self.binVarWrite(self.unknown2, 1)  # 14
        bindata += self.binVarWrite(self.phys_port01, 1)  # 15
        bindata += self.binVarWrite(self.phys_port23, 1)  # 16
        bindata += self.binVarWrite(self.physical_address, 2)  # 17
        bindata += [0] * 13  # 19
        return bindata

    def size(self):
        return 32

    def xmlRead(self, base_element):
        self.groupindex = self.stringSet(self.xml_value(base_element, "./Descriptions/Groups/Group/Type")[0])
        self.imageindex = 0
        # self.orderindex = self.stringSet(self.xml_value(base_element, "./Descriptions/Devices/Device/Type")[0])
        self.orderindex = 0
        self.nameindex = self.stringSet(self.xml_value(base_element, "./Descriptions/Devices/Device/Name")[0])
        self.unknown1 = 0
        self.coe_details = 0
        self.foe_details = 0
        self.eoe_enabled = 0
        self.soe_channels = 0
        self.ds402_channels = 0
        self.sysman_class = 0
        self.flags = 0
        self.current_ebus = 0
        self.unknown2 = 1
        self.phys_port01 = 0
        self.phys_port23 = 0
        self.physical_address = 0

        for mb in base_element.findall(f"./Descriptions/Devices/Device/Mailbox"):
            for element in mb:
                if element.tag in {"CoE", "FoE"}:
                    details = 1
                    details |= int(self.xml_value_parse(element.get("SdoInfo", 0))) << 1
                    details |= int(self.xml_value_parse(element.get("PdoAssign", 0))) << 2
                    details |= int(self.xml_value_parse(element.get("PdoConfig", 0))) << 3
                    details |= int(self.xml_value_parse(element.get("PdoUpload", 0))) << 4
                    details |= int(self.xml_value_parse(element.get("CompleteAccess", 0))) << 5
                    if element.tag == "CoE":
                        self.coe_details = details
                    elif element.tag == "FoE":
                        self.foe_details = details

        Device = base_element.find("./Descriptions/Devices/Device")
        if Device is not None:
            Physics = Device.get("Physics")
            if Physics:
                ports = [0, 0, 0, 0]
                for cn, char in enumerate(Physics):
                    if char == "Y":
                        ports[cn] = 0x01
                    elif char == "K":
                        ports[cn] = 0x03
                self.phys_port01 = (ports[3] << 4) | ports[2]
                self.phys_port23 = (ports[1] << 4) | ports[0]

    def xmlWrite(self, base_element):
        Device = base_element.find("./Descriptions/Devices/Device")
        etree.SubElement(Device, "Name").text = self.value2xmlText(self.nameindex)
        Type = Device.find("./Type")
        if Type is not None:
            Type.text = self.value2xmlText(self.orderindex)

    def Info(self, prefix=""):
        print(f"{prefix}general: {self.startpos}")
        print(f"{prefix}   bin:", list(self.bindata))
        if list(self.bindata) != list(self.binWrite()):
            print(f"{prefix}   bin:", list(self.bindata))
            print(f"{prefix}   bak:", list(self.binWrite()))
        else:
            print(f"{prefix}   bin: RW_OK")
        self.printKeyString("groupindex", self.groupindex, prefix)
        self.printKeyString("imageindex", self.imageindex, prefix)
        self.printKeyString("orderindex", self.orderindex, prefix)
        self.printKeyString("nameindex", self.nameindex, prefix)
        self.printKeyString("unknown1", self.unknown1, prefix)
        self.printKeyValue("coe_details", self.coe_details, prefix)
        self.printKeyValue("foe_details", self.foe_details, prefix)
        self.printKeyValue("eoe_enabled", self.eoe_enabled, prefix)
        self.printKeyValue("soe_channels", self.soe_channels, prefix)
        self.printKeyValue("ds402_channels", self.ds402_channels, prefix)
        self.printKeyValue("sysman_class", self.sysman_class, prefix)
        self.printKeyValue("flags", self.flags, prefix)
        self.printKeyValue("current_ebus", self.current_ebus, prefix)
        self.printKeyValue("unknown2", self.unknown2, prefix)
        self.printKeyValue("phys_port01", self.phys_port01, prefix)
        self.printKeyValue("phys_port23", self.phys_port23, prefix)
        self.printKeyValue("physical_address", self.physical_address, prefix)
        print("")


class txpdo(Base):
    cat_type = 50

    def binRead(self, bindata):
        self.startpos = self.parent.startpos
        self.bindata = bindata
        self.offset = 0
        self.index = self.binVarRead(bindata, 2)  # 0
        self.entries = self.binVarRead(bindata, 1)  # 2
        self.syncmanager = self.binVarRead(bindata, 1)  # 3
        self.dcsync = self.binVarRead(bindata, 1)  # 4
        self.name_index = self.binVarRead(bindata, 1)  # 5
        self.flags = self.binVarRead(bindata, 2)  # 6
        self.entrys = {}
        entry_num = 0
        while True:
            self.entrys[entry_num] = pdo_entry(self)
            entry_size = self.entrys[entry_num].size()
            self.entrys[entry_num].binRead(bindata[self.offset : self.offset + entry_size])
            self.offset += entry_size
            entry_num += 1
            if (len(bindata) - self.offset) < entry_size:
                break
        return self.offset

    def binWrite(self):
        bindata = []
        bindata += self.binVarWrite(self.index, 2)  # 0
        bindata += self.binVarWrite(self.entries, 1)  # 2
        bindata += self.binVarWrite(self.syncmanager, 1)  # 3
        bindata += self.binVarWrite(self.dcsync, 1)  # 4
        bindata += self.binVarWrite(self.name_index, 1)  # 5
        bindata += self.binVarWrite(self.flags, 2)  # 6
        for num, entry in self.entrys.items():
            bindata += entry.binWrite()
        return bindata

    def size(self):
        return 8

    def xmlRead(self, base_element):
        self.index = int(self.xml_value_parse(base_element.find("./Index").text))
        self.entries = 0
        self.syncmanager = int(base_element.get("Sm"))
        self.dcsync = 0
        self.name_index = self.stringSet(base_element.find("./Name").text)
        self.flags = int(base_element.get("Mandatory", 0) in {"true", "1"})
        self.flags |= int(base_element.get("Fixed", 0) in {"true", "1"}) << 4
        self.flags |= int(base_element.get("Virtual", 0) in {"true", "1"}) << 5
        self.flags |= int(base_element.get("OverwrittenByModule", 0) in {"true", "1"}) << 7
        self.entrys = {}
        for entry in base_element.findall("./Entry"):
            self.entrys[self.entries] = pdo_entry(self)
            self.entrys[self.entries].xmlRead(entry)
            self.entries += 1

    def xmlWrite(self, base_element):
        Device = base_element.find("./Descriptions/Devices/Device")
        element = etree.SubElement(Device, "TxPdo", Sm=str(self.syncmanager), Fixed=self.value2xmlBool(1), Mandatory=self.value2xmlBool(1))
        etree.SubElement(element, "Index").text = self.value2xml(self.index, 4)
        etree.SubElement(element, "Name").text = self.value2xmlText(self.name_index)
        for num, entry in self.entrys.items():
            entry.xmlWrite(element)

    def Info(self, prefix=""):
        print(f"{prefix}txpdo: {self.startpos}")
        print(f"{prefix}   bin:", list(self.bindata))
        if list(self.bindata) != list(self.binWrite()):
            print(f"{prefix}   bin:", list(self.bindata))
            print(f"{prefix}   bak:", list(self.binWrite()))
        else:
            print(f"{prefix}   bin: RW_OK")
        self.printKeyValue("index", self.index, prefix)
        self.printKeyValue("entries", self.entries, prefix)
        self.printKeyValue("syncmanager", self.syncmanager, prefix)
        self.printKeyValue("dcsync", self.dcsync, prefix)
        self.printKeyString("name_index", self.name_index, prefix)
        self.printKeyValue("flags", self.flags, prefix)
        for num, entry in self.entrys.items():
            print(f"{prefix}   {num}:")
            entry.Info(f"{prefix}   ")
        print("")


class rxpdo(Base):
    cat_type = 51

    def binRead(self, bindata):
        self.startpos = self.parent.startpos
        self.bindata = bindata
        self.offset = 0
        self.index = self.binVarRead(bindata, 2)  # 0
        self.entries = self.binVarRead(bindata, 1)  # 2
        self.syncmanager = self.binVarRead(bindata, 1)  # 3
        self.dcsync = self.binVarRead(bindata, 1)  # 4
        self.name_index = self.binVarRead(bindata, 1)  # 5
        self.flags = self.binVarRead(bindata, 2)  # 6
        self.entrys = {}
        entry_num = 0
        while True:
            self.entrys[entry_num] = pdo_entry(self)
            entry_size = self.entrys[entry_num].size()
            self.entrys[entry_num].binRead(bindata[self.offset : self.offset + entry_size])
            self.offset += entry_size
            entry_num += 1
            if (len(bindata) - self.offset) < entry_size:
                break
        return self.offset

    def binWrite(self):
        bindata = []
        bindata += self.binVarWrite(self.index, 2)  # 0
        bindata += self.binVarWrite(self.entries, 1)  # 2
        bindata += self.binVarWrite(self.syncmanager, 1)  # 3
        bindata += self.binVarWrite(self.dcsync, 1)  # 4
        bindata += self.binVarWrite(self.name_index, 1)  # 5
        bindata += self.binVarWrite(self.flags, 2)  # 6
        for num, entry in self.entrys.items():
            bindata += entry.binWrite()
        return bindata

    def size(self):
        return 8

    def xmlRead(self, base_element):
        self.index = int(self.xml_value_parse(base_element.find("./Index").text))
        self.entries = 0
        self.syncmanager = int(base_element.get("Sm"))
        self.dcsync = 0
        self.name_index = self.stringSet(base_element.find("./Name").text)
        self.flags = int(base_element.get("Mandatory", 0) in {"true", "1"})
        self.flags |= int(base_element.get("Fixed", 0) in {"true", "1"}) << 4
        self.flags |= int(base_element.get("Virtual", 0) in {"true", "1"}) << 5
        self.flags |= int(base_element.get("OverwrittenByModule", 0) in {"true", "1"}) << 7
        self.entrys = {}
        for entry in base_element.findall("./Entry"):
            self.entrys[self.entries] = pdo_entry(self)
            self.entrys[self.entries].xmlRead(entry)
            self.entries += 1

    def xmlWrite(self, base_element):
        Device = base_element.find("./Descriptions/Devices/Device")
        element = etree.SubElement(Device, "RxPdo", Sm=str(self.syncmanager), Fixed=self.value2xmlBool(1), Mandatory=self.value2xmlBool(1))
        etree.SubElement(element, "Index").text = self.value2xml(self.index, 4)
        etree.SubElement(element, "Name").text = self.value2xmlText(self.name_index)
        for num, entry in self.entrys.items():
            entry.xmlWrite(element)

    def Info(self, prefix=""):
        print(f"{prefix}rxpdo: {self.startpos}")
        print(f"{prefix}   bin:", list(self.bindata))
        if list(self.bindata) != list(self.binWrite()):
            print(f"{prefix}   bin:", list(self.bindata))
            print(f"{prefix}   bak:", list(self.binWrite()))
        else:
            print(f"{prefix}   bin: RW_OK")
        self.printKeyValue("index", self.index, prefix)
        self.printKeyValue("entries", self.entries, prefix)
        self.printKeyValue("syncmanager", self.syncmanager, prefix)
        self.printKeyValue("dcsync", self.dcsync, prefix)
        self.printKeyString("name_index", self.name_index, prefix)
        self.printKeyValue("flags", self.flags, prefix)
        for num, entry in self.entrys.items():
            print(f"{prefix}   {num}:")
            entry.Info(f"{prefix}   ")
        print("")


class pdo_entry(Base):
    def binRead(self, bindata):
        self.startpos = self.parent.startpos
        self.bindata = bindata
        self.offset = 0
        self.index = self.binVarRead(bindata, 2)  # 0
        self.subindex = self.binVarRead(bindata, 1)  # 2
        self.string_index = self.binVarRead(bindata, 1)  # 3
        self.data_type = self.binVarRead(bindata, 1)  # 4
        self.bit_length = self.binVarRead(bindata, 1)  # 5
        self.flags = self.binVarRead(bindata, 2)  # 6
        if self.offset != self.size():
            print("SIZE ERROR:", self, self.offset, self.size())
        return self.offset

    def binWrite(self):
        bindata = []
        bindata += self.binVarWrite(self.index, 2)  # 0
        bindata += self.binVarWrite(self.subindex, 1)  # 2
        bindata += self.binVarWrite(self.string_index, 1)  # 3
        bindata += self.binVarWrite(self.data_type, 1)  # 4
        bindata += self.binVarWrite(self.bit_length, 1)  # 5
        bindata += self.binVarWrite(self.flags, 2)  # 6
        return bindata

    def size(self):
        return 8

    def xmlRead(self, base_element):
        self.index = int(self.xml_value_parse(base_element.find("./Index").text))
        self.subindex = int(self.xml_value_parse(base_element.find("./SubIndex").text))
        self.string_index = self.stringSet(base_element.find("./Name").text)
        self.data_type = self.datatypeSet(base_element.find("./DataType").text)
        self.bit_length = int(self.xml_value_parse(base_element.find("./BitLen").text))
        self.flags = 0

    def xmlWrite(self, base_element):
        Entry = etree.SubElement(base_element, "Entry")
        etree.SubElement(Entry, "Index").text = self.value2xml(self.index, 4)
        etree.SubElement(Entry, "SubIndex").text = str(self.subindex)
        etree.SubElement(Entry, "BitLen").text = str(self.bit_length)
        etree.SubElement(Entry, "Name").text = self.value2xmlText(self.string_index)
        etree.SubElement(Entry, "DataType").text = self.value2xmlDatatype(self.data_type)

    def Info(self, prefix=""):
        print(f"{prefix}pdo_entry:")
        print(f"{prefix}   bin:", list(self.bindata))
        if list(self.bindata) != list(self.binWrite()):
            print(f"{prefix}   bin:", list(self.bindata))
            print(f"{prefix}   bak:", list(self.binWrite()))
        else:
            print(f"{prefix}   bin: RW_OK")
        self.printKeyValue("index", self.index, prefix)
        self.printKeyValue("subindex", self.subindex, prefix)
        self.printKeyString("string_index", self.string_index, prefix)
        self.printKeyDatatype("data_type", self.data_type, prefix)
        self.printKeyValue("bit_length", self.bit_length, prefix)
        self.printKeyValue("flags", self.flags, prefix)
        print("")


class fmmu(Base):
    cat_type = 40

    def binRead(self, bindata):
        self.startpos = self.parent.startpos
        self.bindata = bindata
        self.offset = 0
        self.entrys = {}
        entry_num = 0
        if len(bindata) == self.offset:
            return 0
        while True:
            self.entrys[entry_num] = fmmu_entry(self)
            entry_size = self.entrys[entry_num].size()
            self.entrys[entry_num].binRead(bindata[self.offset : self.offset + entry_size])
            self.offset += entry_size
            entry_num += 1
            if (len(bindata) - self.offset) < entry_size:
                break
        return self.offset

    def binWrite(self):
        bindata = []
        for num, entry in self.entrys.items():
            bindata += entry.binWrite()
        return bindata

    def size(self):
        return 0

    def xmlRead(self, base_element):
        self.entrys = {}
        entry_num = 0
        for fmmu in base_element.findall("./Descriptions/Devices/Device/Fmmu"):
            self.entrys[entry_num] = fmmu_entry(self)
            self.entrys[entry_num].xmlRead(fmmu)
            entry_num += 1

    def xmlWrite(self, base_element):
        pass

    def Info(self, prefix=""):
        print(f"{prefix}fmmu: {self.startpos}")
        print(f"{prefix}   bin:", list(self.bindata))
        if list(self.bindata) != list(self.binWrite()):
            print(f"{prefix}   bin:", list(self.bindata))
            print(f"{prefix}   bak:", list(self.binWrite()))
        else:
            print(f"{prefix}   bin: RW_OK")
        for num, entry in self.entrys.items():
            print(f"{prefix}   {num}:")
            entry.Info(f"{prefix}   ")
        print("")


class fmmu_entry(Base):
    def binRead(self, bindata):
        self.startpos = self.parent.startpos
        self.bindata = bindata
        self.offset = 0
        self.usage = self.binVarRead(bindata, 1)  # 0
        if self.offset != self.size():
            print("SIZE ERROR:", self, self.offset, self.size())
        return self.offset

    def binWrite(self):
        bindata = []
        bindata += self.binVarWrite(self.usage, 1)  # 0
        return bindata

    def size(self):
        return 1

    def xmlWrite(self, base_element):
        pass

    def xmlRead(self, base_element):
        text = base_element.text
        self.usage = 0
        if text == "Outputs":
            self.usage = 0x01
        elif text == "Inputs":
            self.usage = 0x02
        elif text == "MBoxState":
            self.usage = 0x03

    def Info(self, prefix=""):
        print(f"{prefix}fmmu_entry:")
        print(f"{prefix}   bin:", list(self.bindata))
        if list(self.bindata) != list(self.binWrite()):
            print(f"{prefix}   bin:", list(self.bindata))
            print(f"{prefix}   bak:", list(self.binWrite()))
        else:
            print(f"{prefix}   bin: RW_OK")
        self.printKeyValue("usage", self.usage, prefix)
        print("")


class syncm(Base):
    cat_type = 41

    def binRead(self, bindata):
        self.startpos = self.parent.startpos
        self.bindata = bindata
        self.offset = 0
        self.entrys = {}
        entry_num = 0
        while True:
            self.entrys[entry_num] = syncm_entry(self)
            entry_size = self.entrys[entry_num].size()
            self.entrys[entry_num].binRead(bindata[self.offset : self.offset + entry_size])
            self.offset += entry_size
            entry_num += 1
            if (len(bindata) - self.offset) < entry_size:
                break
        return self.offset

    def binWrite(self):
        bindata = []
        for num, entry in self.entrys.items():
            bindata += entry.binWrite()
        return bindata

    def size(self):
        return 0

    def xmlRead(self, base_element):
        self.entrys = {}
        entry_num = 0
        for syncm in base_element.findall("./Descriptions/Devices/Device/Sm"):
            self.entrys[entry_num] = syncm_entry(self)
            self.entrys[entry_num].xmlRead(syncm)
            entry_num += 1

    def xmlWrite(self, base_element):
        for num, entry in self.entrys.items():
            entry.xmlWrite(base_element)

    def Info(self, prefix=""):
        print(f"{prefix}syncm: {self.startpos}")
        print(f"{prefix}   bin:", list(self.bindata))
        if list(self.bindata) != list(self.binWrite()):
            print(f"{prefix}   bin:", list(self.bindata))
            print(f"{prefix}   bak:", list(self.binWrite()))
        else:
            print(f"{prefix}   bin: RW_OK")
        for num, entry in self.entrys.items():
            print(f"{prefix}   {num}:")
            entry.Info(f"{prefix}   ")
        print("")


class syncm_entry(Base):
    def binRead(self, bindata):
        self.startpos = self.parent.startpos
        self.bindata = bindata
        self.offset = 0
        self.phys_address = self.binVarRead(bindata, 2)  # 0
        self.lenght = self.binVarRead(bindata, 2)  # 2
        self.control = self.binVarRead(bindata, 1)  # 4
        self.status = self.binVarRead(bindata, 1)  # 5
        self.enable = self.binVarRead(bindata, 1)  # 6
        self.type = self.binVarRead(bindata, 1)  # 7
        if self.offset != self.size():
            print("SIZE ERROR:", self, self.offset, self.size())
        return self.offset

    def binWrite(self):
        bindata = []
        bindata += self.binVarWrite(self.phys_address, 2)  # 0
        bindata += self.binVarWrite(self.lenght, 2)  # 2
        bindata += self.binVarWrite(self.control, 1)  # 4
        bindata += self.binVarWrite(self.status, 1)  # 5
        bindata += self.binVarWrite(self.enable, 1)  # 6
        bindata += self.binVarWrite(self.type, 1)  # 7
        return bindata

    def size(self):
        return 8

    def xmlRead(self, base_element):
        self.phys_address = int(self.xml_value_parse(base_element.get("StartAddress", 0)))
        self.lenght = int(self.xml_value_parse(base_element.get("DefaultSize", 0)))
        self.control = int(self.xml_value_parse(base_element.get("ControlByte", 0)))
        self.status = 0
        self.enable = int(self.xml_value_parse(base_element.get("Enable", 0)))
        self.type = 0
        if base_element.text == "MBoxOut":
            self.type = 1
        elif base_element.text == "MBoxIn":
            self.type = 2
        elif base_element.text == "Outputs":
            self.type = 3
        elif base_element.text == "Inputs":
            self.type = 4

    def xmlWrite(self, base_element):
        Device = base_element.find("./Descriptions/Devices/Device")
        etree.SubElement(Device, "Sm", Enable=str(self.enable), StartAddress=self.value2xml(self.phys_address, 4), ControlByte=self.value2xml(self.control, 2), DefaultSize=str(self.lenght))

    def Info(self, prefix=""):
        print(f"{prefix}syncm_entry:")
        print(f"{prefix}   bin:", list(self.bindata))
        if list(self.bindata) != list(self.binWrite()):
            print(f"{prefix}   bin:", list(self.bindata))
            print(f"{prefix}   bak:", list(self.binWrite()))
        else:
            print(f"{prefix}   bin: RW_OK")
        self.printKeyValue("phys_address", self.phys_address, prefix)
        self.printKeyValue("lenght", self.lenght, prefix)
        self.printKeyValue("control", self.control, prefix)
        self.printKeyValue("status", self.status, prefix)
        self.printKeyValue("enable", self.enable, prefix)
        self.printKeyValue("type", self.type, prefix)
        print("")


class dclock(Base):
    cat_type = 60
    # fill_n = 28
    fill_n = 4

    def binRead(self, bindata):
        self.startpos = self.parent.startpos
        self.bindata = bindata
        self.offset = 0
        self.cycleTime0 = self.binVarRead(bindata, 4)  # 0
        self.shiftTime0 = self.binVarRead(bindata, 4)  # 4
        self.shiftTime1 = self.binVarRead(bindata, 4)  # 8
        self.sync1CycleFactor = self.binVarRead(bindata, 2)  # 12
        self.assignActivate = self.binVarRead(bindata, 2)  # 14
        self.sync0CycleFactor = self.binVarRead(bindata, 2)  # 16
        self.nameIdx = self.binVarRead(bindata, 1)  # 18
        self.descIdx = self.binVarRead(bindata, 1)  # 19
        self.unknown1 = bindata[self.offset : self.offset + self.fill_n]  # 20
        self.offset += self.fill_n
        if self.offset != self.size():
            print("SIZE ERROR:", self, self.offset, self.size())
        return self.offset

    def binWrite(self):
        bindata = []
        bindata += self.binVarWrite(self.cycleTime0, 4)  # 0
        bindata += self.binVarWrite(self.shiftTime0, 4)  # 4
        bindata += self.binVarWrite(self.shiftTime1, 4)  # 8
        bindata += self.binVarWrite(self.sync1CycleFactor, 2)  # 12
        bindata += self.binVarWrite(self.assignActivate, 2)  # 14
        bindata += self.binVarWrite(self.sync0CycleFactor, 2)  # 16
        bindata += self.binVarWrite(self.nameIdx, 1)  # 18
        bindata += self.binVarWrite(self.descIdx, 1)  # 19
        bindata += self.unknown1  # 20
        return bindata

    def size(self):
        return 20 + self.fill_n

    def xmlRead(self, base_element):
        self.nameIdx = self.stringSet(self.xml_value(base_element, "./Name")[0])
        self.descIdx = self.stringSet(self.xml_value(base_element, "./Desc")[0])
        # self.assignActivate = int(self.xml_value(base_element, "./AssignActivate")[0])
        self.assignActivate = 0
        self.cycleTime0 = int(self.xml_value(base_element, "./CycleTimeSync0")[0])
        self.shiftTime0 = int(self.xml_value(base_element, "./ShiftTimeSync0")[0])
        self.cycleTime1 = int(self.xml_value(base_element, "./CycleTimeSync1")[0])
        self.shiftTime1 = int(self.xml_value(base_element, "./ShiftTimeSync1")[0])
        self.sync0CycleFactor = 0
        self.sync1CycleFactor = 0
        self.unknown1 = [0] * self.fill_n

    def xmlWrite(self, base_element):
        pass

    def Info(self, prefix=""):
        print(f"{prefix}dclock: {self.startpos}")
        print(f"{prefix}   bin:", list(self.bindata))
        if list(self.bindata) != list(self.binWrite()):
            print(f"{prefix}   bin:", list(self.bindata))
            print(f"{prefix}   bak:", list(self.binWrite()))
        else:
            print(f"{prefix}   bin: RW_OK")
        self.printKeyValue("cycleTime0", self.cycleTime0, prefix)
        self.printKeyValue("shiftTime0", self.shiftTime0, prefix)
        self.printKeyValue("shiftTime1", self.shiftTime1, prefix)
        self.printKeyValue("sync1CycleFactor", self.sync1CycleFactor, prefix)
        self.printKeyValue("assignActivate", self.assignActivate, prefix)
        self.printKeyValue("sync0CycleFactor", self.sync0CycleFactor, prefix)
        self.printKeyValue("nameIdx", self.nameIdx, prefix)
        self.printKeyValue("descIdx", self.descIdx, prefix)
        print("")


class strings(Base):
    cat_type = 10
    fill = 0

    def binRead(self, bindata):
        self.startpos = self.parent.startpos
        self.bindata = bindata
        self.strings = [""]
        self.offset = 0
        self.num_strings = bindata[self.offset]
        self.offset += 1
        for strn in range(self.num_strings):
            strlen = bindata[self.offset]
            self.offset += 1
            text = bindata[self.offset : self.offset + strlen].decode()
            self.strings.append(text)
            self.offset += strlen
        if self.offset % 2 != 0:
            self.fill = bindata[-1]
            self.offset += 1
        return self.offset

    def binWrite(self):
        bindata = []
        num_strings = len(self.strings[1:])
        bindata += self.binVarWrite(num_strings, 1)
        for text in self.strings[1:]:
            strlen = len(text)
            bindata += self.binVarWrite(strlen, 1)
            bindata += list(text.encode())
        if len(bindata) % 2 != 0:
            bindata += [self.fill]
        return bindata

    def size(self):
        return 20

    def xmlRead(self, base_element):
        pass

    def xmlWrite(self, base_element):
        pass

    def Info(self, prefix=""):
        self.num_strings = len(self.parent.strings[1:])
        print(f"{prefix}strings: {self.startpos}")
        print(f"{prefix}   bin:", list(self.bindata))
        if list(self.bindata) != list(self.binWrite()):
            print(f"{prefix}   bin:", list(self.bindata))
            print(f"{prefix}   bak:", list(self.binWrite()))
        else:
            print(f"{prefix}   bin: RW_OK")
        self.printKeyValue("Strings", self.num_strings, prefix)
        for tn, text in enumerate(self.strings):
            self.printKeyValue(f"{tn}", f"'{text}'", prefix)
        print("")


class unknown_cat(Base):
    cat_size = 0
    cat_type = 99

    def binRead(self, bindata):
        self.data = bindata
        return len(bindata)

    def binWrite(self):
        bindata = self.data
        return bindata

    def size(self):
        return self.cat_size

    def xmlRead(self, base_element):
        pass

    def xmlWrite(self, base_element):
        pass

    def Info(self, prefix=""):
        print(f"{prefix}UNKNOWN CATALOG: {self.startpos}")
        print(f"{prefix}   bin:", list(self.bindata))
        if list(self.bindata) != list(self.binWrite()):
            print(f"{prefix}   bin:", list(self.bindata))
            print(f"{prefix}   bak:", list(self.binWrite()))
        else:
            print(f"{prefix}   bin: RW_OK")

        self.printKeyValue("Type-Id", self.cat_type, prefix)
        self.printKeyValue("Cat-Size", self.cat_size, prefix)
        print("")


cat_mapping = {
    "strings": strings,
    # "datatypes": datatypes,
    "general": general,
    "fmmu": fmmu,
    "syncm": syncm,
    "txpdo": txpdo,
    "rxpdo": rxpdo,
    "dclock": dclock,
}


class Esi(Base):
    def __init__(self):
        self.offset = 0
        self.catalogs = {}
        self.strings = [""]
        self.preamble = preamble(self)
        self.stdconfig = stdconfig(self)

    def xmlRead(self, xmldata):
        root = etree.fromstring(xmldata)

        self.preamble.xmlRead(root)
        self.stdconfig.xmlRead(root)

        cat_num = 0
        self.catalogs = {}

        self.catalogs[cat_num] = strings(self)
        self.catalogs[cat_num].xmlRead(root)
        cat_num += 1

        self.catalogs[cat_num] = general(self)
        self.catalogs[cat_num].xmlRead(root)
        cat_num += 1

        self.catalogs[cat_num] = fmmu(self)
        self.catalogs[cat_num].xmlRead(root)
        cat_num += 1

        self.catalogs[cat_num] = syncm(self)
        self.catalogs[cat_num].xmlRead(root)
        cat_num += 1

        for pdo in root.findall(f"./Descriptions/Devices/Device/RxPdo"):
            self.catalogs[cat_num] = rxpdo(self)
            self.catalogs[cat_num].xmlRead(pdo)
            cat_num += 1

        for pdo in root.findall(f"./Descriptions/Devices/Device/TxPdo"):
            self.catalogs[cat_num] = txpdo(self)
            self.catalogs[cat_num].xmlRead(pdo)
            cat_num += 1

        for opMode in root.findall(f"./Descriptions/Devices/Device/Dc/OpMode"):
            self.catalogs[cat_num] = dclock(self)
            self.catalogs[cat_num].xmlRead(opMode)
            cat_num += 1

    def binRead(self, bindata):
        self.startpos = 0
        self.offset = 0
        self.offset += self.preamble.binRead(bindata[0 : 0 + self.preamble.size()])
        self.startpos = self.offset
        self.offset += self.stdconfig.binRead(bindata[self.offset : self.offset + self.stdconfig.size()])
        # read catalogs
        cat_num = 0
        self.catalogs = {}
        self.offset = 128
        while True:
            if self.offset + 4 > len(bindata):
                break
            cat_type = self.binVarRead(bindata, 2)
            cat_name = categorys.get(cat_type)
            cat_size = self.binVarRead(bindata, 2) * 2
            if cat_name in cat_mapping:
                self.catalogs[cat_num] = cat_mapping[cat_name](self)
                self.startpos = self.offset
                self.catalogs[cat_num].binRead(bindata[self.offset : self.offset + cat_size])
                if cat_name == "strings":
                    self.strings = self.catalogs[cat_num].strings
            else:
                if cat_type != 65535:  # fill at the end
                    print("###############################################################")
                    print("Unknown catalog")
                    print(f" Num:{cat_num}, Name:{cat_name}, Type:{cat_type}, Size:{cat_size}")
                    if cat_size < 100:
                        print(bindata[self.offset : self.offset + cat_size])
                        print(list(bindata[self.offset : self.offset + cat_size]))
                    print("###############################################################")
                    if cat_size < 100:
                        self.catalogs[cat_num] = unknown_cat(self)
                        self.catalogs[cat_num].cat_type = cat_type
                        self.catalogs[cat_num].cat_size = cat_size
                        self.startpos = self.offset
                        self.catalogs[cat_num].binRead(bindata[self.offset : self.offset + cat_size])

            self.offset += cat_size
            cat_num += 1

    def xmlWrite(self):
        root = etree.Element("EtherCATInfo")
        Vendor = etree.SubElement(root, "Vendor")
        Descriptions = etree.SubElement(root, "Descriptions")
        Devices = etree.SubElement(Descriptions, "Devices")
        Device = etree.SubElement(Devices, "Device")
        Type = etree.SubElement(Device, "Type")

        self.preamble.xmlWrite(root)
        self.stdconfig.xmlWrite(root)
        for cat_num, catalog in self.catalogs.items():
            catalog.xmlWrite(root)

        return etree.tostring(root, pretty_print=True).decode()

    def Info(self, prefix=""):
        self.preamble.Info(prefix)
        self.stdconfig.Info(prefix)
        for cat_num, catalog in self.catalogs.items():
            catalog.Info(prefix)
        print("")

    def binWrite(self):
        bindata = []
        bindata += self.preamble.binWrite()
        bindata += self.stdconfig.binWrite()
        # use fixed order
        for ctype in categorys:
            for cat_num, catalog in self.catalogs.items():
                if catalog.cat_type != ctype:
                    continue
                cat_bindata = catalog.binWrite()
                cat_size = len(cat_bindata)
                cat_type = catalog.cat_type
                bindata += self.binVarWrite(cat_type, 2)
                bindata += self.binVarWrite(cat_size // 2, 2)
                bindata += cat_bindata

        bindata += [255, 255]  # fill ???
        return bytes(bindata)


def readeeprom(filename):
    data = []
    if filename.endswith(".bin"):
        with open(filename, "rb") as f:
            data = f.read()
            return data
    else:
        with open("sdotest.hex", "r") as f:
            for line in f.readlines():
                line = line.strip()
                if line and line[0] == ":":
                    byteCount = int(f"0x{line[1:3]}", 0)
                    Address = int(f"0x{line[3:7]}", 0)
                    Address = line[3:7]
                    Typ = line[7:9]
                    Data = line[9 : 9 + byteCount * 2]
                    cSum = line[9 + byteCount * 2 : 9 + byteCount * 2 + 2]
                    for bn in range(byteCount):
                        byte = line[9 + (bn * 2) : 9 + (bn * 2) + 2]
                        byte = int(f"0x{byte}", 0)
                        data.append(byte)
            data = bytes(data)
            return data
    return None


parser = argparse.ArgumentParser()
parser.add_argument("--info", "-i", help="show info", default=False, action="store_true")
parser.add_argument("--xml", "-x", help="export xml", default=False, action="store_true")
parser.add_argument("--bin", "-b", help="export eeprom", default=False, action="store_true")
parser.add_argument("--comp", "-c", help="compare bin", default=False, action="store_true")

parser.add_argument("--binwrite", "-bw", help="write eeprom", type=str)

parser.add_argument("filename", help="input filename .xml|.bin|.hex", nargs="?", type=str, default="")
args = parser.parse_args()

esi = Esi()

if args.filename.endswith(".bin") or args.filename.endswith(".hex"):
    bindata = readeeprom(args.filename)
    esi.binRead(bindata)

    if args.comp:
        bindata_new = esi.binWrite()
        print(list(bindata))
        print("")
        print(list(bindata_new))
        print("")
        if list(bindata) == list(bindata_new):
            print("------- OK -------")
        for pos in range(len(bindata)):
            if bindata[pos] != bindata_new[pos]:
                print(f"{pos} {bindata[pos]:8d} {bindata_new[pos]:8d}")

elif args.filename.endswith(".xml"):
    xmldata = open(args.filename, "rb").read()
    esi.xmlRead(xmldata)

if args.info:
    esi.Info()

if args.xml:
    res = esi.xmlWrite()
    print(res)

if args.bin:
    res = esi.binWrite()
    print(res)

if args.binwrite:
    res = esi.binWrite()
    print(f"writing binary data to '{args.binwrite}'")
    open(args.binwrite, "wb").write(res)
