#!/usr/bin/env python3
#
#

import argparse
import sys
import tempfile
from lxml import etree
import subprocess
import struct

try:
    import dialog
except Exception:
    dialog = None


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

lcidinfo = {
    "1031": "German (Germany)",
    "1033": "English (United States)",
    "1036": "French (France)",
    "1027": "Catalan",
    "1028": "Chinese (Taiwan)",
    "1034": "Spanish (Traditional Sort)",
    "1040": "Italian (Italy)",
    "1041": "Japanese",
    "1043": "Dutch (Netherlands)",
    "1044": "Norwegian (Bokmal)",
    "1049": "Russian",
    "1053": "Swedish",
    "2052": "Chinese (PRC)",
    "2055": "German (Switzerland)",
    "2057": "English (United Kingdom)",
    "2068": "Norwegian (Nynorsk)",
    "2070": "Portuguese (Portugal)",
    "3076": "Chinese (Hong Kong S.A.R.)",
    "3081": "English (Australia)",
    "3084": "French (Canada)",
    "4100": "Chinese (Singapore)",
}


class Base:
    def __init__(self, parent):
        self.parent = parent
        self.strings = parent.strings
        self.xml_root = parent.xml_root
        self.lcid = parent.lcid
        self.lcids = parent.lcids
        self.images = parent.images
        self.deviceid = parent.deviceid
        self.deviceids = parent.deviceids
        self.debug = parent.debug
        self.device_info = parent.device_info
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
        text = str(text)
        if text not in self.parent.strings:
            self.parent.strings.append(text)
        string_index = self.parent.strings.index(text)
        return string_index

    def datatypeSet(self, datatype):
        dlist = list(datatypes.values())
        datatype = (
            datatype.replace("UINT16", "UINT")
            .replace("UINT8", "UINT")
            .replace("UINT32", "UINT")
        )
        if datatype in dlist:
            datatype_index = dlist.index(datatype)
            return datatype_index
        return 0

    def printKeyDatatype(self, key, value, prefix=""):
        datatype = datatypes.get(value, "UNSET")
        return [f"{prefix}   {key:30} {value:6d} ({datatype})"]

    def printKeyString(self, key, value, prefix=""):
        if value < len(self.parent.strings):
            text = self.parent.strings[value]
            return [f"{prefix}   {key:30} '{text}'"]
        else:
            return [f"{prefix}   {key:30} {value:6d}"]

    def printKeyValue(self, key, value, prefix="", fmt=None):
        if isinstance(value, int):
            return [f"{prefix}   {key:30} 0x{value:04x} ({value})"]
        else:
            return [f"{prefix}   {key:30} {value:6s}"]

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

    def value2xml(self, value, size=0):
        if size == 2:
            return f"#x{value:02X}"
        elif size == 4:
            return f"#x{value:04X}"
        elif size == 8:
            return f"#x{value:08X}"
        return str(value)

    def xml_value_parse(self, value):
        if isinstance(value, str):
            value = value.strip()
            if value and value.startswith("#x"):
                value = int(value.replace("#x", "0x"), 0)
            elif value == "true":
                value = 1
            elif value == "false":
                value = 0
        return value

    def xml_value(self, base_element, xpath, attribute=None, default=0):
        values = []
        result = base_element.findall(xpath)
        if result is not None and result:
            for element in result:
                lcId = element.get("LcId")
                if lcId and lcId not in self.lcids:
                    self.lcids.append(lcId)
                if lcId and self.lcid and lcId != self.lcid:
                    continue
                if attribute:
                    value = element.get(attribute, default)
                else:
                    value = element.text or default
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

        configDataElement = base_element.find(
            f"./Descriptions/Devices/Device[{self.deviceid}]/Eeprom/ConfigData"
        )
        if configDataElement is not None:
            configData = bytearray.fromhex(configDataElement.text)
            cpos = 0
            if len(configData) >= cpos + 2:
                self.pdi_ctrl = struct.unpack("<H", configData[cpos : cpos + 2])[0]
            cpos += 2
            if len(configData) >= cpos + 2:
                self.pdi_conf = struct.unpack("<H", configData[cpos : cpos + 2])[0]
            cpos += 2
            if len(configData) >= cpos + 2:
                self.sync_impulse = struct.unpack("<H", configData[cpos : cpos + 2])[0]
            cpos += 2
            if len(configData) >= cpos + 2:
                self.pdi_conf2 = struct.unpack("<H", configData[cpos : cpos + 2])[0]
            cpos += 2
            if len(configData) >= cpos + 2:
                self.alias = struct.unpack("<H", configData[cpos : cpos + 2])[0]
            cpos += 2

    def xmlWrite(self, base_element):
        Device = base_element.find(f"./Descriptions/Devices/Device[{self.deviceid}]")
        Eeprom = etree.SubElement(Device, "Eeprom")
        etree.SubElement(Eeprom, "ByteSize").text = "2048"
        ConfigData = etree.SubElement(Eeprom, "ConfigData")
        blist = []
        blist += struct.pack("<H", self.pdi_ctrl)
        blist += struct.pack("<H", self.pdi_conf)
        blist += struct.pack("<H", self.sync_impulse)
        blist += struct.pack("<H", self.pdi_conf2)
        blist += struct.pack("<H", self.alias)
        ConfigData.text = "".join([f"{b:02x}" for b in list(blist)])

    def Info(self, prefix=""):
        output = []
        output.append(f"{prefix}preamble: {self.startpos}")
        if self.debug > 0:
            output.append(f"{prefix}   bin:", list(self.bindata))
        if self.bindata and list(self.bindata) != list(self.binWrite()):
            output.append(f"{prefix}   bin:", list(self.bindata))
            output.append(f"{prefix}   bak:", list(self.binWrite()))
        output += self.printKeyValue("pdi_ctrl", self.pdi_ctrl, prefix)
        output += self.printKeyValue("pdi_conf", self.pdi_conf, prefix)
        output += self.printKeyValue("sync_impulse", self.sync_impulse, prefix)
        output += self.printKeyValue("pdi_conf2", self.pdi_conf2, prefix)
        output += self.printKeyValue("alias", self.alias, prefix)
        output += self.printKeyValue("checksum", self.checksum, prefix)
        output.append("")
        return output


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
            output.append("SIZE ERROR:", self, self.offset, self.size())
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
        self.product_id = int(
            self.xml_value(
                base_element,
                f"./Descriptions/Devices/Device[{self.deviceid}]/Type",
                "ProductCode",
            )[0]
        )
        self.revision_id = int(
            self.xml_value(
                base_element,
                f"./Descriptions/Devices/Device[{self.deviceid}]/Type",
                "RevisionNo",
            )[0]
        )
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

        for sm in base_element.findall(
            f"./Descriptions/Devices/Device[{self.deviceid}]/Sm"
        ):
            name = sm.text
            if name == "MBoxOut":
                self.std_rec_mbox_size = int(
                    self.xml_value_parse(sm.get("DefaultSize", 0))
                )
                self.std_rec_mbox_offset = int(
                    self.xml_value_parse(sm.get("StartAddress", 0))
                )
            if name == "MBoxIn":
                self.std_snd_mbox_size = int(
                    self.xml_value_parse(sm.get("DefaultSize", 0))
                )
                self.std_snd_mbox_offset = int(
                    self.xml_value_parse(sm.get("StartAddress", 0))
                )

        eeprom_size = int(
            self.xml_value(
                base_element,
                f"./Descriptions/Devices/Device[{self.deviceid}]/Eeprom/ByteSize",
            )[0]
        )
        if eeprom_size:
            self.eeprom_size = self.bytes2ee(eeprom_size)

        bootStrapElement = base_element.find(
            f"./Descriptions/Devices/Device[{self.deviceid}]/Eeprom/BootStrap"
        )
        if bootStrapElement is not None:
            bootStrap = bytearray.fromhex(bootStrapElement.text)
            cpos = 0
            self.bs_rec_mbox_offset = struct.unpack("<H", bootStrap[cpos : cpos + 2])[0]
            cpos += 2
            self.bs_rec_mbox_size = struct.unpack("<H", bootStrap[cpos : cpos + 2])[0]
            cpos += 2
            self.bs_snd_mbox_offset = struct.unpack("<H", bootStrap[cpos : cpos + 2])[0]
            cpos += 2
            self.bs_snd_mbox_size = struct.unpack("<H", bootStrap[cpos : cpos + 2])[0]
            cpos += 2

        coe = 0
        eoe = 0
        foe = 0
        voe = 0
        for mb in base_element.findall(
            f"./Descriptions/Devices/Device[{self.deviceid}]/Mailbox"
        ):
            for element in mb:
                if element.tag == "CoE":
                    coe = 0x04
                elif element.tag == "EoE":
                    eoe = 0x02
                elif element.tag == "FoE":
                    foe = 0x08
                elif element.tag == "VoE":
                    voe = 0x20
        self.mailbox_protocol = coe | eoe | foe | voe

    def xmlWrite(self, base_element):
        Vendor = base_element.find("./Vendor")
        etree.SubElement(Vendor, "Id").text = self.value2xml(self.vendor_id, 8)
        Device = base_element.find(f"./Descriptions/Devices/Device[{self.deviceid}]")
        Mailbox = base_element.find(
            f"./Descriptions/Devices/Device[{self.deviceid}]/Mailbox"
        )
        Type = Device.find("./Type")
        if Type is not None:
            Type.set("ProductCode", self.value2xml(self.product_id, 8))
            Type.set("RevisionNo", self.value2xml(self.revision_id, 8))
            if bool(self.mailbox_protocol & 0x04):
                CoE = base_element.find(
                    f"./Descriptions/Devices/Device[{self.deviceid}]/Mailbox/CoE"
                )
                if CoE is None:
                    etree.SubElement(Mailbox, "CoE")
            if bool(self.mailbox_protocol & 0x02):
                EoE = base_element.find(
                    f"./Descriptions/Devices/Device[{self.deviceid}]/Mailbox/EoE"
                )
                if EoE is None:
                    etree.SubElement(Mailbox, "EoE")
            if bool(self.mailbox_protocol & 0x08):
                FoE = base_element.find(
                    f"./Descriptions/Devices/Device[{self.deviceid}]/Mailbox/FoE"
                )
                if FoE is None:
                    etree.SubElement(Mailbox, "FoE")
            if bool(self.mailbox_protocol & 0x20):
                VoE = base_element.find(
                    f"./Descriptions/Devices/Device[{self.deviceid}]/Mailbox/VoE"
                )
                if VoE is None:
                    etree.SubElement(Mailbox, "VoE")

        Eeprom = base_element.find(
            f"./Descriptions/Devices/Device[{self.deviceid}]/Eeprom"
        )
        BootStrap = etree.SubElement(Eeprom, "BootStrap")
        blist = []
        blist += struct.pack("<H", self.bs_rec_mbox_offset)
        blist += struct.pack("<H", self.bs_rec_mbox_size)
        blist += struct.pack("<H", self.bs_snd_mbox_offset)
        blist += struct.pack("<H", self.bs_snd_mbox_size)
        BootStrap.text = "".join([f"{b:02x}" for b in list(blist)])

    def Info(self, prefix=""):
        output = []
        output.append(f"{prefix}stdconfig: {self.startpos}")
        if self.debug > 0:
            output.append(f"{prefix}   bin:", list(self.bindata))
        if self.bindata and list(self.bindata) != list(self.binWrite()):
            output.append(f"{prefix}   bin:", list(self.bindata))
            output.append(f"{prefix}   bak:", list(self.binWrite()))
        output += self.printKeyValue("vendor_id", self.vendor_id, prefix)
        output += self.printKeyValue("product_id", self.product_id, prefix)
        output += self.printKeyValue("revision_id", self.revision_id, prefix)
        output += self.printKeyValue("serial", self.serial, prefix)
        output += self.printKeyValue(
            "bs_rec_mbox_offset", self.bs_rec_mbox_offset, prefix
        )
        output += self.printKeyValue("bs_rec_mbox_size", self.bs_rec_mbox_size, prefix)
        output += self.printKeyValue(
            "bs_snd_mbox_offset", self.bs_snd_mbox_offset, prefix
        )
        output += self.printKeyValue("bs_snd_mbox_size", self.bs_snd_mbox_size, prefix)
        output += self.printKeyValue(
            "std_rec_mbox_offset", self.std_rec_mbox_offset, prefix
        )
        output += self.printKeyValue(
            "std_rec_mbox_size", self.std_rec_mbox_size, prefix
        )
        output += self.printKeyValue(
            "std_snd_mbox_offset", self.std_snd_mbox_offset, prefix
        )
        output += self.printKeyValue(
            "std_snd_mbox_size", self.std_snd_mbox_size, prefix
        )
        output += self.printKeyValue("mailbox_protocol", self.mailbox_protocol, prefix)
        output += self.printKeyValue("eeprom_size", self.eeprom_size, prefix)
        output += self.printKeyValue("version", self.version, prefix)
        output.append("")
        return output


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
        self.unknown2 = self.binVarRead(bindata, 2)  # 14
        self.phys_port01 = self.binVarRead(bindata, 1)  # 16
        self.phys_port23 = self.binVarRead(bindata, 1)  # 17
        self.physical_address = self.binVarRead(bindata, 2)  # 18
        self.offset += 12  # 19
        if self.offset != self.size():
            output.append("SIZE ERROR:", self, self.offset, self.size())
        self.device_info["name"] = self.value2xmlText(self.nameindex)
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
        bindata += self.binVarWrite(self.unknown2, 2)  # 14
        bindata += self.binVarWrite(self.phys_port01, 1)  # 16
        bindata += self.binVarWrite(self.phys_port23, 1)  # 17
        bindata += self.binVarWrite(self.physical_address, 2)  # 18
        bindata += [0] * 12  # 19
        return bindata

    def size(self):
        return 32

    def xmlRead(self, base_element):
        self.groupindex = self.stringSet(
            self.xml_value(
                base_element, "./Descriptions/Groups/Group/Type", default=""
            )[0]
        )
        self.imageindex = 0
        # self.orderindex = self.stringSet(self.xml_value(base_element, f"./Descriptions/Devices/Device[{self.deviceid}]/Type", default="")[0])
        self.orderindex = 0
        self.nameindex = self.stringSet(
            self.xml_value(
                base_element,
                f"./Descriptions/Devices/Device[{self.deviceid}]/Name",
                default="",
            )[0]
        )
        self.unknown1 = 0
        self.eoe_enabled = 0
        self.coe_details = 0
        self.foe_details = 0
        self.soe_channels = 0
        self.ds402_channels = 0
        self.sysman_class = 0
        self.flags = 0
        self.current_ebus = 0
        self.unknown2 = 1
        self.phys_port01 = 0
        self.phys_port23 = 0
        self.physical_address = 0

        for mb in base_element.findall(
            f"./Descriptions/Devices/Device[{self.deviceid}]/Mailbox"
        ):
            for element in mb:
                if element.tag == "EoE":
                    self.eoe_enabled = 1
                elif element.tag == "FoE":
                    self.foe_details = 1
                elif element.tag == "CoE":
                    details = 1
                    details |= int(self.xml_value_parse(element.get("SdoInfo", 0))) << 1
                    details |= (
                        int(self.xml_value_parse(element.get("PdoAssign", 0))) << 2
                    )
                    details |= (
                        int(self.xml_value_parse(element.get("PdoConfig", 0))) << 3
                    )
                    details |= (
                        int(self.xml_value_parse(element.get("PdoUpload", 0))) << 4
                    )
                    # details |= int(self.xml_value_parse(element.get("CompleteAccess", 0))) << 5
                    self.coe_details = details

        Device = base_element.find(f"./Descriptions/Devices/Device[{self.deviceid}]")
        if Device is not None:
            Physics = Device.get("Physics")
            if Physics:
                ports = [0, 0, 0, 0]
                for cn, char in enumerate(Physics):
                    if char == "Y":
                        ports[cn] = 0x01
                    elif char == "K":
                        ports[cn] = 0x03
                self.phys_port01 = (ports[1] << 4) | ports[0]
                self.phys_port23 = (ports[3] << 4) | ports[2]
        self.device_info["name"] = self.value2xmlText(self.nameindex)

    def xmlWrite(self, base_element):
        Device = base_element.find(f"./Descriptions/Devices/Device[{self.deviceid}]")
        Name = base_element.find(f"./Descriptions/Devices/Device[{self.deviceid}]/Name")
        GroupType = base_element.find(
            f"./Descriptions/Devices/Device[{self.deviceid}]/GroupType"
        )
        Mailbox = etree.SubElement(Device, "Mailbox")
        physics = ""
        ports = [0, 0, 0, 0]
        ports[0] = (self.phys_port01 >> 4) & 0x0F
        ports[1] = (self.phys_port01) & 0x0F
        ports[2] = (self.phys_port23 >> 4) & 0x0F
        ports[3] = (self.phys_port23) & 0x0F
        for port in ports:
            if port == 0x01:
                physics += "Y"
            elif port == 0x03:
                physics += "K"
        Device.set("Physics", physics)

        Name.text = self.value2xmlText(self.nameindex)
        GroupType.text = self.value2xmlText(self.groupindex)

        Type = Device.find("./Type")
        if Type is not None:
            Type.text = self.value2xmlText(self.orderindex)

        Group = base_element.find("./Descriptions/Groups/Group")
        if Group is not None:
            etree.SubElement(Group, "Type").text = self.value2xmlText(self.groupindex)
            etree.SubElement(Group, "Name").text = "UNKNOWN"

        if self.eoe_enabled:
            etree.SubElement(Mailbox, "EoE")
        if self.coe_details:
            CoE = etree.SubElement(Mailbox, "CoE")
            if bool(self.coe_details & (0x01 << 1)):
                CoE.set("SdoInfo", "true")
            else:
                CoE.set("SdoInfo", "false")
            if bool(self.coe_details & (0x01 << 2)):
                CoE.set("PdoAssign", "true")
            else:
                CoE.set("PdoAssign", "false")
            if bool(self.coe_details & (0x01 << 3)):
                CoE.set("PdoConfig", "true")
            else:
                CoE.set("PdoConfig", "false")
            if bool(self.coe_details & (0x01 << 4)):
                CoE.set("PdoUpload", "true")
            else:
                CoE.set("PdoUpload", "false")
            if bool(self.coe_details & (0x01 << 5)):
                CoE.set("CompleteAccess", "true")
            else:
                CoE.set("CompleteAccess", "false")
        if self.foe_details:
            etree.SubElement(Mailbox, "FoE")

    def Info(self, prefix=""):
        output = []
        output.append(f"{prefix}general: {self.startpos}")
        if self.debug > 0:
            output.append(f"{prefix}   bin:", list(self.bindata))
        if self.bindata and list(self.bindata) != list(self.binWrite()):
            output.append(f"{prefix}   bin:", list(self.bindata))
            output.append(f"{prefix}   bak:", list(self.binWrite()))
        output += self.printKeyString("nameindex", self.nameindex, prefix)
        output += self.printKeyString("groupindex", self.groupindex, prefix)
        output += self.printKeyString("imageindex", self.imageindex, prefix)
        output += self.printKeyString("orderindex", self.orderindex, prefix)

        """
  CoE Details:
    Enable SDO: .................. no
    Enable SDO Info: ............. no
    Enable PDO Assign: ........... no
    Enable PDO Configuration: .... no
    Enable Upload at startup: .... no
    Enable SDO complete access: .. no
        """
        output.append(f"{prefix}   coe_details:")
        output += self.printKeyValue(
            "  Enable SDO", (self.coe_details & (1 << 0)) and "yes" or "no", prefix
        )
        output += self.printKeyValue(
            "  Enable SDO Info", (self.coe_details & (1 << 1)) and "yes" or "no", prefix
        )
        output += self.printKeyValue(
            "  Enable PDO Assign",
            (self.coe_details & (1 << 2)) and "yes" or "no",
            prefix,
        )
        output += self.printKeyValue(
            "  Enable PDO Configuration",
            (self.coe_details & (1 << 3)) and "yes" or "no",
            prefix,
        )
        output += self.printKeyValue(
            "  Enable Upload at Startup",
            (self.coe_details & (1 << 4)) and "yes" or "no",
            prefix,
        )
        output += self.printKeyValue(
            "  Enable SDO complete access",
            (self.coe_details & (1 << 5)) and "yes" or "no",
            prefix,
        )

        output += self.printKeyValue(
            "foe_details", self.foe_details and "enabled" or "not enabled", prefix
        )
        output += self.printKeyValue(
            "eoe_enabled", self.eoe_enabled and "enabled" or "not enabled", prefix
        )
        output.append("")

        # output += self.printKeyValue("soe_channels", self.soe_channels, prefix)
        # output += self.printKeyValue("ds402_channels", self.ds402_channels, prefix)
        # output += self.printKeyValue("sysman_class", self.sysman_class, prefix)

        output += self.printKeyValue(
            "Flag SafeOp",
            (self.flags & (1 << 0)) and "enabled" or "not enabled",
            prefix,
        )
        output += self.printKeyValue(
            "Flag notLRW",
            (self.flags & (1 << 0)) and "enabled" or "not enabled",
            prefix,
        )
        output += self.printKeyValue(
            "Flag MboxDataLinkLayer",
            (self.flags & (1 << 0)) and "enabled" or "not enabled",
            prefix,
        )
        output += self.printKeyValue(
            "Flag IdentALStatus",
            (self.flags & (1 << 0)) and "enabled" or "not enabled",
            prefix,
        )
        output += self.printKeyValue(
            "Flag IdentPhysicalMemory",
            (self.flags & (1 << 0)) and "enabled" or "not enabled",
            prefix,
        )
        output.append("")
        output += self.printKeyValue("current_ebus", self.current_ebus, prefix)
        phys_port0 = (self.phys_port01) & 0x0F
        phys_port1 = (self.phys_port01 >> 4) & 0x0F
        phys_port2 = (self.phys_port23) & 0x0F
        phys_port3 = (self.phys_port23 >> 4) & 0x0F
        modes = {0: "not used", 1: "MII", 3: "EBUS"}
        output.append(f"{prefix}   Physical Ports:")
        output += self.printKeyValue(
            "  Port 0", modes.get(phys_port0, phys_port0), prefix
        )
        output += self.printKeyValue(
            "  Port 1", modes.get(phys_port1, phys_port1), prefix
        )
        output += self.printKeyValue(
            "  Port 2", modes.get(phys_port2, phys_port2), prefix
        )
        output += self.printKeyValue(
            "  Port 3", modes.get(phys_port3, phys_port3), prefix
        )
        output.append("")
        output += self.printKeyValue("physical_address", self.physical_address, prefix)
        output.append("")
        return output


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
            self.entrys[entry_num].binRead(
                bindata[self.offset : self.offset + entry_size]
            )
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
        self.name_index = self.stringSet(self.xml_value(base_element, "./Name")[0])
        self.flags = int(base_element.get("Mandatory", 0) in {"true", "1"})
        self.flags |= int(base_element.get("Fixed", 0) in {"true", "1"}) << 4
        self.flags |= int(base_element.get("Virtual", 0) in {"true", "1"}) << 5
        self.flags |= (
            int(base_element.get("OverwrittenByModule", 0) in {"true", "1"}) << 7
        )
        self.entrys = {}
        for entry in base_element.findall("./Entry"):
            self.entrys[self.entries] = pdo_entry(self)
            self.entrys[self.entries].xmlRead(entry)
            self.entries += 1

    def xmlWrite(self, base_element):
        Device = base_element.find(f"./Descriptions/Devices/Device[{self.deviceid}]")
        self.flags |= int(base_element.get("Virtual", 0) in {"true", "1"}) << 5
        self.flags |= (
            int(base_element.get("OverwrittenByModule", 0) in {"true", "1"}) << 7
        )
        element = etree.SubElement(
            Device,
            "TxPdo",
            Sm=str(self.syncmanager),
            Mandatory=self.value2xmlBool(bool(self.flags & 0x01)),
            Fixed=self.value2xmlBool(bool(self.flags & (0x01 << 4))),
            Virtual=self.value2xmlBool(bool(self.flags & (0x01 << 5))),
            OverwrittenByModule=self.value2xmlBool(bool(self.flags & (0x01 << 7))),
        )
        etree.SubElement(element, "Index").text = self.value2xml(self.index, 4)
        etree.SubElement(element, "Name").text = self.value2xmlText(self.name_index)
        for num, entry in self.entrys.items():
            entry.xmlWrite(element)

    def Info(self, prefix=""):
        output = []
        output.append(f"{prefix}txpdo: {self.startpos}")
        if self.debug > 0:
            output.append(f"{prefix}   bin:", list(self.bindata))
        if self.bindata and list(self.bindata) != list(self.binWrite()):
            output.append(f"{prefix}   bin:", list(self.bindata))
            output.append(f"{prefix}   bak:", list(self.binWrite()))
        output += self.printKeyValue("index", self.index, prefix)
        output += self.printKeyValue("entries", self.entries, prefix)
        output += self.printKeyValue("syncmanager", self.syncmanager, prefix)
        output += self.printKeyValue("dcsync", self.dcsync, prefix)
        output += self.printKeyString("name_index", self.name_index, prefix)
        output += self.printKeyValue("flags", self.flags, prefix)
        for num, entry in self.entrys.items():
            output.append(f"{prefix}   {num}:")
            output += entry.Info(f"{prefix}   ")
        output.append("")
        return output


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
            self.entrys[entry_num].binRead(
                bindata[self.offset : self.offset + entry_size]
            )
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
        self.name_index = self.stringSet(self.xml_value(base_element, "./Name")[0])
        self.flags = int(base_element.get("Mandatory", 0) in {"true", "1"})
        self.flags |= int(base_element.get("Fixed", 0) in {"true", "1"}) << 4
        self.flags |= int(base_element.get("Virtual", 0) in {"true", "1"}) << 5
        self.flags |= (
            int(base_element.get("OverwrittenByModule", 0) in {"true", "1"}) << 7
        )
        self.entrys = {}
        for entry in base_element.findall("./Entry"):
            self.entrys[self.entries] = pdo_entry(self)
            self.entrys[self.entries].xmlRead(entry)
            self.entries += 1

    def xmlWrite(self, base_element):
        Device = base_element.find(f"./Descriptions/Devices/Device[{self.deviceid}]")
        element = etree.SubElement(
            Device,
            "RxPdo",
            Sm=str(self.syncmanager),
            Mandatory=self.value2xmlBool(bool(self.flags & 0x01)),
            Fixed=self.value2xmlBool(bool(self.flags & (0x01 << 4))),
            Virtual=self.value2xmlBool(bool(self.flags & (0x01 << 5))),
            OverwrittenByModule=self.value2xmlBool(bool(self.flags & (0x01 << 7))),
        )
        etree.SubElement(element, "Index").text = self.value2xml(self.index, 4)
        etree.SubElement(element, "Name").text = self.value2xmlText(self.name_index)
        for num, entry in self.entrys.items():
            entry.xmlWrite(element)

    def Info(self, prefix=""):
        output = []
        output.append(f"{prefix}rxpdo: {self.startpos}")
        if self.debug > 0:
            output.append(f"{prefix}   bin:", list(self.bindata))
        if self.bindata and list(self.bindata) != list(self.binWrite()):
            output.append(f"{prefix}   bin:", list(self.bindata))
            output.append(f"{prefix}   bak:", list(self.binWrite()))
        output += self.printKeyValue("index", self.index, prefix)
        output += self.printKeyValue("entries", self.entries, prefix)
        output += self.printKeyValue("syncmanager", self.syncmanager, prefix)
        output += self.printKeyValue("dcsync", self.dcsync, prefix)
        output += self.printKeyString("name_index", self.name_index, prefix)
        output += self.printKeyValue("flags", self.flags, prefix)
        for num, entry in self.entrys.items():
            output.append(f"{prefix}   {num}:")
            output += entry.Info(f"{prefix}   ")
        output.append("")
        return output


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
        self.index = int(self.xml_value(base_element, "./Index")[0])
        self.subindex = int(self.xml_value(base_element, "./SubIndex")[0])
        self.string_index = self.stringSet(
            self.xml_value(base_element, "./Name", default="")[0]
        )
        self.data_type = self.datatypeSet(
            self.xml_value(base_element, "./DataType", default="")[0]
        )
        self.bit_length = int(self.xml_value(base_element, "./BitLen")[0])
        self.flags = 0

    def xmlWrite(self, base_element):
        Entry = etree.SubElement(base_element, "Entry")
        etree.SubElement(Entry, "Index").text = self.value2xml(self.index, 4)
        etree.SubElement(Entry, "SubIndex").text = str(self.subindex)
        etree.SubElement(Entry, "BitLen").text = str(self.bit_length)
        etree.SubElement(Entry, "Name").text = self.value2xmlText(self.string_index)
        etree.SubElement(Entry, "DataType").text = self.value2xmlDatatype(
            self.data_type
        )

    def Info(self, prefix=""):
        output = []
        output.append(f"{prefix}pdo_entry:")
        if self.debug > 0:
            output.append(f"{prefix}   bin:", list(self.bindata))
        if self.bindata and list(self.bindata) != list(self.binWrite()):
            output.append(f"{prefix}   bin:", list(self.bindata))
            output.append(f"{prefix}   bak:", list(self.binWrite()))
        output += self.printKeyValue("index", self.index, prefix)
        output += self.printKeyValue("subindex", self.subindex, prefix)
        output += self.printKeyString("string_index", self.string_index, prefix)
        output += self.printKeyDatatype("data_type", self.data_type, prefix)
        output += self.printKeyValue("bit_length", self.bit_length, prefix)
        output += self.printKeyValue("flags", self.flags, prefix)
        output.append("")
        return output


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
            self.entrys[entry_num].binRead(
                bindata[self.offset : self.offset + entry_size]
            )
            self.offset += entry_size
            entry_num += 1
            if (len(bindata) - self.offset) < entry_size:
                break
        if self.offset % 2 != 0:
            self.fill = bindata[-1]
            self.offset += 1
        return self.offset

    def binWrite(self):
        bindata = []
        for num, entry in self.entrys.items():
            bindata += entry.binWrite()
        if len(bindata) % 2 != 0:
            bindata += [0]
        return bindata

    def size(self):
        return 0

    def xmlRead(self, base_element):
        self.entrys = {}
        entry_num = 0
        for fmmu in base_element.findall(
            f"./Descriptions/Devices/Device[{self.deviceid}]/Fmmu"
        ):
            self.entrys[entry_num] = fmmu_entry(self)
            self.entrys[entry_num].xmlRead(fmmu)
            entry_num += 1

    def xmlWrite(self, base_element):
        for num, entry in self.entrys.items():
            entry.xmlWrite(base_element)

    def Info(self, prefix=""):
        output = []
        output.append(f"{prefix}fmmu: {self.startpos}")
        if self.debug > 0:
            output.append(f"{prefix}   bin:", list(self.bindata))
        if self.bindata and list(self.bindata) != list(self.binWrite()):
            output.append(f"{prefix}   bin:", list(self.bindata))
            output.append(f"{prefix}   bak:", list(self.binWrite()))
        for num, entry in self.entrys.items():
            output.append(f"{prefix}   {num}:")
            output += entry.Info(f"{prefix}   ")
        output.append("")
        return output


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
        Device = base_element.find(f"./Descriptions/Devices/Device[{self.deviceid}]")
        Fmmu = etree.SubElement(Device, "Fmmu")
        if self.usage == 0x01:
            Fmmu.text = "Outputs"
        elif self.usage == 0x02:
            Fmmu.text = "Inputs"
        elif self.usage == 0x03:
            Fmmu.text = "MBoxState"

    def xmlRead(self, base_element):
        self.usage = 0
        if base_element is not None:
            text = base_element.text
            if text == "Outputs":
                self.usage = 0x01
            elif text == "Inputs":
                self.usage = 0x02
            elif text == "MBoxState":
                self.usage = 0x03

    def Info(self, prefix=""):
        output = []
        output.append(f"{prefix}fmmu_entry:")
        if self.debug > 0:
            output.append(f"{prefix}   bin:", list(self.bindata))
        if self.bindata and list(self.bindata) != list(self.binWrite()):
            output.append(f"{prefix}   bin:", list(self.bindata))
            output.append(f"{prefix}   bak:", list(self.binWrite()))
        output += self.printKeyValue("usage", self.usage, prefix)
        output.append("")
        return output


class syncm(Base):
    cat_type = 41

    def binRead(self, bindata):
        self.startpos = self.parent.startpos
        self.bindata = bindata
        self.offset = 0
        self.entrys = {}
        entry_num = 0
        if len(bindata) == self.offset:
            return 0
        while True:
            self.entrys[entry_num] = syncm_entry(self)
            entry_size = self.entrys[entry_num].size()
            self.entrys[entry_num].binRead(
                bindata[self.offset : self.offset + entry_size]
            )
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
        for syncm in base_element.findall(
            f"./Descriptions/Devices/Device[{self.deviceid}]/Sm"
        ):
            self.entrys[entry_num] = syncm_entry(self)
            self.entrys[entry_num].xmlRead(syncm)
            entry_num += 1

    def xmlWrite(self, base_element):
        for num, entry in self.entrys.items():
            entry.xmlWrite(base_element)

    def Info(self, prefix=""):
        output = []
        output.append(f"{prefix}syncm: {self.startpos}")
        if self.debug > 0:
            output.append(f"{prefix}   bin:", list(self.bindata))
        if self.bindata and list(self.bindata) != list(self.binWrite()):
            output.append(f"{prefix}   bin:", list(self.bindata))
            output.append(f"{prefix}   bak:", list(self.binWrite()))
        for num, entry in self.entrys.items():
            output.append(f"{prefix}   {num}:")
            output += entry.Info(f"{prefix}   ")
        output.append("")
        return output


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
        self.phys_address = int(
            self.xml_value_parse(base_element.get("StartAddress", 0))
        )
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
        Device = base_element.find(f"./Descriptions/Devices/Device[{self.deviceid}]")
        Sm = etree.SubElement(
            Device,
            "Sm",
            Enable=str(self.enable),
            StartAddress=self.value2xml(self.phys_address, 4),
            ControlByte=self.value2xml(self.control, 2),
            DefaultSize=str(self.lenght),
        )
        if self.type == 1:
            Sm.text = "MBoxOut"
        elif self.type == 2:
            Sm.text = "MBoxIn"
        elif self.type == 3:
            Sm.text = "Outputs"
        elif self.type == 4:
            Sm.text = "Inputs"

    def Info(self, prefix=""):
        output = []
        output.append(f"{prefix}syncm_entry:")
        if self.debug > 0:
            output.append(f"{prefix}   bin:", list(self.bindata))
        if self.bindata and list(self.bindata) != list(self.binWrite()):
            output.append(f"{prefix}   bin:", list(self.bindata))
            output.append(f"{prefix}   bak:", list(self.binWrite()))
        output += self.printKeyValue("phys_address", self.phys_address, prefix)
        output += self.printKeyValue("lenght", self.lenght, prefix)
        output += self.printKeyValue("control", self.control, prefix)
        output += self.printKeyValue("status", self.status, prefix)
        output += self.printKeyValue("enable", self.enable, prefix)
        output += self.printKeyValue("type", self.type, prefix)
        output.append("")
        return output


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
        self.nameIdx = self.stringSet(
            self.xml_value(base_element, "./Name", default="")[0]
        )
        self.descIdx = self.stringSet(
            self.xml_value(base_element, "./Desc", default="")[0]
        )
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
        Device = base_element.find(f"./Descriptions/Devices/Device[{self.deviceid}]")
        Dc = base_element.find(f"./Descriptions/Devices/Device[{self.deviceid}]/Dc")
        if Dc is None:
            Dc = etree.SubElement(Device, "Dc")

        OpMode = etree.SubElement(Dc, "OpMode")
        etree.SubElement(OpMode, "Name").text = self.value2xmlText(self.nameIdx)
        etree.SubElement(OpMode, "Desc").text = self.value2xmlText(self.descIdx)

        etree.SubElement(OpMode, "AssignActivate").text = self.value2xml(
            self.assignActivate, 2
        )

        etree.SubElement(
            OpMode, "CycleTimeSync0", Factor=self.value2xml(self.sync0CycleFactor)
        ).text = self.value2xml(self.cycleTime0)
        etree.SubElement(OpMode, "ShiftTimeSync0").text = self.value2xml(
            self.shiftTime0
        )
        # etree.SubElement(
        #     OpMode, "CycleTimeSync1", Factor=self.value2xml(self.sync1CycleFactor)
        # ).text = self.value2xml(self.cycleTime1)
        etree.SubElement(OpMode, "ShiftTimeSync1").text = self.value2xml(
            self.shiftTime1
        )

    def Info(self, prefix=""):
        output = []
        output.append(f"{prefix}dclock: {self.startpos}")
        if self.debug > 0:
            output.append(f"{prefix}   bin:", list(self.bindata))
        if self.bindata and list(self.bindata) != list(self.binWrite()):
            output.append(f"{prefix}   bin:", list(self.bindata))
            output.append(f"{prefix}   bak:", list(self.binWrite()))
        output += self.printKeyValue("cycleTime0", self.cycleTime0, prefix)
        output += self.printKeyValue("shiftTime0", self.shiftTime0, prefix)
        output += self.printKeyValue("shiftTime1", self.shiftTime1, prefix)
        output += self.printKeyValue("sync1CycleFactor", self.sync1CycleFactor, prefix)
        output += self.printKeyValue("assignActivate", self.assignActivate, prefix)
        output += self.printKeyValue("sync0CycleFactor", self.sync0CycleFactor, prefix)
        output += self.printKeyString("nameIdx", self.nameIdx, prefix)
        output += self.printKeyString("descIdx", self.descIdx, prefix)
        output.append("")
        return output


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
            strlen = len(text.encode())
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
        output = []
        self.num_strings = len(self.parent.strings[1:])
        output.append(f"{prefix}strings: {self.startpos}")
        if self.debug > 0:
            output.append(f"{prefix}   bin:", list(self.bindata))
        if self.bindata and list(self.bindata) != list(self.binWrite()):
            output.append(f"{prefix}   bin:", list(self.bindata))
            output.append(f"{prefix}   bak:", list(self.binWrite()))
        output += self.printKeyValue("Strings", self.num_strings, prefix)
        for tn, text in enumerate(self.strings):
            output += self.printKeyValue(f"{tn}", f"'{text}'", prefix)
        output.append("")
        return output


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
        output = []
        output.append(f"{prefix}UNKNOWN CATALOG: {self.startpos}")
        if self.debug > 0:
            output.append(f"{prefix}   bin:", list(self.bindata))
        if self.bindata and list(self.bindata) != list(self.binWrite()):
            output.append(f"{prefix}   bin:", list(self.bindata))
            output.append(f"{prefix}   bak:", list(self.binWrite()))
        output += self.printKeyValue("Type-Id", self.cat_type, prefix)
        output += self.printKeyValue("Cat-Size", self.cat_size, prefix)
        output.append("")
        return output


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
    def __init__(self, filename, lcid=None, deviceid=None, debug=0):
        self.lcid = lcid
        self.lcids = []
        if deviceid is None:
            deviceid = "1"
        self.deviceid = deviceid
        self.deviceids = []
        self.device_info = {"name": ""}
        self.debug = debug
        self.images = {}
        self.offset = 0
        self.catalogs = {}
        self.xml_root = None
        self.strings = [""]
        self.preamble = preamble(self)
        self.stdconfig = stdconfig(self)

        if filename.endswith(".bin") or filename.endswith(".hex"):
            bindata = self.readeeprom(filename)
            self.binRead(bindata)
        elif filename.endswith(".xml"):
            xmldata = open(filename, "rb").read()
            self.xmlRead(xmldata)

        elif filename and filename.isnumeric():
            slave_id = filename
            cmd = ["ethercat", "sii_read", "-p", slave_id]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode != 0:
                print("#################################################")
                print(f"# error getting eeprom from slave ({slave_id})")
                print("#################################################")
                print(f"# cmd: {' '.join(cmd)}")
                print("#################################################")
                print("")
                print(result.stderr.decode())
                exit(1)
            else:
                bindata = result.stdout
                self.binRead(bindata)

        else:
            print(f"UNKNOWN FORMAT: {filename}")

    def xmlRead(self, xmldata):
        root = etree.fromstring(xmldata)
        self.xml_root = root

        elements = root.findall("./Descriptions/Devices/Device/Type")
        for element in elements:
            self.deviceids.append(element.text)

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

        for pdo in root.findall(
            f"./Descriptions/Devices/Device[{self.deviceid}]/RxPdo"
        ):
            self.catalogs[cat_num] = rxpdo(self)
            self.catalogs[cat_num].xmlRead(pdo)
            cat_num += 1

        for pdo in root.findall(
            f"./Descriptions/Devices/Device[{self.deviceid}]/TxPdo"
        ):
            self.catalogs[cat_num] = txpdo(self)
            self.catalogs[cat_num].xmlRead(pdo)
            cat_num += 1

        for opMode in root.findall(
            f"./Descriptions/Devices/Device[{self.deviceid}]/Dc/OpMode"
        ):
            self.catalogs[cat_num] = dclock(self)
            self.catalogs[cat_num].xmlRead(opMode)
            cat_num += 1

        elements = root.find("./Vendor")
        for element in elements:
            if element.tag is etree.Comment:
                continue
            if element.tag.startswith("ImageData"):
                imageData = bytearray.fromhex(element.text)
                self.images[f"Vendor/{element.tag.replace('ImageData', '')}"] = (
                    imageData
                )
                open("/tmp/test.img", "wb").write(imageData)

        elements = root.find(f"./Descriptions/Devices/Device[{self.deviceid}]")
        for element in elements:
            if element.tag is etree.Comment:
                continue
            if element.tag.startswith("ImageData"):
                imageData = bytearray.fromhex(element.text)
                self.images[f"Device/{element.tag.replace('ImageData', '')}"] = (
                    imageData
                )
                open("/tmp/test.img", "wb").write(imageData)

    def binRead(self, bindata):
        self.startpos = 0
        self.offset = 0
        self.offset += self.preamble.binRead(bindata[0 : 0 + self.preamble.size()])
        self.startpos = self.offset
        self.offset += self.stdconfig.binRead(
            bindata[self.offset : self.offset + self.stdconfig.size()]
        )
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
                self.catalogs[cat_num].binRead(
                    bindata[self.offset : self.offset + cat_size]
                )
                if cat_name == "strings":
                    self.strings = self.catalogs[cat_num].strings
            else:
                if cat_type != 65535:  # fill at the end
                    print(
                        "###############################################################"
                    )
                    print("Unknown catalog")
                    print(
                        f" Num:{cat_num}, Name:{cat_name}, Type:{cat_type}, Size:{cat_size}"
                    )
                    if cat_size < 100:
                        print(bindata[self.offset : self.offset + cat_size])
                        print(list(bindata[self.offset : self.offset + cat_size]))
                    print(
                        "###############################################################"
                    )
                    if cat_size < 100:
                        self.catalogs[cat_num] = unknown_cat(self)
                        self.catalogs[cat_num].cat_type = cat_type
                        self.catalogs[cat_num].cat_size = cat_size
                        self.startpos = self.offset
                        self.catalogs[cat_num].binRead(
                            bindata[self.offset : self.offset + cat_size]
                        )

            self.offset += cat_size
            cat_num += 1

    def xmlWrite(self):
        xmlns = "EtherCATInfo.xsd"
        xsi = "http://www.w3.org/2001/XMLSchema-instance"
        root = etree.Element("EtherCATInfo", nsmap={"xsi": xsi})
        root.set(f"{{{xsi}}}noNamespaceSchemaLocation", xmlns)
        root.set("Version", "1.6")

        Vendor = etree.SubElement(root, "Vendor")
        Descriptions = etree.SubElement(root, "Descriptions")
        Groups = etree.SubElement(Descriptions, "Groups")
        etree.SubElement(Groups, "Group")
        Devices = etree.SubElement(Descriptions, "Devices")
        Device = etree.SubElement(Devices, "Device")
        etree.SubElement(Device, "Type")
        etree.SubElement(Device, "Name")
        etree.SubElement(Device, "GroupType")

        categorys_out = {
            0: "nop",
            10: "strings",
            20: "datatypes",
            40: "fmmu",
            41: "syncm",
            51: "rxpdo",
            50: "txpdo",
            30: "general",
            60: "dclock",
        }

        for ctype in categorys_out:
            for cat_num, catalog in self.catalogs.items():
                if catalog.cat_type != ctype:
                    continue
                catalog.xmlWrite(root)

        self.preamble.xmlWrite(root)
        self.stdconfig.xmlWrite(root)

        etree.SubElement(Vendor, "Name").text = "UNKNOWN"

        # cleanup
        Mailbox = root.find("./Descriptions/Devices/Device/Mailbox")
        if not list(Mailbox):
            Mailbox.getparent().remove(Mailbox)

        return (
            '<?xml version="1.0" encoding="ISO8859-1"?>\n'
            + etree.tostring(root, pretty_print=True).decode()
        )

    def Info(self, prefix=""):
        output = []
        output += self.preamble.Info(prefix)
        output += self.stdconfig.Info(prefix)
        for cat_num, catalog in self.catalogs.items():
            output += catalog.Info(prefix)

        if self.deviceids:
            output.append(f"{prefix}DeviceId's:")
            for deviceid, name in enumerate(self.deviceids, 1):
                if str(self.deviceid) == str(deviceid):
                    output += self.printKeyValue(
                        "DeviceId", f"{deviceid} ({name}) *", prefix
                    )
                else:
                    output += self.printKeyValue(
                        "DeviceId", f"{deviceid} ({name})", prefix
                    )
        output.append("")

        if self.lcids:
            output.append(f"{prefix}Locale Identifiers (LcId's):")
            for lcid in sorted(self.lcids):
                if self.lcid == lcid:
                    output += self.printKeyValue(
                        "LcId", f"{lcid} ({lcidinfo.get(lcid, '')}) *", prefix
                    )
                else:
                    output += self.printKeyValue(
                        "LcId", f"{lcid} ({lcidinfo.get(lcid, '')})", prefix
                    )
        output.append("")

        if self.images:
            output.append(f"{prefix}Images:")
            for name in sorted(self.images):
                output += self.printKeyValue("Image", f"{name}", prefix)
        output.append("")
        return output

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
                # write only filled catalogs
                if cat_size > 0:
                    bindata += self.binVarWrite(cat_type, 2)
                    bindata += self.binVarWrite(cat_size // 2, 2)
                    bindata += cat_bindata

        bindata += [255, 255]  # fill ???
        return bytes(bindata)

    def readeeprom(self, filename):
        data = []
        if filename.endswith(".bin"):
            with open(filename, "rb") as f:
                data = f.read()
                return data
        else:
            with open(filename, "r") as f:
                for line in f.readlines():
                    line = line.strip()
                    if line and line[0] == ":":
                        byteCount = int(f"0x{line[1:3]}", 0)
                        # Address = line[3:7]
                        # Typ = line[7:9]
                        # Data = line[9 : 9 + byteCount * 2]
                        # cSum = line[9 + byteCount * 2 : 9 + byteCount * 2 + 2]
                        for bn in range(byteCount):
                            byte = line[9 + (bn * 2) : 9 + (bn * 2) + 2]
                            byte = int(f"0x{byte}", 0)
                            data.append(byte)
                data = bytes(data)
                return data
        return None


def ethercat_slaves():
    menuentries = []
    cmd = ["ethercat", "slaves"]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode == 0:
        for line in result.stdout.decode().split("\n"):
            if not line:
                continue
            splitted = line.split()
            slave_id = splitted[0]
            # full_id = splitted[1]
            # status = splitted[2]
            # plus = splitted[3]
            slave_name = " ".join(splitted[4:])
            menuentries.append((slave_id, slave_name))
    return menuentries


def ethercat_sii_write(slave_id, bindata):
    with tempfile.NamedTemporaryFile() as tmp:
        open(tmp.name, "wb").write(bindata)
        cmd = ["ethercat", "sii_write", "-p", slave_id, tmp.name]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            print("done")
        else:
            print("#################################################")
            print(f"# error writing eeprom to slave ({slave_id})")
            print("#################################################")
            print(f"# cmd: {' '.join(cmd)}")
            print("#################################################")
            print("")
            print(result.stderr.decode())
            exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    if dialog is not None:
        parser.add_argument(
            "--menu", "-m", help="use menu", default=False, action="store_true"
        )
    parser.add_argument(
        "--debug", "-D", help="show debug infos", default=False, action="store_true"
    )
    parser.add_argument(
        "--info", "-i", help="show info", default=False, action="store_true"
    )
    parser.add_argument(
        "--xml", "-x", help="print xml", default=False, action="store_true"
    )
    parser.add_argument(
        "--bin", "-b", help="print eeprom data", default=False, action="store_true"
    )
    parser.add_argument(
        "--comp", "-c", help="compare bin", default=False, action="store_true"
    )
    parser.add_argument("--lcid", "-l", help="Location ID", type=str)
    parser.add_argument("--deviceid", "-d", help="Device ID", type=str)
    parser.add_argument("--imgsave", "-is", help="save image to file", type=str)
    parser.add_argument("--binsave", "-bs", help="save eeprom to file", type=str)
    parser.add_argument("--binwrite", "-bw", help="write eeprom to flash", type=str)
    parser.add_argument(
        "filename",
        help="input filename .xml|.bin|.hex|slave-number",
        nargs="?",
        type=str,
        default="",
    )
    args = parser.parse_args()
    if dialog is None:
        args.menu = None

    if args.menu:
        if not args.filename:
            menuentries = ethercat_slaves()
            if menuentries:
                d = dialog.Dialog()
                code, tag = d.menu("read eeprom from slave:", choices=menuentries)
                if code != "ok":
                    exit(0)
                args.filename = tag

        if args.filename:
            esi = Esi(args.filename)

            if args.deviceid is None and esi.deviceids:
                d = dialog.Dialog()
                menuentries = []
                for deviceid, name in enumerate(esi.deviceids, 1):
                    menuentries.append((str(deviceid), name))
                code, tag = d.menu("Select an Device:", choices=menuentries)
                if code != "ok":
                    exit(0)
                args.deviceid = tag

            if args.lcid is None and esi.lcids:
                d = dialog.Dialog()
                menuentries = []
                for lcid in sorted(esi.lcids):
                    menuentries.append((lcid, f"{lcid} ({lcidinfo.get(lcid, '')})"))
                code, tag = d.menu(
                    "Select an Location-Identifier:", choices=menuentries
                )
                if code != "ok":
                    exit(0)
                args.lcid = tag

    if not args.filename:
        parser.print_help(sys.stderr)
        exit(1)

    esi = Esi(args.filename, lcid=args.lcid, deviceid=args.deviceid, debug=args.debug)

    if (
        args.menu
        and args.info is False
        and args.xml is False
        and args.bin is False
        and args.binsave is None
        and args.imgsave is None
        and args.binwrite is None
    ):
        menuentries = (
            ("I", "show Info"),
            ("X", "print XML (uncomplete)"),
            ("B", "print Binary"),
            ("P", "save Image"),
            ("W", "write eeprom"),
        )
        d = dialog.Dialog()
        code, tag = d.menu(
            f"select output for '{esi.device_info['name']}':", choices=menuentries
        )
        if code != "ok":
            exit(0)
        if tag == "I":
            args.info = True
        elif tag == "X":
            args.xml = True
        elif tag == "B":
            args.bin = True
        elif tag == "W":
            args.binwrite = ""
        elif tag == "P":
            args.imgsave = ""
        else:
            exit(0)

    if args.info:
        output = esi.Info()
        if args.menu:
            d = dialog.Dialog()
            code, tag = d.scrollbox("\n".join(output), title="ESI-Info")
        else:
            print("\n".join(output))

    if args.xml:
        res = esi.xmlWrite()
        print(res)

    if args.bin:
        res = esi.binWrite()
        print(res)

    if args.binsave:
        res = esi.binWrite()
        print(f"writing binary data to '{args.binsave}'")
        open(args.binsave, "wb").write(res)

    if args.imgsave is not None:
        if not args.binwrite and args.menu:
            menuentries = []
            for image in esi.images:
                menuentries.append((image, image))
            if menuentries:
                d = dialog.Dialog()
                code, tag = d.menu("write eeprom to slave:", choices=menuentries)
                if code != "ok":
                    exit(0)
                args.imgsave = tag
            else:
                print("no images found")
        if not args.imgsave:
            print("no image selected")
        elif args.imgsave not in esi.images:
            print(f"{args.imgsave} not found in {list(esi.images.keys())}")
        else:
            filename = f"{args.imgsave.replace('/', '_')}.bmp"
            print(f"write image to {filename}")
            open(filename, "wb").write(esi.images[args.imgsave])

    if args.binwrite is not None:
        if not args.binwrite and args.menu:
            menuentries = ethercat_slaves()
            if menuentries:
                d = dialog.Dialog()
                code, tag = d.menu(
                    f"write eeprom for '{esi.device_info['name']}' to slave:",
                    choices=menuentries,
                )
                if code != "ok":
                    exit(0)
                args.binwrite = tag
        slave_id = args.binwrite
        bindata = esi.binWrite()
        print(f"write bin to eeprom on slave ({slave_id})...")
        ethercat_sii_write(slave_id, bindata)
