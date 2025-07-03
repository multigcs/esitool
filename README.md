# ESI-Tool
Ethercat ESI-File Tool

* convert xml into .bin files (eeprom)
* display infos of .bin and .hex files

!!! WIP !!!

## Status
* bin read
* xml read
* bit compatible to siitool (xml->bin / but small test base)
* initial lcid support

## TODO
* more tests
* test agains TwinCat
* fixing xml export
* editor

## quick start

Display infos of an .bin file:
```
python3 esitool.py tests/xml2bin/single.bin -i 
```

Convert .xml into .bin:
```
python3 esitool.py -bs single.bin tests/xml2bin/single.xml
```

write .bin to eeprom on 1st ethercat device
```
ethercat sii_write -p 0 FILE.bin
```

## running tests

```
make test
```
