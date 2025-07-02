import glob
import pytest
from esitool import Esi


filenames = []
for filename in glob.glob("tests/xml2bin/*.xml"):
    name = filename.replace(".xml", "")
    filenames.append(name)


@pytest.mark.parametrize(
    "name",
    filenames,
)
def test_xml2bin(name):
    esi = Esi(f"{name}.xml")
    expected = open(f"{name}.bin", "rb").read()

    bindata = esi.binWrite()

    if list(expected) == list(bindata):
        print("------- OK -------")
    for pos in range(len(expected)):
        if expected[pos] != bindata[pos]:
            print(f"{pos} {expected[pos]:8d} {bindata[pos]:8d}")

    assert list(expected) == list(bindata)


@pytest.mark.parametrize(
    "name, deviceid, lcid",
    [
        (
            "tests/xml2bin/siem",
            "1",
            "1031",
        ),
        (
            "tests/xml2bin/siem",
            "2",
            "1031",
        ),
        (
            "tests/xml2bin/siem",
            "1",
            "1033",
        ),
        (
            "tests/xml2bin/siem",
            "2",
            "1033",
        ),
    ],
)
def test_xml2bin_options(name, deviceid, lcid):
    esi = Esi(f"{name}.xml", lcid=lcid, deviceid=deviceid)
    bindata = esi.binWrite()
    open(f"{name}_{deviceid}_{lcid}.bin", "wb").write(bindata)
    expected = open(f"{name}_{deviceid}_{lcid}.bin", "rb").read()
    if list(expected) == list(bindata):
        print("------- OK -------")
    for pos in range(len(expected)):
        if expected[pos] != bindata[pos]:
            print(f"{pos} {expected[pos]:8d} {bindata[pos]:8d}")

    assert list(expected) == list(bindata)
