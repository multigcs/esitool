import glob
import pytest
from esitool import Esi


filenames = []
for filename in glob.glob("tests/*.bin"):
    name = filename.replace(".bin", "")
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
