#!/bin/bash
#
#

set -e
set -x

XML=$1

siitool -o /tmp/tmp1.bin -m -c $XML
python3 esitool.py /tmp/tmp1.bin -i > /tmp/t1
#python3 esitool.py -l 1033 $XML -bw /tmp/tmp2.bin
python3 esitool.py $XML -bw /tmp/tmp2.bin
python3 esitool.py /tmp/tmp2.bin -i > /tmp/t2

echo "fldiff /tmp/t1 /tmp/t2"

