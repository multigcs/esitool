
XMLFILES := $(shell find tests -name '*.xml')
BINFILES = $(XMLFILES:.xml=.bin)

all: format test

test: testfiles
	python3 -m pytest -vv -v tests/

format:
	ruff format *.py tests/*.py

check:
	ruff check *.py tests/*.py

testfiles: ${BINFILES}

tests/%.bin: tests/%.xml
	xmllint --schema tests/EtherCATInfo.xsd "$<" >/dev/null
	siitool -m -c -o $@ "$<"
