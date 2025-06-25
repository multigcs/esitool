
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
	siitool -m -c -o $@ "$<"
