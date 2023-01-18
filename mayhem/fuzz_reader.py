#!/usr/bin/env python3
import atheris
import io
import sys

with atheris.instrument_imports():
    import clevercsv

sniffer = clevercsv.Sniffer()


@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    try:
        excel_data = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
        with io.StringIO(excel_data) as csvfile:
            dialect = sniffer.sniff(excel_data)
            clevercsv.reader(csvfile, dialect)
    except clevercsv.Error:
        return -1
    except ValueError as e:
        if 'dialect' not in str(e):
            raise


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == '__main__':
    main()
