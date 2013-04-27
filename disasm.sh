./peinfo "$1" dumptext > hex
objdump -D -b binary -mi386 hex | gvim -
