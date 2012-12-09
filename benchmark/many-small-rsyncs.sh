#!/bin/bash

ITERS=$1
CONC=$2

n=1
while [ "$n" -le "$CONC" ]; do
  (i=1;
   while [ "$i" -le "$ITERS" ]; do
    rsync rsync://certtest-1.local/repository/30MB.dat /tmp/30MB.dat.$n
    rm /tmp/30MB.dat.$n
    i=`expr $i + 1`
  done) & 
  sleep 0.01
  n=`expr $n + 1`
done
wait

