#!/bin/bash

i=1
while [ $i -le $1 ]; do
  rsync --recursive --update --delete --times rsync://certtest-1.local/repository/db/0a4ae9-4ae1-4555-9115-3cacf05d535a/1 certtest-1/db/0a4ae9-4ae1-4555-9115-3cacf05d535a/1 & 
  sleep 0.001
  i=`expr $i + 1`
done
wait
