#!/bin/bash

ab -n $1 -c $2  http://certtest-1.local/certification/repository/30MB.dat 
#>& /dev/null
