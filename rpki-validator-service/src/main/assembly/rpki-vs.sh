#!/bin/sh
#
# The BSD License
#
# Copyright (c) 2010, 2011 RIPE NCC
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#   - Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimer.
#   - Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions and the following disclaimer in the documentation
#     and/or other materials provided with the distribution.
#   - Neither the name of the RIPE NCC nor the names of its contributors may be
#     used to endorse or promote products derived from this software without
#     specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#


cd `dirname $0`
CMD=$1

#
# Specify the location of the Java home directory. If set then $JAVA will
# be defined to $JAVA_HOME/bin/java, else $JAVA will be "java".
#
JAVA_HOME="/usr/local/bad/java"

if [ -n "$JAVA_HOME" ]; then
    JAVA="$JAVA_HOME/bin/java"
else
    JAVA="java"
fi

# wicket configuration type: [deployment|development]
JAVA_OPTS="$JAVA_OPTS -Dwicket.configuration=deployment"

# change config directory to be placed elsewhere
#JAVA_OPTS="$JAVA_OPTS -Drpki.config=<absolute path>"

set lib/*.jar
CLASSPATH=$(IFS=:; echo "$*")

RPKI_VALIDATOR_PID_FILE=rpki-vs.pid 
RPKI_VALIDATOR_CMD="$JAVA $JAVA_OPTS -cp $CLASSPATH net.ripe.rpki.validator.daemon.JettyServerRunnerMain"


case $CMD in
    start)
        echo "Starting rpki-validator service..."
        $RPKI_VALIDATOR_CMD &
                echo $! >> $RPKI_VALIDATOR_PID_FILE
        ;;
    stop)
        echo "Stopping rpki-validator service..."
        if [ -e $RPKI_VALIDATOR_PID_FILE ]
        then
            kill `cat $RPKI_VALIDATOR_PID_FILE` && rm $RPKI_VALIDATOR_PID_FILE
        else
            echo "rpki-validator service was not running"
        fi
        ;;
    *)
        echo "Usage: $0 { start | stop }"
        ;;
esac