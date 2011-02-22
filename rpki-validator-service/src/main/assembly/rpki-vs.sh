#!/bin/sh

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

set lib/*.jar
CLASSPATH=$(IFS=:; echo "$*")


RPKI_VALIDATOR_PID_FILE=rpki-vs.pid 
RPKI_VALIDATOR_CMD="$JAVA $JAVA_OPTS -cp $CLASSPATH net.ripe.rpki.validator.daemon.JettyServerRunnerMain"


case $CMD in
    start)
        echo "Starting rpki-validator"
        $RPKI_VALIDATOR_CMD &
                echo $! >> $RPKI_VALIDATOR_PID_FILE
        ;;
    stop)
        echo "Stopping rpki-validator"
        if [ -e $RPKI_VALIDATOR_PID_FILE ]
        then
            kill `cat $RPKI_VALIDATOR_PID_FILE` && rm $RPKI_VALIDATOR_PID_FILE
        else
            echo "rpki-validator was not running"
        fi
        ;;
    *)
        echo "Usage: $0 { start | stop }"
        ;;
esac