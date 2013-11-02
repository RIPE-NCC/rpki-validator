#!/usr/bin/env bash
#
# The BSD License
#
# Copyright (c) 2010-2012 RIPE NCC
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

# Don't edit this script, but use JAVA_OPTS to override these settings.
DEFAULT_JVM_ARGUMENTS="-Xms1024m -Xmx1024m"

EXECUTION_DIR=`dirname "$BASH_SOURCE"`
cd ${EXECUTION_DIR}

APP_NAME="rpki-validator"
PID_FILE=${APP_NAME}.pid

function error_exit {
    echo -e "[ error ] $1"
    exit 1
}

function info {
    echo -e "[ info ] $1"
}

function warn {
    echo -e "[ warn ] $1"
}

function usage {
cat << EOF
Usage: $0 start [-c my-configuration.conf]
   or  $0 stop [-c my-configuration.conf]
   or  $0 status [-c my-configuration.conf]
EOF
}

#
# Specify the location of the Java home directory. If set then $JAVA_CMD will
# be defined to $JAVA_HOME/bin/java
#
if [ -d "${JAVA_HOME}"  ] ; then
    JAVA_CMD="${JAVA_HOME}/bin/java"
else
    warn "JAVA_HOME is not set, will try to find java on path."
    JAVA_CMD=`which java`
fi

if [ -z $JAVA_CMD ]; then
    error_exit "Cannot find java on path. Make sure java is installed and/or set JAVA_HOME"
fi


# See how we're called
FIRST_ARG="$1"
shift
if [[ -n $MODE ]]; then
   usage
   exit
fi


# Parse config file, if given
getopts ":c:" OPT_NAME
CONFIG_FILE=$OPTARG

HTTP_PORT_VALUE="8080"
RTR_PORT_VALUE="8282"
LIB_DIR="lib"

ENV_ARGUMENTS="-Dapp.name=${APP_NAME}"
if [[ -n $CONFIG_FILE ]]; then

    if [[ ! $CONFIG_FILE =~ .*conf$ ]]; then
         error_exit "Configuration file name must end with .conf"
    fi

    if [[ ! -r $CONFIG_FILE ]]; then
         error_exit "Can't read config file: $CONFIG_FILE"
    fi

    ALT_HTTP_PORT=`grep "^ui.http.port" $CONFIG_FILE | awk -F "=" '{ print $2 }'`
    ALT_RTR_PORT=`grep "^rtr.port" $CONFIG_FILE | awk -F "=" '{ print $2 }'`
    ALT_LIB_DIR=`grep "^locations.libdir" $CONFIG_FILE | awk -F "=" '{ print $2 }'`
    ALT_PID_FILE=`grep "^locations.pidfile" $CONFIG_FILE | awk -F "=" '{ print $2 }'`

    ENV_ARGUMENTS="$ENV_ARGUMENTS -Dconfig.file=$CONFIG_FILE"
    LIB_DIR=${ALT_LIB_DIR:-$LIB_DIR}
    HTTP_PORT_VALUE=${ALT_HTTP_PORT:-$HTTP_PORT_VALUE}
    RTR_PORT_VALUE=${ALT_RTR_PORT:-$RTR_PORT_VALUE}
    PID_FILE=${ALT_PID_FILE:-$PID_FILE}
fi


#
# Determine if the application is already running
#
RUNNING="false"
if [ -e ${PID_FILE} ]; then
    ps `cat ${PID_FILE}` | grep "\-Dapp.name=${APP_NAME}" >/dev/null 2>&1
    if [ $? == "0" ]; then
        RUNNING="true"
    fi
fi


case ${FIRST_ARG} in
    start)
        if [ ${RUNNING} == "true" ]; then
            error_exit "${APP_NAME} is already running"
        fi

        info "Starting ${APP_NAME}..."

        CLASSPATH=:"$LIB_DIR/*"

        ${JAVA_CMD} ${DEFAULT_JVM_ARGUMENTS} ${JAVA_OPTS} \
            -classpath ${CLASSPATH} \
            $ENV_ARGUMENTS \
            net.ripe.rpki.validator.config.Main &

        PID=$!
        echo $PID > $PID_FILE
        info "writing logs under log directory"
        info "Web user interface is available on port ${HTTP_PORT_VALUE}"
        info "Routers can connect on port ${RTR_PORT_VALUE}"
        info "Writing PID ${PID} to ${PID_FILE}"
        ;;
    stop)
        info "Stopping ${APP_NAME}..."
        if [ ${RUNNING} == "true" ]; then
            kill `cat ${PID_FILE}` && rm ${PID_FILE}
        else
            info "${APP_NAME} in not running"
        fi
        ;;
    status)
        if [ ${RUNNING} == "true" ]; then
            info "${APP_NAME} is running"
            exit 0
        else
            info "${APP_NAME} is not running"
            exit 0
        fi
        ;;
    *)
        usage
        exit
        ;;
esac

exit $?

