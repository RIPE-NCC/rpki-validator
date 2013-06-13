#! /bin/bash
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

DEFAULT_JVM_ARGUMENTS="-Xms512m -Xmx512m"

EXECUTION_DIR=`dirname "$BASH_SOURCE"`
cd ${EXECUTION_DIR}

APP_NAME="rpki-validator"
CONF_DIR="config"
LIB_DIR="lib"
PID_FILE=${APP_NAME}.pid

function error_exit {
    echo -e "[ error ] $1"
    exit 1
}

function info {
    echo -e "[ info ] $1"
}

#
# Specify the location of the Java home directory. If set then $JAVA will
# be defined to $JAVA_HOME/bin/java
#
if [ -d "${JAVA_HOME}"  ] ; then
    JAVA_CMD="${JAVA_HOME}/bin/java"
else
    error_exit "JAVA_HOME is not set. Please export JAVA_HOME."
fi

#
# Determine if is already running
#
RUNNING="false"
if [ -e ${PID_FILE} ]; then
    ps `cat ${PID_FILE}` | grep "\-Dapp.name=${APP_NAME}" >/dev/null 2>&1
    if [ $? == "0" ]; then
        RUNNING="true"
    fi
fi

# Remove the first argument from the arguments list. Remaining arguments will be passed into the java application
FIRST_ARG="$1"
shift

case ${FIRST_ARG} in
    start)
        if [ ${RUNNING} == "true" ]; then
            error_exit "${APP_NAME} is already running"
        fi

        info "Starting ${APP_NAME}..."

        CLASSPATH=${CONF_DIR}:"$LIB_DIR/*"

        ${JAVA_CMD} ${DEFAULT_JVM_ARGUMENTS} ${JAVA_OPTS} \
            -classpath ${CLASSPATH} \
            -Dapp.name=${APP_NAME} \
            net.ripe.rpki.validator.config.Main "$@" &

        echo $! > ${PID_FILE}
        info "writing logs under log directory"
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
            error_exit "${APP_NAME} is not running"
        fi
        ;;
    *)
        info "Usage: $0 { start | stop | status }"
        ;;
esac

exit $?
