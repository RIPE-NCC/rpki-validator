#!/bin/sh
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


set -e

CHECKOUT_DIR=${CHECKOUT_DIR:-../..}

function fail() {
    echo "$@"
    exit 1
}

function check_dir() {
    [ -d "$1" ] || fail "directory $1 does not exist"
}

VERSION=`xsltproc pom.xslt pom.xml`

# The projects to package source code for.
PROJECTS="
$CHECKOUT_DIR/rpki-validator
$CHECKOUT_DIR/rpki-commons
"

for p in $PROJECTS; do
    check_dir "$p"
done

cd $CHECKOUT_DIR/rpki-validator/rpki-validator-cli

[ -d target/sources ] && rm -r target/sources
[ -d target/rpki-validator-$VERSION-src ] && rm -r target/rpki-validator-$VERSION-src

mkdir -p target/sources

for p in $PROJECTS; do
    name=`basename $p`
    mkdir "target/sources/$name"
    (cd $p && tar -c -f - --exclude ".*" --exclude target --exclude \*.iml --exclude create-source-zip.sh --exclude pom.xslt --exclude src/test --exclude rpki-vs.log --exclude validated-tas *) | (cd "target/sources/$name" && tar -x -f -)
done

LICENSE_FILE="$CHECKOUT_DIR/rpki-validator/LICENSE.txt"
[ -r "$LICENSE_FILE" ] || fail "license file does not exist"
find target/sources -type f -name \*.java | while read FILENAME; do mv $FILENAME $FILENAME.bak; cat "$LICENSE_FILE" > $FILENAME; cat $FILENAME.bak >> $FILENAME; rm $FILENAME.bak; done

mv target/sources target/rpki-validator-$VERSION-src

(cd target && zip -r -9 rpki-validator-$VERSION-src.zip rpki-validator-$VERSION-src)

echo "target/rpki-validator-$VERSION-src.zip generated."
