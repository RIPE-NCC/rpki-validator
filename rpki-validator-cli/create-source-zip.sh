#!/bin/sh

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
$CHECKOUT_DIR/rpki-validator/rpki-validator-cli
$CHECKOUT_DIR/rpki-commons/rpki-objects
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
	(cd $p && tar -c -f - --exclude ".*" --exclude target --exclude \*.iml --exclude create-source-zip.sh --exclude pom.xslt --exclude src/test *) | (cd "target/sources/$name" && tar -x -f -)
done

LICENSE_FILE="src/main/release/LICENSE.txt"
[ -r "$LICENSE_FILE" ] || fail "license file does not exist"
find target/sources -type f -name \*.java | while read FILENAME; do mv $FILENAME $FILENAME.bak; cat "$LICENSE_FILE" > $FILENAME; cat $FILENAME.bak >> $FILENAME; rm $FILENAME.bak; done

mv target/sources target/rpki-validator-$VERSION-src

(cd target && zip -r -9 rpki-validator-$VERSION-src.zip rpki-validator-$VERSION-src)

echo "target/rpki-validator-$VERSION-src.zip generated."
