#!/usr/bin/python
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


#
# Script that downloads a certificate from a (rsync) URI,
# and creates a TAL file for it.
#
# Supports the additional non-RFC standard used by the RIPE NCC
# RPKI Validator that allows users to specify a different name,
# and additional rsync uris to fetch data from for the TA. The
# latter can help performance for so-called flat repositories.
# See the included TAL files for examples on this.
#

import subprocess
import argparse
import re

tmpFile = ".temp.file.cer"

## run cmd
def runProcess(exe):    
	lines = []
	p = subprocess.Popen(exe, stdout=subprocess.PIPE)
	while(True):
		retcode = p.poll() #returns None while subprocess is running
		if retcode is None:
			(so, se) = p.communicate()
			# print so
			# yield line
			if so != None:
				# lines.append(line)
				line = so
		else:
			break

		lines = so.split("\n")
	return lines
## end run cmd

## sidr tal
def write_sidr_tal(url, keyLines):
	lines = []
	lines.append(url)
	for l1 in keyLines:
		lines.append(l1)
	return lines
## end sidr tal

## ripe tal
def write_ripe_tal(url, keyLines, ca_name, prefetch_uri):
	lines = []
	if ca_name:
		lines.append("ca.name = " + ca_name)
	else:
		lines.append("ca.name = TAL imported from " + url)
	lines.append("certificate.location = " + url)
	lines.append("public.key.info = " + "".join(keyLines))
	if prefetch_uri:
		lines.append("prefetch.uris = " + prefetch_uri)
	return lines
## end ripe tal

## parse cmd line
parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url", help="rsync URL pointing to root certificate")
parser.add_argument("-o", "--output-format", help="output format, can be either sidr or ripe, default is sidr", default="sidr")
parser.add_argument("-n", "--ca-name", help="descriptive name, only useful for tals in ripe format", default=None)
parser.add_argument("-p", "--prefetch-uri", help="Additional rsync uri to do a recursive fetch on, only useful for tals in ripe format for flat repositories", default=None)
args = vars(parser.parse_args())

if args["url"] != None:
	# print "Fetching root cert from %s" % (args["url"])
	subprocess.call( ["/usr/bin/rsync", args["url"], tmpFile]) 
else:
	print "No URL specified. Use -h for help."
	exit(1)

## get key
keyLines = []
for line in runProcess( ["openssl", "x509", "-inform", "DER", "-in", tmpFile, "-pubkey", "-noout"] ):
	# print "-- %s" % (line)
	if re.match("-----BEGIN", line):
		pass
	elif re.match("-----END", line):
		pass
	else:
		keyLines.append(line.strip())
#
# print "Cert key is: %s" % "".join(keyLines)

## generate output
tal = []
if args["output_format"] == "sidr":
	tal = write_sidr_tal(args["url"], keyLines)
elif args["output_format"] == "ripe":
	tal = write_ripe_tal(args["url"], keyLines, args["ca_name"], args["prefetch_uri"])
else:
	print "Unknown output format %s. Please try again" % (args["output_format"])
	exit(1)
#
for l1 in tal:
	print l1
##
