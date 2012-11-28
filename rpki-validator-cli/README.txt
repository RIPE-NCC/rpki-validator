Certification Validator Tool
============================

The Certification Validator Tool allows you to validate objects that have been
published in a public certificate repository.

Two types of validation are supported:

1. Top-down validation takes a (set of) Trust Anchor Locator(s), uses this to
   retrieve the trust anchors and validates all objects issued by
   these trust anchors, recursively. During the validation process, all objects
   are downloaded from the public repository servers using rsync(1).

   When all trust anchors are processed this way the validator will print a
   tab separated summary of all validated objects:

   |date       | The date in YYYY/MM/DD format                  |
   |certs      | The number of validated certificates           |
   |roas       | The number of validated roas                   |
   |roa-asn    | The number of distinct ASN found in ROAs       |
   |roa-v4     | The number of distinct IPv4 ROA prefixes found |
   |roa-v4u    | The coverage in /24 units of ROA IPv4 space    | 
   |roa-v6     | The number of distinct IPv6 ROA prefixes found |
   |roa-v6u    | The coverage in /48 units of ROA IPv6 space    |

2. Bottom-up validation validates a single object that is already present on
   the local file system. Rsync(1) is used to download all required parent
   objects, including Certificate Revocation Lists (CRLs). Only resource certificates,
   ROAs, and manifests can be validated this way (not CRLs).

Two other operations are also supported:

1. As a part of top-down validation all route origin authorisation
   information found in all validated ROAs can be exported to a CSV file.

2. A single object can be printed in text format.


Prerequisites
-------------

The Certification Validator Tool has the following requirements:

- A Unix-like operating system. It has not been tested on Windows operating systems.

- Rsync(1), which must be available by just typing the 'rsync' command.
  The validator uses the following rsync(1) options: --update, --times, 
  --copy-links, --recursive, and --delete.

- SUN Java 6
  This software was developed and tested using SUN Java 1.6. This Java version
  should be available without restrictions for all major platforms, though it may
  not be included in your distribution by default.

  You can check which version of Java you have by running:

  $ java -version

  If you need to use an alternative location for your Java version, you can
  use the script provided to specify another location by setting the 
  'JAVA' environment variable to point directly to your Java executable, or
  by setting 'JAVA_HOME' environment variable to point to the base of your
  Java installation.


Installation
------------

Unpack the downloaded archive. A new directory named 
"rpki-validator-cli-X.Y.Z" (where X.Y.Z is the version) will be automatically
created containing the required components. The validator can be run using
the command "rpki-validator-cli-X.Y.Z/bin/certification-validator". The
script expects to be installed in the original unpack directory. Installing
in /usr/local/bin (or some other directory) is not yet supported (though you can
modify the script yourself to allow this). 

Optional: the validation tool uses rsync(1) to download repositories to the
local file system. We recommend running the validation tool as an 
unprivileged user and/or in a secured environment (such as a chroot jail) to
prevent security breaches.


Obtaining Trust Anchors
-----------------------
In order to validate anything you will have to specify a Trust Anchor Locator that
the validator can use. You can find a copy of the Trust Anchor Locator file in the
rpki-validator-cli-X.Y.Z/tal directory but we advise you to obtain the up-to-date
version from another source to make sure it is genuine. 

You can use the Trust Anchor Locator file by specifying the '-t' option.


Use Case Example
----------------

Top-down validation using one trust anchor.
===================

Note: use '-t' for defining the Trust Anchor Locator.

All downloaded and validated certificates will be placed in the directory specified by
the --output-dir parameter.


Top-down validation using the resource trust anchor:
$ certification-validator -t ripe-ncc.tal --output-dir validator

Exporting all validated ROA prefixes to a file:

$ certification-validator -t ripe-ncc.tal \
        --output-dir validator --roa-export roa-prefixes.csv


Bottom-up validation of a local ROA, checking against a given trust anchor:

$ certification-validator -t ripe-ncc.tal -f file.roa --output-dir validator


Printing the contents of a local object, such as a CRL (no validation):
$ certification-validator --print -f file.crl


Display all validation checks performed (use -v for verbose messages):
$ certification-validator -t ripe-ncc.tal -f file.roa --output-dir validator -v





Known Bugs and Limitations
--------------------------

1. Validation fails if the next update time for a CRL or manifest is in the 
   past. Maybe this should be a warning instead (or be controlled by a
   command line switch).

2. Rsync timeouts are not implemented.

3. Validating a self-signed certificate (resource trust anchor) fails. The
   output may be improved. Also we are not sure whether the tool should just
   trust whatever the user specifies as trust anchor, or that if it should do
   additional checks to make sure that the trust anchor really follows all
   standards.



Support
-------

Please contact certification@ripe.net with any questions relating to the
Certification Validator Tool or the RIPE NCC resource certification service.

