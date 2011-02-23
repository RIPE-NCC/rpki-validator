Certification Validator Service
===============================

The Certification Validator Service offers a webbased user interface
for bottom-up validation of a single ROA object which has been published
in a public certificate repository.

Rsync(1) is used to download all required parent objects, including
Certificate Revocation Lists (CRLs).

Prerequisites
-------------

The Certification Validator Service has the following requirements:

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
"rpki-validator--serviceX.Y" (where X.Y is the version) will be created containing
the required components.


Configuring
===========
The service configuration is stored in rpki-vs.properties, to be found in the config
directory. An example configuration is supplied in config/rpki-vs.properties.example

By default the configuration directory is assumed be located in <current directory>/config.
This can be changed by editing rpki-vs.sh and replace <absolute path> with the path
of your config directory. Make sure to remove the leading # tag in front of:
#JAVA_OPTS="$JAVA_OPTS -Drpki.config=<absolute path>"

Configuration options
---------------------

Trust Anchor
------------
In order to validate anything you will have to specify a Trust Anchor Locator that
the validator can use. You can find a copy of the Trust Anchor Locator file in the
certification-validator-X.Y/config/root.tal filebut we advise you to obtain the up-to-date
version from another source to make sure it is genuine.

Specify the location of the tal file in rpki-vs.properties:
tal.location=root.tal

The location can either be an absolute path or a relative path, relative to the config
directory.

Port
----
The service by default runs on port 8082. You can change this port with the jetty.port
property:
jetty.port=8082

Theming
-------
If you want to change the default, plain, layout of the validator webpage you can do so
by supplying three different HTML files:
The header file contains any content you want to be added to the <head> section of the HTML
page, such as CSS and/or javascript. Define the absolute path with theme.head.section.
Default value is:
theme.head_section=../theme/default_html_head.html

The body header file contains all HTML you want to be placed above the validator service.
This HTML must include the <body> tag.
Default value is:
theme.body_header=../theme/default_body_header.html

The body footer file contains all HTML you want to be placed under the validator service.
This HTML must include the closing </body> tag but not the the closing </html> tag.
Default value is:
theme.body_footer=../theme/default_body_footer.html


Starting and stopping the service
=================================
The service is controlled using the rpki-vs.sh script. To start the service execute:
./rpki-vs.sh start

After starting the service will run in the background.

To use the validator, browse to http://localhost:8082/certification-validator/
When you changed the port in the property file, modify the port in the URL accordingly.

To stop the service, execute:
./rpki.vs stop

Optional: the validation tool uses rsync(1) to download repositories to the
local file system. We recommend running the validation tool as an
unprivileged user and/or in a secured environment (such as a chroot jail) to
prevent security breaches.


Using the service
=================
Browse to http://localhost:8082/certification-validator/
To verify a ROA, stored on your local filesystem, press the Choose File button and
select the ROA. Press validate! to validate the ROA.

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

