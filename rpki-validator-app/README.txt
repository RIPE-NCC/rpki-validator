RIPE NCC RPKI Validator
=======================

This application allows operators to download and validate the global Resource 
Public Key Infrastructure (RPKI) data set for use in their BGP decision making 
process and router configuration. To learn more about RPKI and BGP Origin Validation, 
please visit:

  https://www.ripe.net/certification/


Source Code
-----------

The RIPE NCC RPKI Validator is an open source project on Github. Please contribute!

  https://github.com/RIPE-NCC/rpki-validator/


Support
-------

Please contact <certification@ripe.net> with any questions relating to the
RIPE NCC RPKI Validator or the RIPE NCC Resource Certification (RPKI) service.


Requirements
-------------

= A Unix-like operating system.

= Rsync(1), which must be available by just typing the 'rsync' command. The validator 
  uses the following rsync(1) options: --update, --times, --copy-links, --recursive, and
  --delete.
  
= Oracle JDK 7 or 8

  This software was developed and tested using Oracle JDK 8. This Java version should be
  available without restrictions for all major platforms, though it may not be included 
  in your distribution by default.
  
  Oracle JDK 7, as well as OpenJDK 7 and 8 should also work. Please let us know if you
  should run into any issues using this.

  You can check which version of Java you have by running:

  $ java -version
  
  The start script will try to find java on the path, using 'which java'.

  If this is not what you want, e.g. because you have multiple java versions on your
  system, or you just don't want to have it on the normal path, then you can specify
  a java installation explicitly by setting the JAVA_HOME directory.

  Beware that JAVA_HOME should not point to the java executable itself, but the 
  installation directory of your java distribution. The executable is expected here:
      
  $JAVA_HOME/bin/java

= At least 1.5 GB of free memory

  For performance reasons this tool keeps a lot of data in memory and runs many tasks in
  parallel.  The actual amount of memory used by the validator depends on the number of
  enabled trust anchors, number of CPU cores, and on configured validation interval.  In
  general, more CPU cores require more memory for validator, and vice versa.  
  
  If the validator keeps crashing with "Out of memory" error, try to increase the amount
  of memory allocated to it ("jvm.memory.maximum" parameter in the config file). If the
  validator gets killed by the OOM killer, try to lower the amount of memory allocated to
  it, or decrease the number of trust anchors (see below), or increase the validation
  interval ("validation.interval" option in the config file).

  
Manual Installation
-------------------

= Decompress the downloaded package
= Run the RPKI Validator script from the root folder to start, run (in foreground), stop
  and check the status of the application

       ./rpki-validator.sh start  [-c /path/to/my-configuration.conf]
   or  ./rpki-validator.sh run    [-c /path/to/my-configuration.conf]
   or  ./rpki-validator.sh stop   [-c /path/to/my-configuration.conf]
   or  ./rpki-validator.sh status [-c /path/to/my-configuration.conf]
   
  Note: you only have to use the -c flag if you change the name and/or location of the
  configuration file, as explained below.   

= Once the application has started, it will write the current PID to rpki-validator.pid 
  and start logging to the log directory. You can access the web user interface here:
  
  http://yourhost:http-port/    (e.g. http://localhost:8080/)

Using Puppet
------------

ARIN created a puppet module for this application that may be useful to you.
It can be found here: https://github.com/arinlabs/puppet-rpki_validator

Configuration file
------------------

You can override the default settings of the RPKI Validator by editing the configuration
file at the following location:

  <root-folder>/conf/rpki-validator.conf

If you want to be sure that future upgrades do not overwrite your local changes, you may 
want to make a local copy of the configuration file and refer to it explicitly using
the -c option. For usage, please refer to the configuration file comments.  
  

Notes on kiosk mode
-------------------

In kiosk mode the application will be accessible read-only to anyone, but any action or
update will require authentication with a username and password. This a basic, 
experimental feature. Kiosk mode is merely intended to prevent unauthorised people from 
making (accidental) changes. The password you configure is stored in plain text. When a 
user enters the credentials, they are sent unencrypted. Lastly, the credentials remain 
valid for the entire browser session, so you need to quit your browser to log out.


Configuring additional Java Virtual Machine (JVM) options
---------------------------------------------------------

The configuration file allows you to change the most import memory options and/or specify
a SOCKS or HTTP proxy to be used by the Java Virtual Machine (JVM) that will run this
application.

Additionally, you can use the JAVA_OPTS environment variable to pass in more JVM options,
not supported by the configuration file and start script. Use this very carefully though,
we can give no guarantees about the result.


Configuring Trust Anchors
-------------------------

This validator will automatically pick up any file matching this pattern:  

  <root-folder>/conf/tal/*.tal

The Trust Anchor Locator (TAL) files for four Regional Internet Registries are included
with this distribution: AFRINIC, APNIC, LACNIC and RIPE NCC. 

To access ARIN's TAL, you will have to agree to ARIN's Relying Party Agreement. After 
that, the TAL will be emailed to the recipient. Please visit this ARIN web page for
more information: http://www.arin.net/public/rpki/tal/index.xhtml

After obtaining ARIN's TAL, please copy it to the following location to use it:
 
  <root-folder>/conf/tal/

If you compare the format of the included files to the Trust Anchor format defined here:

  http://tools.ietf.org/html/rfc6490

you will notice that the format used here is slightly different. We are using key-value 
pairs to allow specifying some additional information. Make sure that you enter a value 
for ca.name. The certificate.location and public.key.info correspond to the location and 
subjectPublicKeyInfo fields in the standard. The prefecth.uris field is optional. You may 
specify a comma separated list of rsync URIs for directories here, that will be 
'pre-fetched'. This helps performance for repositories that have a flat structure 
(children not published under parents).

Example:  

  ca.name = ARIN RPKI Root
  certificate.location = rsync://rpki.arin.net/repository/arin-rpki-ta.cer
  public.key.info = MIIBI..... etc 1 LINE
  prefetch.uris = rsync://rpki.arin.net/repository/

 
API
---

This validator has a RESTful API that allows you to get the full validated ROA set.

Usage:

= CSV format:  http://yourhost:http-port/export.csv
= JSON format: http://yourhost:http-port/export.json

You can also query this RPKI Validator for validity information about a BGP announcement. 
You will get a response in JSON format containing the following data:

= The RPKI validity state, as described in RFC 6811
= The validated ROA prefixes that caused the state
= In case of an 'Invalid' state, the reason:
    = The prefix is originated from an unauthorised AS
    = The prefix is more specific than allowed in the Maximum Length of the ROA

Usage:

= http://yourhost:http-port/api/v1/validity/:ASN/:prefix

e.g.

= IPv4: http://yourhost:http-port/api/v1/validity/AS12654/93.175.146.0/24
= IPv6: http://yourhost:http-port/api/v1/validity/AS12654/2001:7fb:ff03::/48

Full documentation can be found here:

  https://www.ripe.net/developers/rpki-validator-api
  
RPSL route object output (beta)
-------------------------------

With version 2.18 we have added beta support for exporting the full validated ROA set
in RPSL route object format: http://yourhost:http-port/export.rpsl

This beta feature is intended to make it easier to integrate using ROA data in an existing
RPSL based tool chain. When using this feature please keep the following in mind:

 1) Mandatory attributes missing from ROAs
 
    ROAs do not have data for all mandatory attributes in (RIPE) route objects.
    Generated 'pseudo' route objects currently look like this:
    
      route: 10.0.0.0/24
      origin: AS65001
      descr: exported from ripe ncc validator
      mnt-by: NA
      created: 2015-04-28T09:57:21Z
      last-modified: 2015-04-28T09:57:21Z
      source: ROA-TRUST-ANCHOR-NAME
    
    The 'route:' and 'origin:' values are taken from the ROA, and the 'source:' reflects
    the Trust Anchor where the ROA was found.
    
    The 'mnt-by:' value is meant to indicate 'not applicable'. And the values for 'created:'
    and 'last-modified:' use the time of the export.

 2) ROAs can have a 'maximum length' attribute
 
    The maximum length parameter in ROAs can be used as a shorthand in case a prefix has
    de-aggregated announcements from a single ASN. Rather than having to create ROAs for
    each prefix the ROA can specify a maximum length. For example:
    
      prefix: 10.0.0.0/22
      max length: 24
      ASN: 65001
      
      Implies that 10.0.0.0/22 can be announced from AS65001, but also 10.0.0.0/23 and
      10.0.2.0/23, as well as 10.0.0.0/24, 10.0.1.0/24, 10.0.2.0/24 and 10.0.3.0/24.
      
    When converting ROAs to route objects we currently generate objects for each more
    specific announcement. However, since this could result in an enormous amount of
    more specifics, we have to put limits on this. Especially in IPv6 space this could
    result in millions of objects. Therefore we currently only create objects for the
    prefix itself and more specifics up to 8 bits.

 3) Difference in authorisation model
 
    In contrast to ROUTE objects ROAs are only authorised by the holder of the prefix,
    not the holder of the ASN. The reasoning behind this is that it's the holder of the
    prefix who gets to authorise an ASN to announce the space, but the authorisation by
    the ASN is implicit by them actually announcing this space, or not.
    
    If this distinction is important to your decision process then you may not want to
    use this feature.

Please let us know what you think.
  


Deep Links
----------

You can specify an AS Number or prefix in the URL of the ROA and BGP Preview pages to get
direct, bookmark-able access to information. For example:

= http://yourhost:http-port/roas?q=93.175.146.0/24
= http://yourhost:http-port/bgp-preview?q=AS12654


Monitoring
----------
You can monitor the health of the application itself using this url:

   http://yourhost:http-port/health

This url will return data in JSON format with information on each test.

Monitoring tools should check the http status of the response.
    200 -> Everything is OK
    500 -> One or more checks failed

For the moment we only check that the rsync binary can be found and executed, but we may
add more checks in the future.

In addition, each Trust Anchor has a dedicated monitoring page showing statistics, 
validation warnings and errors. Clicking one of the "Processed Items" links on the Trust 
Anchors page will take you to an overview with all checks and warnings for that trust 
anchor.

You can set up your monitoring tool to check for the contents of this page. Using 
regular expressions, check for the label in the span tag with the id "healthcheck-result":

   <span id="healthcheck-result">.*OK.*</span>
   <span id="healthcheck-result">.*ALERT.*</span>


RRDP Support
------------

This version of the validator supports the RPKI Repository Delta Protocol (RRDP), but by
default validator will prefer rsync protocol.  You could change that by turning the
"prefer.rrdp" option in the configuration file to "true".  Note that currently RRDP is in
the draft state, and only the RIPE NCC repository publishes data using RRDP.  RRDP is
described in https://tools.ietf.org/html/draft-ietf-sidr-delta-protocol.

Known Issues
------------

= The validator does not check for revocations or expiration times in between validation 
  runs

= In its RTR implementation, the validator does not support incremental updates as defined
  here, yet: http://tools.ietf.org/html/rfc6810#section-6.2
  
  When the validator has any updates, it will respond with a cache-reset, as described 
  here: http://tools.ietf.org/html/rfc6810#section-6.3


Version History
---------------

2.23 - 28 September 2016
= Performance and stability improvements, bugfixes
= Add Trust Anchor name as additional column in export files
= Fallback to plain HTTP if HTTPS connection fails
= Improve error reporting
= Parse and validate Ghostbusters Records
= Support multiple TA certificate URLs in TAL
= Support HTTP URLs in TAL

2.22 - 25 May 2016
= Multiple improvements in RRDP support
= Multiple improvements in database and memory handling
= Replaced log4j by logback; log configuration is now in logback.xml.
= Added support multiple TALs for the same TA. This changed monitoring URLs for TALs.
  If you were using TA monitoring feature, you have to update URLs for monitored trust
  anchors.

2.21 - 2 November 2015
= Fixed a bug where a broken CRL made the validation process crash for the given TA
= Added support for the RPKI Retrieval Delta Protocol, which uses HTTP instead of rsync 
  as the transport if the RPKI server supports it. There is a boolean option "prefer.rrdp"
  in the configuration file to enable it. 
= The startup script now warns if the Java version running on the host is too old
= Added log rotation for all log files
= A brand new RIPE NCC logo

2.20 - 5 June 2015
= Improvements to the caching system; previous versions could use a lot of disk space
= Multithreading improvements; application is up to 50% faster

2.19 - 12 May 2015
= General improvements

2.18 - 30 April 2015
= Updated validation algorithm in preparation of alternative RPKI data retrieval protocol
= Added initial support for new RPKI data retrieval protocol. Documented here:
  https://datatracker.ietf.org/doc/draft-ietf-sidr-delta-protocol/
= Added beta support for exporting ROAs in RPSL route object format. Feedback welcome!
= Improved some error handling and reporting
    - rejecting expired TA certificate
    - report on retrieval errors separate from validation errors

2.17 - 3 July 2014
= Added a configuration file option to manually set the update interval of the 
  Trust Anchors
= If no Trust Anchors are enabled, the application will report "all have been 
  validated" to connected routers, instead of "no data available"
= Added an option to enable the "loose" validation algorithm in the config file
  (draft-huston-rpki-validation-01)
= New RIPE NCC logo awesomeness
  
2.16 - 21 March 2014
= Fixed memory leak

2.15 - 3 January 2014
= More refinements to the trust anchor monitoring functionality to ensure alerts are 
  triggered accurately and lower the chance of a false positive
= Added an alert if more than 10% of objects have a validation error
= Carrying over the alert for an unexplained drop in object count over subsequent 
  validation runs until the object count is restored and/or no more errors are observed
= No longer warns when manifest EE certificate validity times do not match the manifest 
  "this update" and "next update" times
= Warn about stale manifests and CRLs for up to X days, as configured by the user 
  (default = 0), reject after
= Reject manifests with expired EE certificates
= A more detailed error message is displayed when a ROA is rejected because it refers to
  resources the holder no longer has on their certificate

2.14 - 9 December 2013
= Fixed an issue where the wrong CRL could be used when a remote repository is being 
  updated during validation
= Improved monitoring code to allow for easier tracking of alerts
= Several clarifications in the text

2.13 - 22 November 2013
= The application now uses a single configuration file to override all default settings.
= The application will now try to find your Java installation if you have not specified
  your JAVA_HOME.
= Added basic application and Trust Anchor monitoring
= Bug and conformance fixes, as well as other magical improvements

2.12 - 25 October 2013
= Changed default memory settings from 512MB to 1024MB after out of memory problems with
  the current size of RPKI repositories
= Added experimental support to run validator in "Kiosk" mode

2.11.1 - 12 July 2013
= Bug fix release, validator was rejecting *all* subsequent manifests as soon as one
  object was rejected for a Trust Anchor. 
= All users are recommended to upgrade to this release.

2.11 - 26 June 2013
= Application packaging is now in tar format
= Included a script to start, stop and check the status of the application
= It is now possible specify a proxy server for outgoing HTTP connections, which the
  application uses to retrieve the RIS Route Collector dump files.
= Added a RESTful API that allows users to request the RPKI validity state of a BGP 
  announcement.
= In the BGP Preview tab, Invalid announcements now display the reason for the state.

2.10 - 5 June 2013
= Validated ROA cache can now be exported in JSON format
= Router sessions logging format has changed according to RFC 6810

2.9 - 7 May 2013
= Fix an issue that breaks the RTR interface

2.8.1 - 12 April 2013
= Fix performance issue introduced in 2.8

2.8 - 5 April 2013
= Added a warning if objects with unknown extensions (such as *.gbr) are found.

2.7 - 28 November 2012
= Made validator and projects this depends on available on GitHub and Maven Central
= Updated pre-configured Trust Anchor Files for APNIC and LACNIC
= Made Trust Anchor handling more robust
= Disabled warnings about failure to send performance metrics

2.6 - Internal release

2.5 - 4 September 2012
= Fixed a thread leak bug
= Cleaned up experimental and pilot TAL files. Release now only includes TALs of these 
  four RIRs: AFRINIC, LACNIC, APNIC and RIPE NCC
= Added information to the README.txt how to obtain and use ARIN's TAL

2.4 - 2 July 2012
= Cache repository objects for re-use in case of problems retrieving objects (expired 
  objects are still rejected / warned about as per configuration)

2.3 - 9 May 2012
= Added performance metrics to the RPKI Validator
= Small UI changes on White List page

2.1 - 24 April 2012
= Fixed a bug where in some cases fetching RIS Route Collector data would be slow or 
  failed
= Trust Anchors can now be easily enabled or disabled with a check mark
= Added a dedicated User Preferences page

2.0.4 - 10 April 2012
= Added a "Process Items" section to Trust Anchor page, displaying number of accepted 
  items, warnings and errors
= Added a dedicated Validation results page for inspecting errors and warnings
= Fetching route collector data for the BGP Preview is more robust and indicates the time 
  of the last retrieval

2.0.3 - 16 February 2012
= Fixed a bug that caused certain types of IPv6 notation to break the BGP Preview
= The validator can optionally check for updates of the application

2.0.1 - 3 January 2012
= Performance and stability improvements

2.0 - 13 December 2011
= Initial release of the next generation RPKI Validator toolset:
= It runs as a service and has an intuitive web-based interface
= It allows manual controls and overrides through filters and white lists
= It allows integration in existing (RPSL based) workflows
= It is capable of communicating with RPKI-capable routers
