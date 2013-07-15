RIPE NCC RPKI Validator
=======================

Requirements
-------------

= A Unix-like operating system.

= Rsync(1), which must be available by just typing the 'rsync' command. The validator 
  uses the following rsync(1) options: --update, --times, --copy-links, --recursive, and
  --delete.
  
= SUN Java 6

  This software was developed and tested using SUN Java 1.6. This Java version should be 
  available without restrictions for all major platforms, though it may not be included 
  in your distribution by default.

  You can check which version of Java you have by running:

  $ java -version
  
  The JAVA_HOME environment variable must be set. There are many guides that explain how
  to do this, but these basic steps should get you started for a single user.
  
  1. Find the path to java by running:
  
  $ whereis java
  
  2. Add the location of your Java installation to your .bash_profile:
  
  export JAVA_HOME=/path/to/your/java
  
= At least 1GB of free memory

  For performance this tool keeps a lot of data in memory. This also helps multi-threading
  allowing the tool to work faster by doing tasks in parallel.
  
  
Usage
-----

= Untar the downloaded package
= Run the RPKI Validator script from the root folder to start, stop and check the status 
  of the application

       ./rpki-validator.sh start [OPTIONS]
   or  ./rpki-validator.sh stop
   or  ./rpki-validator.sh status

    OPTIONS

        -h HTTP-PORT       Start the web user interface on the specified port.
                           Default: 8080


        -r RTR-PORT        Allow RPKI-capable routers to connect on the specified port.
                           Default: 8282

        -n                 Stop the server from closing connections when it receives 
                           fatal errors.

        -s                 Stop the server from sending notify messages when it has
                           updates.

= Once the application has started, it will write the current PID to rpki-validator.pid 
  and start logging to the log directory. You can access the web user interface here:
  
  http://yourhost:http-port/    (e.g. http://localhost:8080/)


Configuring additional options
------------------------------

This RPKI Validator allows you to set the several variables that you may want to control 
in your environment. You can do this by using the JAVA_OPTS environment variable to 
override the default.

Examples:

= If you want to change the memory settings to use 128MB minimum and 256MB maximum
  
  export JAVA_OPTS="-Xms128m -Xmx256m"
  
  Be aware though that if you give this tool too little memory it will become slow first, 
  and then stop working properly.
  
= If you want to use a SOCKS proxy, like for example webcache.example.com:8888

  export JAVA_OPTS="-DsocksProxyHost=webcache.example.com -DsocksProxyPort=8888"

= If you want to use a HTTP proxy, like for example webcache.example.com:8888

  export JAVA_OPTS="-Dhttp.proxyHost=webcache.example.com -Dhttp.proxyPort=8888"


Configuring Trust Anchors
-------------------------

This validator will automatically pick up any file matching this pattern:  

  <root-folder>/conf/tal/*.tal

The Trust Anchor Locator (TAL) files for four Regional Internet Registries are included
with this distribution: AFRINIC, APNIC, Lacnic and RIPE NCC. 

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

= CSV format: http://yourhost:http-port/export.csv
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


Known Issues
------------

= The validator does not check for revocations or expiration times in between validation 
  runs

= The validator does not support incremental updates as defined here, yet:
  http://tools.ietf.org/html/rfc6810#section-6.2
  
  When the validator has any updates, it will respond with a cache-reset, as described 
  here: http://tools.ietf.org/html/rfc6810#section-6.3

= We have found that some routers require the -n and -s options. This is due to 
  interoperability issues that may exist on some platforms.

If you find any other problems, please contact us at <certification@ripe.net>.


Version History
---------------

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


Support
-------

Please contact <certification@ripe.net> with any questions relating to the
RIPE NCC RPKI Validator or the RIPE NCC Resource Certification (RPKI) service.


