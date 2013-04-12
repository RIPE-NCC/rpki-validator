RPKI Validator Tool
===================

Requirements
-------------

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
  
- At least 1GB of free memory

  For performance this tool keeps a lot of data in memory. This also helps multi-threading,
  allowing the tool to work faster by doing tasks in parallel.
  
  If you want to change the memory settings, you can manually edit the line containing:
  
  EXTRA_JVM_ARGUMENTS="-Xms128m -Xmx256m"
  
  In the bin/rpki-validator or bin/rpki-validator.bat files.
  
  Be aware though that if you give this tool too little memory it will become slow first, and
  then stop working properly.
  

Usage
-----

= Unzip the downloaded package
= Run the RPKI Validator from the root folder

    ./bin/rpki-validator [OPTIONS]

    OPTIONS

        -h HTTP-PORT            The http port the for the User Interface.
        --http-port HTTP-PORT   Default: 8080


        -r RTR-PORT             The port the rtr-rpki tcp server will listen on.
        --rtr-port RTR-PORT     Default: 8282

        -n                      Stop the server from closing connections when it
        --no-close-on-error     receives fatal errors.

        -s                      Stop the server from sending notify messages when it has
        --silent                updates.


= The validator will start up and start logging to standard output. You can stop it
  by sending it CTRL-C. There is currently no example script provided to run this
  as a background service logging to a file.

= Once started you can access the User Interface here:
  http://yourhost:http-port/    (eg. http://localhost:8080/)


Configuration of Trust Anchors
------------------------------

This validator will automatically pick up any file matching this pattern:  
  <root-folder>/conf/tal/*.tal

Four files are included with this distribution with the Trust Anchor details
as they are known to us for AFRINIC, APNIC, LACNIC and RIPE NCC. 

To access ARIN's TAL, the relying party will have to agree to ARIN's Relying
Party Agreement. After that, the TAL will be emailed to the recipient. Please
visit this ARIN web page for more information (starting late September 2012):
http://www.arin.net/public/rpki/tal/index.xhtml

After obtaining ARIN's TAL, please copy it to the following location to use it:
  <root-folder>/conf/tal/

If you compare the format of the included files to the Trust Anchor format defined here:
http://tools.ietf.org/html/draft-ietf-sidr-ta-07

You will notice that the format used here is slightly different. We are using key-value pairs
to allow specifying some additional information. Make sure that you enter a value for ca.name.
The certificate.location and public.key.info correspond to the location and subjectPublicKeyInfo
fields in the standard. The prefecth.uris field is optional. You may specify a comma separated
list of rsync URIs for directories here, that will be 'pre-fetched'. This helps performance
for repositories that have a flat structure (children not published under parents).

Example:  

  ca.name = AfriNIC RPKI Root
  certificate.location = rsync://rpki.afrinic.net/repository/AfriNIC.cer
  public.key.info = MIIBI..... etc 1 LINE
  prefetch.uris = rsync://rpki.afrinic.net/member_repository/
 


Known Issues
------------

= If you see this:

  Exception in thread "main" java.lang.IllegalArgumentException: Parameter 'directory' is not a directory
    at org.apache.commons.io.FileUtils.listFiles(FileUtils.java:293)
    at org.apache.commons.io.FileUtils.listFiles(FileUtils.java:378)
    at net.ripe.rpki.validator.config.Main$.loadTrustAnchors(Main.scala:108)
    at net.ripe.rpki.validator.config.Main$.run(Main.scala:89)
    at net.ripe.rpki.validator.config.Main$.main(Main.scala:84)
    at net.ripe.rpki.validator.config.Main.main(Main.scala)

  Then you have tried to run the validator from another location than its root folder. Make sure you do:
  ./bin/rpki-validator
  
= The validator does not check for revocations or expiration times in between validation runs

= The validator does not support incremental updates as defined here, yet:
  http://tools.ietf.org/html/draft-ietf-sidr-rpki-rtr-16#section-6.2
  
  When the validator has any updates, it will respond with a cache-reset, as described here:
  http://tools.ietf.org/html/draft-ietf-sidr-rpki-rtr-16#section-6.3

= We have found that some routers require the -n and -s options. This is due to interoperability
  issues that are being worked on.

If you find any other problems, please contact us at <certification@ripe.net>.


Version History
---------------

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
= Cleaned up experimental and pilot TAL files. Release now only includes TALs of these four RIRs: 
  AFRINIC, LACNIC, APNIC and RIPE NCC
= Added information to the README.txt how to obtain and use ARIN's TAL

2.4 - 2 July 2012
= Cache repository objects for re-use in case of problems retrieving objects (expired objects are 
  still rejected / warned about as per configuration)

2.3 - 9 May 2012
= Added performance metrics to the RPKI Validator
= Small UI changes on White List page

2.1 - 24 April 2012
= Fixed a bug where in some cases fetching RIS Route Collector data would be slow or failed
= Trust Anchors can now be easily enabled or disabled with a check mark
= Added a dedicated User Preferences page

2.0.4 - 10 April 2012
= Added a "Process Items" section to Trust Anchor page, displaying number of accepted items, warnings and errors
= Added a dedicated Validation results page for inspecting errors and warnings
= Fetching route collector data for the BGP Preview is more robust and indicates the time of the last retrieval

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