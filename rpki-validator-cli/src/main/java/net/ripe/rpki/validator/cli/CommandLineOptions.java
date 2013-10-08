/**
 * The BSD License
 *
 * Copyright (c) 2010-2012 RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of the RIPE NCC nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.rpki.validator.cli;

import net.ripe.rpki.validator.util.TrustAnchorLocator;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.log4j.Logger;

import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;


public class CommandLineOptions {

    private static final Logger LOG = Logger.getLogger(CommandLineOptions.class);

    private static final String HELP = "help";
    private static final String VERSION = "version";
    private static final String PRINT = "print";
    private static final String TAL = "tal";
    private static final String OUTPUT_DIR = "output-dir";
    private static final String FILE = "file";
    private static final String ROA_EXPORT = "roa-export";
    private static final String PREFETCH = "prefetch";
    private static final String VERBOSE = "verbose";

    private Options options = new Options();

    private File inputFile;
    private File outputDir;
    private List<TrustAnchorLocator> trustAnchorLocators = new ArrayList<TrustAnchorLocator>();
    private List<URI> prefetchUris = new ArrayList<URI>();
    private File roaExportFile;

    private boolean printHelpMode;
    private boolean printVersionMode;
    private boolean printObjectMode;
    private boolean validationMode;

    private boolean roaExportEnabled;
    private boolean verboseEnabled;
    private boolean topDownValidationEnabled;


    public CommandLineOptions() {
        addCommandGroup();
        addOptions();
    }

    private void addCommandGroup() {
        OptionGroup group = new OptionGroup();

        Option helpOption = new Option("h", HELP, false, "Show usage information");
        group.addOption(helpOption);

        Option versionOption = new Option(null, VERSION, false, "Show version information");
        group.addOption(versionOption);

        Option printOption = new Option("p", PRINT, false, "Show the certificate repository object in a readable format");
        group.addOption(printOption);

        Option talOption = new Option("t", TAL, true, "Trust Anchor Locator (TAL). Can be specified more than once.");
        talOption.setArgs(Option.UNLIMITED_VALUES);
        group.addOption(talOption);

        group.setRequired(true);
        options.addOptionGroup(group);
    }

    private void addOptions() {
        options.addOption("f", FILE, true, "Certificate repository object file");
        options.addOption(null, PREFETCH, true, "Prefetch specified rsync URI before top-down validation. Can be specified more than once.");
        options.getOption(PREFETCH).setArgs(Option.UNLIMITED_VALUES);
        options.addOption("o", OUTPUT_DIR, true, "Output directory for the results of top-down validation and the trust anchor file");
        options.addOption("r", ROA_EXPORT, true, "Export routing authorisation found in validated ROAs");
        options.addOption("v", VERBOSE, false, "Show all validation steps");
    }

    public void parse(String... args) throws ParseException {
        CommandLineParser parser = new GnuParser();
        CommandLine commandLine = parser.parse(options, args);

        if (commandLine.hasOption(HELP) || commandLine.getOptions().length == 0) {
            printHelpMode = true;
        } else if (commandLine.hasOption(VERSION)) {
            printVersionMode = true;
        } else if (commandLine.hasOption(PRINT)) {
            printObjectMode = true;
            requireInputFileOption(commandLine);
            parseInputFile(commandLine);
        } else if (commandLine.hasOption(TAL)) {
            validationMode = true;
            parseTrustAnchorFile(commandLine);

            requireOutputDir(commandLine);
            parseOutputDir(commandLine);

            if (commandLine.hasOption(FILE)) {
                topDownValidationEnabled = false;
                parseInputFile(commandLine);
            } else {
                topDownValidationEnabled = true;
                parseRoaExportFile(commandLine);
                parsePrefetchURIs(commandLine);
            }

            if (commandLine.hasOption(VERBOSE)) {
                verboseEnabled = true;
            }
        }
    }

    private void requireInputFileOption(CommandLine commandLine) throws ParseException {
        if (!commandLine.hasOption(FILE)) {
            throw new ParseException("Required option 'file' missing");
        }
    }

    private void parseInputFile(CommandLine commandLine) {
        inputFile = new File(commandLine.getOptionValue(FILE));
    }

    private void requireOutputDir(CommandLine commandLine) throws ParseException {
        if (!commandLine.hasOption(OUTPUT_DIR)) {
            throw new ParseException("Required option 'output-dir' missing");
        }
    }

    private void parseOutputDir(CommandLine commandLine) {
        outputDir = new File(commandLine.getOptionValue(OUTPUT_DIR));
    }

    private void parseTrustAnchorFile(CommandLine commandLine) {
        trustAnchorLocators = new ArrayList<TrustAnchorLocator>();
        for (String optionValue : commandLine.getOptionValues(TAL)) {
            TrustAnchorLocator tal = TrustAnchorLocator.fromFile(new File(optionValue));
            trustAnchorLocators.add(tal);
            prefetchUris.addAll(tal.getPrefetchUris());
        }
    }

    private void parseRoaExportFile(CommandLine commandLine) {
        if (commandLine.hasOption(ROA_EXPORT)) {
            roaExportEnabled = true;
            roaExportFile = new File(commandLine.getOptionValue(ROA_EXPORT));
        }
    }

    private void parsePrefetchURIs(CommandLine commandLine) {
        if (commandLine.hasOption(PREFETCH)) {
            for (String prefetchUri : commandLine.getOptionValues(PREFETCH)) {
                try {
                    if (!prefetchUri.endsWith("/")) {
                        prefetchUri += "/";
                    }
                    URI uri = new URI(prefetchUri);
                    prefetchUris.add(uri);
                } catch (URISyntaxException e) {
                    LOG.warn("unrecognized prefetch URI '" + prefetchUri + "' ignored");
                }
            }
        }
    }

    public boolean isPrintHelpMode() {
        return printHelpMode;
    }

    public boolean isPrintVersionMode() {
        return printVersionMode;
    }

    public boolean isPrintObjectMode() {
        return printObjectMode;
    }

    public boolean isValidationMode() {
        return validationMode;
    }

    public File getInputFile() {
        return inputFile;
    }

    public List<TrustAnchorLocator> getTrustAnchorFiles() {
        return trustAnchorLocators;
    }

    public boolean isVerboseEnabled() {
        return verboseEnabled;
    }

    public boolean isTopDownValidationEnabled() {
        return topDownValidationEnabled;
    }

    public List<URI> getPrefetchUris() {
        return prefetchUris;
    }

    public File getOutputDir() {
        return outputDir;
    }

    public boolean isRoaExportEnabled() {
        return roaExportEnabled;
    }

    public File getRoaExportFile() {
        return roaExportFile;
    }


    public void printHelp() {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("For detailed usage scenarios see README file. Options:", options);
    }
}
