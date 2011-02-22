package net.ripe.certification.validator.cli;

import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.log4j.Logger;


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
    private List<File> trustAnchorFiles = new ArrayList<File>();
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
        trustAnchorFiles = new ArrayList<File>();
        for (String optionValue : commandLine.getOptionValues(TAL)) {
            trustAnchorFiles.add(new File(optionValue));
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

    public List<File> getTrustAnchorFiles() {
        return trustAnchorFiles;
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
