package net.ripe.certification.validator;

import net.ripe.certification.validator.cli.CommandLineOptions;
import net.ripe.certification.validator.commands.BottomUpValidationCommand;
import net.ripe.certification.validator.commands.PrintCertificateRepositoryObjectCommand;
import net.ripe.certification.validator.commands.PrintVersionCommand;
import net.ripe.certification.validator.commands.TopDownValidationCommand;

import org.apache.commons.cli.ParseException;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;


public final class Main {

    private static final Logger LOG = Logger.getLogger(Main.class);

    private CommandLineOptions options;


    private Main() {
    }

    public static void main(String[] args) {
        try {
            new Main().run(args);
            System.exit(0);
        } catch (Exception e) {
            LOG.error(e.getMessage());
            System.exit(1);
        }
    }

    private void run(String[] args) {
        parseOptions(args);
        execute();
    }

    private void execute() {
        if (options.isPrintVersionMode()) {
            new PrintVersionCommand().execute();
        } else if (options.isPrintHelpMode()) {
            options.printHelp();
        } else if (options.isPrintObjectMode()) {
            new PrintCertificateRepositoryObjectCommand(options).execute();
        } else if (options.isValidationMode()) {
            setVerbosity();
            if (options.isTopDownValidationEnabled()) {
                new TopDownValidationCommand(options).execute();
            } else {
                new BottomUpValidationCommand(options).execute();
            }
        }
    }

    private void parseOptions(String[] args) {
        options = new CommandLineOptions();
        try {
            options.parse(args);
        } catch (ParseException e) {
            LOG.fatal(e.getMessage());
            System.exit(1);
        }

    }

    private void setVerbosity() {
        if (options.isVerboseEnabled()) {
            Logger ripeNet = Logger.getLogger("net.ripe");
            ripeNet.setLevel(Level.DEBUG);
        }
    }
}
