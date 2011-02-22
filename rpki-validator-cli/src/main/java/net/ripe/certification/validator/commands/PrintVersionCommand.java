package net.ripe.certification.validator.commands;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;

public class PrintVersionCommand {

    private static final Logger LOG = Logger.getLogger(PrintVersionCommand.class);

    public void execute() {
        InputStream input = null;
        try {
            input = getClass().getResourceAsStream("/version.properties");
            Properties versionProperties = new Properties();
            versionProperties.load(input);
            System.out.println("RIPE NCC Certificate Validation Tool version " + versionProperties.get("version")); //NOPMD - SystemPrintln
        } catch (IOException e) {
            LOG.fatal(e);
        } finally {
            IOUtils.closeQuietly(input);
        }
    }
}
