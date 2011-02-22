package net.ripe.certification.validator.commands;

import static net.ripe.certification.validator.util.CertificateRepositoryObjectLocalFileHelper.readCertificateRepositoryObject;

import java.io.File;
import java.io.PrintWriter;

import net.ripe.certification.validator.cli.CommandLineOptions;
import net.ripe.commons.certification.util.CertificateRepositoryObjectPrinter;

public class PrintCertificateRepositoryObjectCommand {

    private File inputFile;

    public PrintCertificateRepositoryObjectCommand(CommandLineOptions options) {
        inputFile = options.getInputFile();
    }

    public void execute() {
        CertificateRepositoryObjectPrinter.print(new PrintWriter(System.out, true), readCertificateRepositoryObject(inputFile));
    }
}
