package net.ripe.certification.validator.commands;

import static net.ripe.certification.validator.util.CertificateRepositoryObjectLocalFileHelper.readCertificateRepositoryObject;

import java.io.File;

import net.ripe.certification.validator.cli.CommandLineOptions;
import net.ripe.commons.certification.validation.ValidationResult;

public class BottomUpValidationCommand extends ValidationCommand {

    private File inputFile;

    public BottomUpValidationCommand(CommandLineOptions options) {
        super(options);
        inputFile = options.getInputFile();
    }

    public ValidationResult execute() {
        BottomUpCertificateRepositoryObjectValidator validator = new BottomUpCertificateRepositoryObjectValidator(getTrustAnchors(), readCertificateRepositoryObject(inputFile), inputFile.toURI());
        return validator.validate();
    }
}
