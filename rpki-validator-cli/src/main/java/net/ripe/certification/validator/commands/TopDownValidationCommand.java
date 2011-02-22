package net.ripe.certification.validator.commands;

import java.io.File;
import java.net.URI;
import java.util.List;

import net.ripe.certification.validator.cli.CommandLineOptions;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;

public class TopDownValidationCommand extends ValidationCommand {

    private File outputDir;

    private List<URI> prefetchUris;

    private boolean roaExportEnabled;

    private File roaExportFile;


    public TopDownValidationCommand(CommandLineOptions options) {
        super(options);
        outputDir = options.getOutputDir();
        prefetchUris = options.getPrefetchUris();
        roaExportEnabled = options.isRoaExportEnabled();
        roaExportFile = options.getRoaExportFile();
    }

    public void execute() {
        List<CertificateRepositoryObjectValidationContext> trustAnchors = getTrustAnchors();
        TopDownCertificateRepositoryValidator validator;
        if (roaExportEnabled) {
            validator = new TopDownCertificateRepositoryValidator(trustAnchors, outputDir, roaExportFile);
        } else {
            validator = new TopDownCertificateRepositoryValidator(trustAnchors, outputDir);
        }
        validator.setPrefetchUris(prefetchUris);
        validator.prepare();
        validator.validate();
    }
}
