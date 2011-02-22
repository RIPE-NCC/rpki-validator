package net.ripe.certification.validator.commands;

import java.util.ArrayList;
import java.util.List;

import net.ripe.certification.validator.cli.CommandLineOptions;
import net.ripe.certification.validator.util.TrustAnchorExtractor;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;

public abstract class ValidationCommand {

    private TrustAnchorExtractor trustAnchorExtractor;
    
    private CommandLineOptions options;

    public ValidationCommand(CommandLineOptions options) {
        this.options = options;
        trustAnchorExtractor = new TrustAnchorExtractor();
    }

    protected List<CertificateRepositoryObjectValidationContext> getTrustAnchors() {
        List<CertificateRepositoryObjectValidationContext> trustAnchors = new ArrayList<CertificateRepositoryObjectValidationContext>();
        trustAnchors.addAll(trustAnchorExtractor.extractTAS(options));
        return trustAnchors;
    }
}
