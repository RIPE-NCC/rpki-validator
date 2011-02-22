package net.ripe.rpki.validator.daemon.service;

import net.ripe.certification.validator.commands.BottomUpCertificateRepositoryObjectValidator;
import net.ripe.certification.validator.util.TrustAnchorExtractor;
import net.ripe.commons.certification.cms.roa.RoaCms;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;

import java.io.File;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

public class BottomUpRoaValidationCommand {

    private static final URI OBJECT_TO_VALIDATE_FAKE_URI = URI.create("rsync://no/where");

    public ValidationResult validate(RoaCms roaCms, File talFile) {
        return new BottomUpCertificateRepositoryObjectValidator(getTrustAnchors(talFile), roaCms, OBJECT_TO_VALIDATE_FAKE_URI).validate();
    }

    List<CertificateRepositoryObjectValidationContext> getTrustAnchors(File talFile) {
        List<File> talFiles = new ArrayList<File>();
        talFiles.add(talFile);

        TrustAnchorExtractor trustAnchorExtractor = new TrustAnchorExtractor();
        return trustAnchorExtractor.extractTAS(talFiles, "./validated-tas");
    }

}
