package net.ripe.rpki.validator.daemon.service;

import net.ripe.commons.certification.cms.roa.RoaCms;
import net.ripe.commons.certification.validation.ValidationResult;

public class BottomUpRoaValidationResult {
    private RoaCms roa;
    private ValidationResult result;

    public BottomUpRoaValidationResult() {

    }

    public BottomUpRoaValidationResult(RoaCms roa, ValidationResult result) {
        this.roa = roa;
        this.result = result;
    }

    public RoaCms getRoa() {
        return roa;
    }

    public ValidationResult getResult() {
        return result;
    }

    public boolean isValid() {
        boolean valid = true;

        valid &= roa != null;
        valid &= result != null && !result.hasFailures();

        return valid;
    }
}
