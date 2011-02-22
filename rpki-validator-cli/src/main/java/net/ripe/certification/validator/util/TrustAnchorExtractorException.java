package net.ripe.certification.validator.util;


public class TrustAnchorExtractorException extends RuntimeException {

    private static final long serialVersionUID = 1L;


    public TrustAnchorExtractorException(String message, Exception e) {
        super(message, e);
    }

    public TrustAnchorExtractorException(String message) {
        super(message);
    }
}