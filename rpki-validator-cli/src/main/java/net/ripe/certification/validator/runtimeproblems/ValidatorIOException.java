package net.ripe.certification.validator.runtimeproblems;

public class ValidatorIOException extends RuntimeException {
    
    private static final long serialVersionUID = 1L;

    public ValidatorIOException(String msg, Exception e) {
        super(msg, e);
    }

    public ValidatorIOException(String msg) {
        super(msg);
    }
}
