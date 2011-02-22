package net.ripe.rpki.validator.daemon.service;

public interface BottomUpRoaValidationService {

    BottomUpRoaValidationResult validateRoa(byte[] encodedObject);
}
