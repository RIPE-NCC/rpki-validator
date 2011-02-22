package net.ripe.rpki.validator.daemon.service;

import net.ripe.commons.certification.cms.roa.RoaCmsObjectMother;
import net.ripe.commons.certification.validation.ValidationResult;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class BottomUpRoaValidationResultTest {
    @Test
    public void shouldBeValidWithRoaAndNonFailingValidationChecks() {
        BottomUpRoaValidationResult result = new BottomUpRoaValidationResult(RoaCmsObjectMother.getRoaCms(), new ValidationResult());

        assertTrue(result.isValid());
    }

    @Test
    public void shouldBeInvalidWithoutAnything() {
        BottomUpRoaValidationResult result = new BottomUpRoaValidationResult();

        assertFalse(result.isValid());
    }

    @Test
    public void shouldBeInvalidWithFailingValidation() {
        ValidationResult validationResult = new ValidationResult();
        validationResult.push("a");
        validationResult.isFalse(true, "a");
        BottomUpRoaValidationResult result = new BottomUpRoaValidationResult(RoaCmsObjectMother.getRoaCms(), validationResult);

        assertFalse(result.isValid());
    }
}
