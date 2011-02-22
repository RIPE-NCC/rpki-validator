package net.ripe.rpki.validator.daemon.service;

import net.ripe.commons.certification.cms.manifest.ManifestCms;
import net.ripe.commons.certification.cms.manifest.ManifestCmsTest;
import net.ripe.commons.certification.cms.roa.RoaCms;
import net.ripe.commons.certification.cms.roa.RoaCmsObjectMother;
import net.ripe.commons.certification.validation.ValidationResult;
import org.junit.Before;
import org.junit.Test;

import java.io.File;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;


public class BottomUpRoaValidationServiceTest {

    private BottomUpRoaValidationServiceImpl subject;
    private StubbedBottomUpRoaValidationCommand stubbedBottomUpRoaValidationCommand;

    @Before
    @SuppressWarnings("deprecation")
    public void setUp() {
        subject = new BottomUpRoaValidationServiceImpl();
        stubbedBottomUpRoaValidationCommand = new StubbedBottomUpRoaValidationCommand();
        subject.setValidationCommand(stubbedBottomUpRoaValidationCommand);
        subject.setTalLocation("./config/root.tal");
    }

    @Test
    public void shouldRejectGarbageUploaded() {
        byte[] garbage = new byte[]{0x10, 0x12, 0x3};
        BottomUpRoaValidationResult result = subject.validateRoa(garbage);
        assertFalse(result.isValid());
        assertFalse(stubbedBottomUpRoaValidationCommand.isCalled());
    }

    @Test
    public void shouldRejectOtherRpkiObjects() {
        ManifestCms manifestObject = ManifestCmsTest.getRootManifestCms();
        byte[] encodedManifestObject = manifestObject.getEncoded();
        BottomUpRoaValidationResult result = subject.validateRoa(encodedManifestObject);
        assertFalse(result.isValid());
        assertFalse(stubbedBottomUpRoaValidationCommand.isCalled());
    }

    @Test
    public void shouldValidateRoa() {
        RoaCms roaCms = RoaCmsObjectMother.getRoaCms();
        subject.validateRoa(roaCms.getEncoded());
        assertTrue(stubbedBottomUpRoaValidationCommand.isCalled());
    }

    private class StubbedBottomUpRoaValidationCommand extends BottomUpRoaValidationCommand {

        private boolean called = false;

        @Override
        public ValidationResult validate(RoaCms roaCms, File talFile) {
            called = true;
            return new ValidationResult();
        }

        public boolean isCalled() {
            return called;
        }

    }


}
