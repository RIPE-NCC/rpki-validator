package net.ripe.certification.validator.commands;

import static org.junit.Assert.*;

import java.io.File;
import java.util.List;

import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;

import org.junit.Before;
import org.junit.Test;

public class BottomUpCertificateRepositoryObjectValidatorTest {

	private BottomUpCertificateRepositoryObjectValidator validator;

	@Before
	public void setUp() {
		validator = new BottomUpCertificateRepositoryObjectValidator(null, null, null);
	}

	@Test
	public void shouldCreateAndDeleteTempDirectory() {
		SingleObjectWalker singleObjectWalker = new SingleObjectWalker(null, null, null, null, null) {

			@Override
			public ValidationResult execute(List<CertificateRepositoryObjectValidationContext> trustAnchors) {
				// Do nothing for this test
				return new ValidationResult();
			}

			

		};
		validator.setSingleObjectWalker(singleObjectWalker);

		File tempDir = validator.getTempDirectory();
		assertTrue(tempDir.exists());
		assertTrue(tempDir.canWrite());

		validator.validate();

		assertFalse(tempDir.exists());

	}
}
