package net.ripe.certification.validator.output;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.net.URI;

import net.ripe.certification.validator.util.UriToFileMapper;
import net.ripe.certification.validator.util.UriToFileMapperTest;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateTest;

import org.apache.commons.io.FileUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;


public class ValidatedObjectWriterTest {

    private static final File TEST_TARGET_DIRECTORY = new File(System.getProperty("java.io.tmp", "/tmp"));

    private static final URI TEST_OBJECT_URI = URI.create("RSYNC://localhost:9999/repo/ca%20repo/object.cer");

    private static final File TEST_OBJECT_FILE = new File(TEST_TARGET_DIRECTORY, "localhost:9999/repo/ca%20repo/object.cer");

    private ValidationResult result;
    private X509ResourceCertificate certificate;
    private ValidatedObjectWriter subject;

    @Before
    public void setUp() {
        result = new ValidationResult();
        result.push(TEST_OBJECT_URI);

        certificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate();
        subject = new ValidatedObjectWriter(new UriToFileMapper(TEST_TARGET_DIRECTORY));
    }

    @After
    public void tearDown() throws IOException {
        FileUtils.deleteDirectory(TEST_OBJECT_FILE.getParentFile());
    }

    @Test
    public void shouldCopyValidatedObjectToTargetDirectory() throws IOException {
        subject.afterFetchSuccess(TEST_OBJECT_URI, certificate, result);

        assertTrue("file created", TEST_OBJECT_FILE.exists());
        assertArrayEquals("contents match", certificate.getEncoded(), FileUtils.readFileToByteArray(TEST_OBJECT_FILE));
    }

    @Test
    public void shouldNotOverwriteExistingFile() throws IOException {
        FileUtils.writeStringToFile(TEST_OBJECT_FILE, "123");
        subject.afterFetchSuccess(TEST_OBJECT_URI, certificate, result);

        assertTrue("file created", TEST_OBJECT_FILE.exists());
        assertEquals("123", FileUtils.readFileToString(TEST_OBJECT_FILE, null));
    }

    @Test(expected=IllegalArgumentException.class)
    public void shouldFailIfUriCannotBeMappedToFile() {
        subject.afterFetchSuccess(UriToFileMapperTest.INVALID_URI, certificate, result);
    }

}
