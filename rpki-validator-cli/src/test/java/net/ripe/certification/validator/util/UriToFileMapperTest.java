package net.ripe.certification.validator.util;

import static net.ripe.commons.certification.validation.ValidationString.*;
import static org.junit.Assert.*;

import java.io.File;
import java.net.URI;

import net.ripe.commons.certification.validation.ValidationResult;

import org.junit.Before;
import org.junit.Test;


public class UriToFileMapperTest {

    public static final URI INVALID_URI = URI.create("rsync:///path/file.txt");

    private static final File TARGET_DIRECTORY = new File("/test");

    private ValidationResult validationResult;
    private UriToFileMapper subject;

    @Before
    public void setUp() {
        validationResult = new ValidationResult();
        validationResult.push("test");
        subject = new UriToFileMapper(TARGET_DIRECTORY);
    }

    @Test
    public void shouldIncludeHostAndPathInFile() {
        assertEquals(new File("/test/localhost/path/file.txt"), subject.map(URI.create("rsync://localhost/path/file.txt"), validationResult));
        assertFalse(validationResult.hasFailureForCurrentLocation());
        assertTrue(validationResult.getResult("test", VALIDATOR_URI_RSYNC_SCHEME).isOk());
        assertTrue(validationResult.getResult("test", VALIDATOR_URI_HOST).isOk());
        assertTrue(validationResult.getResult("test", VALIDATOR_URI_PATH).isOk());
        assertTrue(validationResult.getResult("test", VALIDATOR_URI_SAFETY).isOk());
    }

    @Test
    public void shouldIncludePortInFile() {
        assertEquals(new File("/test/localhost:1234"), subject.map(URI.create("rsync://localhost:1234"), validationResult));
        assertFalse(validationResult.hasFailureForCurrentLocation());
    }

    @Test
    public void shouldRejectNonRsyncUri() {
        assertNull(subject.map(URI.create("http://localhost/path/file.txt"), validationResult));
        assertTrue(validationResult.hasFailureForCurrentLocation());
        assertFalse(validationResult.getResult("test", VALIDATOR_URI_RSYNC_SCHEME).isOk());
    }

    @Test
    public void shouldRejectUriWithoutHost() {
        assertNull(subject.map(URI.create("rsync:///path/file.txt"), validationResult));
        assertTrue(validationResult.hasFailureForCurrentLocation());
        assertFalse(validationResult.getResult("test", VALIDATOR_URI_HOST).isOk());
    }

    @Test
    public void shouldRejectUriWithHostStartingWithDot() {
        assertNull(subject.map(URI.create("rsync://.host/path/file.txt"), validationResult));
        assertTrue(validationResult.hasFailureForCurrentLocation());
        assertFalse(validationResult.getResult("test", VALIDATOR_URI_HOST).isOk());
    }

    @Test
    public void shouldRejectUriWithoutPath() {
        assertNull(subject.map(URI.create("rsync:foo"), validationResult));
        assertTrue(validationResult.hasFailureForCurrentLocation());
        assertFalse(validationResult.getResult("test", VALIDATOR_URI_PATH).isOk());
    }

    @Test
    public void shouldRejectUriContainingParentDirectoryPath() {
        assertNull(subject.map(URI.create("rsync://host/path/../foo.txt"), validationResult));
        assertTrue(validationResult.hasFailureForCurrentLocation());
        assertFalse(validationResult.getResult("test", VALIDATOR_URI_SAFETY).isOk());
    }

    @Test
    public void shouldRejectUriEndingInParentDirectoryPath() {
        assertNull(subject.map(URI.create("rsync://host/.."), validationResult));
        assertTrue(validationResult.hasFailureForCurrentLocation());
        assertFalse(validationResult.getResult("test", VALIDATOR_URI_SAFETY).isOk());
    }

}
