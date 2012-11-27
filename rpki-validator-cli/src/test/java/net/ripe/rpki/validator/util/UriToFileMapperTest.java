/**
 * The BSD License
 *
 * Copyright (c) 2010-2012 RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of the RIPE NCC nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.rpki.validator.util;

import net.ripe.rpki.validator.util.UriToFileMapper;

import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.net.URI;

import static net.ripe.rpki.commons.validation.ValidationString.*;
import static org.junit.Assert.*;


public class UriToFileMapperTest {

    public static final URI INVALID_URI = URI.create("rsync:///path/file.txt");

    private static final File TARGET_DIRECTORY = new File("/test");
    private static final ValidationLocation TEST_LOCATION = new ValidationLocation("test");

    private ValidationResult validationResult;
    private UriToFileMapper subject;

    @Before
    public void setUp() {
        validationResult = new ValidationResult();
        validationResult.setLocation(TEST_LOCATION);
        subject = new UriToFileMapper(TARGET_DIRECTORY);
    }

    @Test
    public void shouldIncludeHostAndPathInFile() {
        assertEquals(new File("/test/localhost/path/file.txt"), subject.map(URI.create("rsync://localhost/path/file.txt"), validationResult));
        assertFalse(validationResult.hasFailureForCurrentLocation());
        assertTrue(validationResult.getResult(TEST_LOCATION, VALIDATOR_URI_RSYNC_SCHEME).isOk());
        assertTrue(validationResult.getResult(TEST_LOCATION, VALIDATOR_URI_HOST).isOk());
        assertTrue(validationResult.getResult(TEST_LOCATION, VALIDATOR_URI_PATH).isOk());
        assertTrue(validationResult.getResult(TEST_LOCATION, VALIDATOR_URI_SAFETY).isOk());
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
        assertFalse(validationResult.getResult(TEST_LOCATION, VALIDATOR_URI_RSYNC_SCHEME).isOk());
    }

    @Test
    public void shouldRejectUriWithoutHost() {
        assertNull(subject.map(URI.create("rsync:///path/file.txt"), validationResult));
        assertTrue(validationResult.hasFailureForCurrentLocation());
        assertFalse(validationResult.getResult(TEST_LOCATION, VALIDATOR_URI_HOST).isOk());
    }

    @Test
    public void shouldRejectUriWithHostStartingWithDot() {
        assertNull(subject.map(URI.create("rsync://.host/path/file.txt"), validationResult));
        assertTrue(validationResult.hasFailureForCurrentLocation());
        assertFalse(validationResult.getResult(TEST_LOCATION, VALIDATOR_URI_HOST).isOk());
    }

    @Test
    public void shouldRejectUriWithoutPath() {
        assertNull(subject.map(URI.create("rsync:foo"), validationResult));
        assertTrue(validationResult.hasFailureForCurrentLocation());
        assertFalse(validationResult.getResult(TEST_LOCATION, VALIDATOR_URI_PATH).isOk());
    }

    @Test
    public void shouldRejectUriContainingParentDirectoryPath() {
        assertNull(subject.map(URI.create("rsync://host/path/../foo.txt"), validationResult));
        assertTrue(validationResult.hasFailureForCurrentLocation());
        assertFalse(validationResult.getResult(TEST_LOCATION, VALIDATOR_URI_SAFETY).isOk());
    }

    @Test
    public void shouldRejectUriEndingInParentDirectoryPath() {
        assertNull(subject.map(URI.create("rsync://host/.."), validationResult));
        assertTrue(validationResult.hasFailureForCurrentLocation());
        assertFalse(validationResult.getResult(TEST_LOCATION, VALIDATOR_URI_SAFETY).isOk());
    }

}
