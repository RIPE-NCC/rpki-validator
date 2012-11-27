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
package net.ripe.rpki.validator.fetchers;

import static net.ripe.rpki.commons.validation.ValidationString.*;
import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.rsync.Rsync;
import net.ripe.rpki.commons.util.Specifications;
import net.ripe.rpki.commons.validation.ValidationCheck;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationStatus;
import net.ripe.rpki.validator.commands.TopDownWalkerTest;
import net.ripe.rpki.validator.util.UriToFileMapper;
import org.apache.commons.io.FileUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class RsyncRpkiRepositoryObjectFetcherTest {

    private static final File TEST_TARGET_DIRECTORY = new File(System.getProperty("java.io.tmpdir", "/tmp"));

    private static final URI TEST_REPOSITORY_URI = URI.create("RSYNC://localhost:9999/repo/ca%20repo/");

    private static final File TEST_REPOSITORY_DIRECTORY = new File(TEST_TARGET_DIRECTORY, "localhost:9999/repo/ca%20repo/");

    private static final URI VALIDATION_URI = TEST_REPOSITORY_URI.resolve("object.cer");

    private static final URI TEST_OBJECT_CERT_URI = TEST_REPOSITORY_URI.resolve("object.cer");
    private static final File TEST_OBJECT_CERT_FILE = new File(TEST_TARGET_DIRECTORY, "localhost:9999/repo/ca%20repo/object.cer");

    private boolean rsyncExecuted = false;
    private int rsyncExitCode = 0;
    private byte[] rsyncFileContents;
    private Rsync rsync;
    private CertificateRepositoryObject object;
    private ValidationResult validationResult;
    private RpkiRepositoryObjectFetcher subject;

    @Before
    public void setUp() {
        rsync = new Rsync() {
            @Override
            public int execute() {
                rsyncExecuted = true;
                if (rsyncFileContents != null) {
                    try {
                        FileUtils.writeByteArrayToFile(new File(getDestination()), rsyncFileContents);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
                return rsyncExitCode;
            }
        };
        object = TopDownWalkerTest.getRootManifestCms();
        validationResult = new ValidationResult();
        validationResult.setLocation(new ValidationLocation(VALIDATION_URI));
        subject = new RsyncRpkiRepositoryObjectFetcher(rsync, new UriToFileMapper(TEST_TARGET_DIRECTORY));
    }

    @After
    public void tearDown() throws IOException {
        FileUtils.deleteDirectory(TEST_REPOSITORY_DIRECTORY);
    }

    @Test
    public void shouldFetchObject() {
        rsyncFileContents = object.getEncoded();
        assertEquals(object, subject.fetch(TEST_OBJECT_CERT_URI, Specifications.<byte[]>alwaysTrue(), validationResult));
        assertEquals(new ValidationCheck(ValidationStatus.PASSED, KNOWN_OBJECT_TYPE, VALIDATION_URI.toString()), validationResult.getResult(new ValidationLocation(VALIDATION_URI), KNOWN_OBJECT_TYPE));
    }

    @Test
    public void shouldNotFetchObjectIfContentsCannotBeVerified() {
        rsyncFileContents = object.getEncoded();
        assertNull("content verification must fail", subject.fetch(TEST_OBJECT_CERT_URI, Specifications.<byte[]>alwaysFalse(), validationResult));
        assertEquals(new ValidationCheck(ValidationStatus.ERROR, VALIDATOR_FILE_CONTENT, TEST_OBJECT_CERT_URI.toString()), validationResult.getResult(new ValidationLocation(TEST_OBJECT_CERT_URI), VALIDATOR_FILE_CONTENT));
    }

    @Test
    public void shouldNotFetchObjectIfContentsCannotBeParsed() {
        rsyncFileContents = new byte[] { 0x10, 0x12, 0x3 };
        assertNull("content should not be parsed", subject.fetch(TEST_OBJECT_CERT_URI, Specifications.<byte[]>alwaysTrue(), validationResult));
        assertEquals(new ValidationCheck(ValidationStatus.ERROR, KNOWN_OBJECT_TYPE, TEST_OBJECT_CERT_URI.toString()), validationResult.getResult(new ValidationLocation(TEST_OBJECT_CERT_URI), KNOWN_OBJECT_TYPE));
    }

    @Test
    public void shouldFetchObjectUsingRsync() {
        subject.fetch(TEST_OBJECT_CERT_URI, Specifications.<byte[]>alwaysTrue(), validationResult);

        assertTrue("rsync executed", rsyncExecuted);
        assertFalse("rsync --recursive must not be added for single file", rsync.containsOption("--recursive"));
        assertEquals(TEST_OBJECT_CERT_URI.toString(), rsync.getSource());
        assertEquals(TEST_OBJECT_CERT_FILE.getAbsolutePath(), rsync.getDestination());
    }

    @Test
    public void shouldNotFetchObjectUsingRsyncWhenUriAlreadyCached() {
        subject.prefetch(TEST_REPOSITORY_URI, validationResult);
        assertTrue("repository prefetched", rsyncExecuted);

        rsyncExecuted = false;
        subject.fetch(TEST_OBJECT_CERT_URI, Specifications.<byte[]>alwaysTrue(), validationResult);
        assertFalse("rsync should not execute for cached uri", rsyncExecuted);
    }

    @Test
    public void shouldNotFetchObjectIfFileCannotBeRead() {
        rsyncExitCode = 0;
        rsyncFileContents = null;
        assertNull(subject.fetch(TEST_OBJECT_CERT_URI, Specifications.<byte[]>alwaysFalse(), validationResult));
        assertFalse(validationResult.getResult(new ValidationLocation(TEST_OBJECT_CERT_URI), VALIDATOR_READ_FILE).isOk());
    }

    @Test
    public void shouldNotFetchObjectIfUriCannotBeMapped() {
        rsyncFileContents = object.getEncoded();
        assertNull(subject.fetch(URI.create("rsync:///missinghost/"), Specifications.<byte[]>alwaysTrue(), validationResult));
        assertTrue(validationResult.hasFailureForCurrentLocation());
    }

    @Test
    public void shouldPrefetchUriUsingRsync() {
        subject.prefetch(TEST_REPOSITORY_URI, validationResult);

        File completeTargetDirectory = TEST_REPOSITORY_DIRECTORY;
        assertTrue("rsync executed", rsyncExecuted);
        assertTrue("target directory created", completeTargetDirectory.isDirectory());
        assertTrue("rsync --recursive option set", rsync.containsOption("--recursive"));
        assertTrue("rsync --delete option set", rsync.containsOption("--delete"));
        assertEquals(TEST_REPOSITORY_URI.toString(), rsync.getSource());
        assertEquals(completeTargetDirectory.getAbsolutePath(), rsync.getDestination());
    }

    @Test
    public void shouldNotPrefetchIfUriCannotBeMapped() {
        subject.prefetch(URI.create("rsync:///missinghost/"), validationResult);
        assertTrue(validationResult.hasFailureForCurrentLocation());
    }

    @Test
    public void shouldNotPrefetchCachedUri() {
        subject.prefetch(TEST_REPOSITORY_URI, validationResult);
        assertTrue("rsync initially executed", rsyncExecuted);

        rsyncExecuted = false;
        subject.prefetch(TEST_REPOSITORY_URI, validationResult);
        assertFalse("rsync should not be executed again", rsyncExecuted);
    }
}
