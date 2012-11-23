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
package net.ripe.certification.validator.commands;

import net.ripe.certification.validator.RepositoryObjectsSetUpHelper;
import net.ripe.certification.validator.fetchers.CertificateRepositoryObjectFetcher;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import org.apache.commons.io.FileUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;

import static net.ripe.certification.validator.commands.TopDownCertificateRepositoryValidator.*;
import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

public class TopDownCertificateRepositoryValidatorTest {

    private static final File TEST_OUTPUT_DIRECTORY = new File(System.getProperty("java.io.tmp", "/tmp"), "certification_unit_tests");

    private static final File VALIDATED_DIRECTORY = new File(new File(TEST_OUTPUT_DIRECTORY, BASE_DIRECTORY_NAME), VALIDATED_DIRECTORY_NAME);

    private static final File OLD_VALIDATED_DIRECTORY = new File(new File(TEST_OUTPUT_DIRECTORY, BASE_DIRECTORY_NAME), OLD_VALIDATED_DIRECTORY_NAME);

    private static final File UNVALIDATED_DIRECTORY = new File(new File(TEST_OUTPUT_DIRECTORY, BASE_DIRECTORY_NAME), UNVALIDATED_DIRECTORY_NAME);

    private CertificateRepositoryObjectValidationContext firstTrustAnchor;
    private CertificateRepositoryObjectValidationContext secondTrustAnchor;
    private LinkedList<CertificateRepositoryObjectValidationContext> expectedTrustAnchors;
    private TopDownCertificateRepositoryValidator subject;

    private List<CertificateRepositoryObjectValidationContext> processedTrustAnchors;
    private Queue<CertificateRepositoryObjectValidationContext> workQueue = new LinkedList<CertificateRepositoryObjectValidationContext>();


    @Before
    public void setUp() {
        processedTrustAnchors = new LinkedList<CertificateRepositoryObjectValidationContext>();

        firstTrustAnchor = new CertificateRepositoryObjectValidationContext(URI.create("rsync://host/first"), createTrustAnchor(IpResourceSet.parse("10.0.0.0/8")));
        secondTrustAnchor = new CertificateRepositoryObjectValidationContext(URI.create("rsync://host/second"), createTrustAnchor(IpResourceSet.parse("192.168.0.0/16")));
        List<CertificateRepositoryObjectValidationContext> trustAnchors = Arrays.asList(firstTrustAnchor, secondTrustAnchor);
        expectedTrustAnchors = new LinkedList<CertificateRepositoryObjectValidationContext>(trustAnchors);

        subject = new TopDownCertificateRepositoryValidator(trustAnchors, TEST_OUTPUT_DIRECTORY);
        subject.setTopDownWalker(new MockTopDownWalker(subject.getFetcher()));
    }

    private X509ResourceCertificate createTrustAnchor(IpResourceSet resources) {
        return RepositoryObjectsSetUpHelper.getRootResourceCertificate(resources);
    }

    @After
    public void tearDown() throws IOException {
        FileUtils.deleteDirectory(TEST_OUTPUT_DIRECTORY);
    }

    @Test
    public void shouldConfigureOutputDirectory() throws IOException {
        subject.prepare();

        assertTrue("unvalidated directory exists", UNVALIDATED_DIRECTORY.isDirectory());
        assertTrue("validated directory exists", VALIDATED_DIRECTORY.isDirectory());
        assertEquals("validated directory is empty", 0, VALIDATED_DIRECTORY.listFiles().length);
    }

    @Test
    public void shoudRenamedExistingValidatedDirectoryToOldValidatedDirectory() throws IOException {
        File validated = new File(VALIDATED_DIRECTORY, "validated.cer");
        FileUtils.writeStringToFile(validated, "validated");

        subject.prepare();

        assertTrue("old validated directory exists", OLD_VALIDATED_DIRECTORY.isDirectory());
        assertArrayEquals("validated.cer moved to old validated directory", new String[] { "validated.cer" }, OLD_VALIDATED_DIRECTORY.list());
    }

    @Test
    public void shouldRemoveExistingOldValidatedDirectory() throws IOException {
        File file = new File(OLD_VALIDATED_DIRECTORY, "file.txt");
        FileUtils.writeStringToFile(file, "hello");

        subject.prepare();

        assertFalse("old validated directory should be removed", OLD_VALIDATED_DIRECTORY.exists());
    }

    @Test
    public void shouldPerformTopDownValidationForEachTrustAnchor() {
        subject = new TopDownCertificateRepositoryValidator(Arrays.asList(firstTrustAnchor, secondTrustAnchor), TEST_OUTPUT_DIRECTORY);
        subject.setTopDownWalker(new MockTopDownWalker(subject.getFetcher()));

        subject.validate();

        assertEquals(2, processedTrustAnchors.size());
        assertTrue(processedTrustAnchors.contains(firstTrustAnchor));
        assertTrue(processedTrustAnchors.contains(secondTrustAnchor));
    }

    @Test
    public void shouldPrefetchRepositoryUris() {
        CertificateRepositoryObjectFetcher fetcher = createMock(CertificateRepositoryObjectFetcher.class);
        subject.setFetcher(fetcher);
        subject.setPrefetchUris(Arrays.asList(URI.create("rsync://foo/bar/"), URI.create("rsync://bar/baz/")));

        fetcher.prefetch(eq(URI.create("rsync://foo/bar/")), isA(ValidationResult.class));
        fetcher.prefetch(eq(URI.create("rsync://bar/baz/")), isA(ValidationResult.class));
        replay(fetcher);

        subject.validate();
        verify(fetcher);
    }

    private class MockTopDownWalker extends TopDownWalker {

        public MockTopDownWalker(CertificateRepositoryObjectFetcher certificateRepositoryObjectFetcher) {
            super(workQueue, certificateRepositoryObjectFetcher, new ValidationResult() );
        }

        @Override
        public void execute() {
            CertificateRepositoryObjectValidationContext expected = expectedTrustAnchors.remove();
            CertificateRepositoryObjectValidationContext actual = workQueue.remove();
            assertEquals("unexpected trust anchor", expected, actual);
            processedTrustAnchors.add(actual);
        }
    }
}
