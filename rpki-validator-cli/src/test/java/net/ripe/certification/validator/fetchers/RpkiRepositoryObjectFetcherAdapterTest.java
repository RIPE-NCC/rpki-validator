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
package net.ripe.certification.validator.fetchers;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.net.URI;
import net.ripe.commons.certification.cms.manifest.ManifestCms;
import net.ripe.commons.certification.cms.manifest.ManifestCmsTest;
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.crl.X509CrlTest;
import net.ripe.commons.certification.util.Specification;
import net.ripe.commons.certification.util.Specifications;
import net.ripe.commons.certification.validation.ValidationLocation;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.ValidationString;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateTest;
import org.junit.Before;
import org.junit.Test;


public class RpkiRepositoryObjectFetcherAdapterTest {

    private static final Specification<byte[]> ALWAYS_TRUE = Specifications.<byte[]>alwaysTrue();

    private static final URI TEST_URI = URI.create("rsync://localhost/test/uri");

    private static final ValidationLocation LOCATION = new ValidationLocation(TEST_URI);

    private ValidationResult validationResult;
    private RpkiRepositoryObjectFetcher fetcher;
    private RpkiRepositoryObjectFetcherAdapter subject;

    private X509ResourceCertificate certificate;
    private ManifestCms manifest;
    private X509Crl crl;

    @Before
    public void setUp() {
        certificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate();
        manifest = ManifestCmsTest.getRootManifestCms();
        crl = X509CrlTest.createCrl();

        validationResult = new ValidationResult();
        validationResult.setLocation(LOCATION);

        fetcher = mock(RpkiRepositoryObjectFetcher.class);

        subject = new RpkiRepositoryObjectFetcherAdapter(fetcher);
    }

    @Test
    public void should_prefetch_using_underlying_fetcher() {
        subject.prefetch(TEST_URI, validationResult);

        verify(fetcher, times(1)).prefetch(TEST_URI, validationResult);
        verifyNoMoreInteractions(fetcher);
    }

    @Test
    public void should_fetch_object_using_underlying_fetcher() {
        when(fetcher.fetch(TEST_URI, ALWAYS_TRUE, validationResult)).thenReturn(certificate);

        assertEquals(certificate, subject.getObject(TEST_URI, null, ALWAYS_TRUE, validationResult));

        verify(fetcher, times(1)).fetch(TEST_URI, ALWAYS_TRUE, validationResult);
    }

    @Test
    public void should_fetch_manifest() {
        when(fetcher.fetch(TEST_URI, ALWAYS_TRUE, validationResult)).thenReturn(manifest);

        assertEquals(manifest, subject.getManifest(TEST_URI, null, validationResult));
        assertTrue(validationResult.getResult(LOCATION, ValidationString.VALIDATOR_FETCHED_OBJECT_IS_MANIFEST).isOk());
    }

    @Test
    public void should_fail_when_fetched_manifest_has_errors() {
        when(fetcher.fetch(TEST_URI, ALWAYS_TRUE, validationResult)).thenReturn(manifest);
        validationResult.error("error");

        assertEquals(null, subject.getManifest(TEST_URI, null, validationResult));
    }

    @Test
    public void should_fail_when_fetched_object_is_not_a_manifest() {
        when(fetcher.fetch(TEST_URI, ALWAYS_TRUE, validationResult)).thenReturn(certificate);

        assertEquals(null, subject.getManifest(TEST_URI, null, validationResult));
        assertFalse(validationResult.getResult(LOCATION, ValidationString.VALIDATOR_FETCHED_OBJECT_IS_MANIFEST).isOk());
    }

    @Test
    public void should_fetch_crl() {
        when(fetcher.fetch(TEST_URI, ALWAYS_TRUE, validationResult)).thenReturn(crl);

        assertEquals(crl, subject.getCrl(TEST_URI, null, validationResult));
        assertTrue(validationResult.getResult(LOCATION, ValidationString.VALIDATOR_FETCHED_OBJECT_IS_CRL).isOk());
    }

    @Test
    public void should_fail_when_fetched_crl_has_errors() {
        when(fetcher.fetch(TEST_URI, ALWAYS_TRUE, validationResult)).thenReturn(crl);
        validationResult.error("error");

        assertEquals(null, subject.getCrl(TEST_URI, null, validationResult));
    }

    @Test
    public void should_fail_when_fetched_object_is_not_a_crl() {
        when(fetcher.fetch(TEST_URI, ALWAYS_TRUE, validationResult)).thenReturn(certificate);

        assertEquals(null, subject.getCrl(TEST_URI, null, validationResult));
        assertFalse(validationResult.getResult(LOCATION, ValidationString.VALIDATOR_FETCHED_OBJECT_IS_CRL).isOk());
    }
}
