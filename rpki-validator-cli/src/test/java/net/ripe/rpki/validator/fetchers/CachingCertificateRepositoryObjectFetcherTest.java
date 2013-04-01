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

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import java.net.URI;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.util.Specification;
import net.ripe.rpki.commons.util.Specifications;
import net.ripe.rpki.commons.validation.CertificateRepositoryObjectValidationContextTest;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.rpki.validator.RepositoryObjectsSetUpHelper;
import org.junit.Before;
import org.junit.Test;


public class CachingCertificateRepositoryObjectFetcherTest {

    private URI uri;
    private CertificateRepositoryObjectValidationContext context;
    private Specification<byte[]> fileContentSpecification;
    private ValidationResult result;
    private CertificateRepositoryObjectFetcher fetcher;
    private CachingCertificateRepositoryObjectFetcher subject;

    @Before
    public void setUp() {
        uri = URI.create("rsync://host/path/");
        context = CertificateRepositoryObjectValidationContextTest.create();
        fileContentSpecification = Specifications.alwaysTrue();
        result = ValidationResult.withLocation(uri);
        fetcher = mock(CertificateRepositoryObjectFetcher.class);

        subject = new CachingCertificateRepositoryObjectFetcher(fetcher);
    }

    @Test
    public void shouldPassOnPrefetch() {
        subject.prefetch(uri, result);

        verify(fetcher).prefetch(uri, result);
    }

    @Test
    public void shouldCacheSuccessFromGetObject() {
        X509ResourceCertificate object = RepositoryObjectsSetUpHelper.getChildResourceCertificate();

        when(fetcher.getObject(uri, context, fileContentSpecification, result)).thenReturn(object);

        assertEquals(object, subject.getObject(uri, context, fileContentSpecification, result));
        assertEquals(object, subject.getObject(uri, context, fileContentSpecification, result));

        verify(fetcher, times(1)).getObject(uri, context, fileContentSpecification, result);
    }

    @Test
    public void shouldCacheFailureFromGetObject() {
        when(fetcher.getObject(uri, context, fileContentSpecification, result)).thenReturn(null);

        assertEquals(null, subject.getObject(uri, context, fileContentSpecification, result));
        assertEquals(null, subject.getObject(uri, context, fileContentSpecification, result));
        assertEquals(null, subject.getCrl(uri, context, result));
        assertEquals(null, subject.getManifest(uri, context, result));

        verify(fetcher, times(1)).getObject(uri, context, fileContentSpecification, result);
    }

    @Test
    public void shouldCacheManifestFromGetObject() {
        ManifestCms object = RepositoryObjectsSetUpHelper.getRootManifestCms();
        when(fetcher.getObject(uri, context, fileContentSpecification, result)).thenReturn(object);

        assertEquals(object, subject.getObject(uri, context, fileContentSpecification, result));
        assertEquals(object, subject.getManifest(uri, context, result));
        assertNull(subject.getCrl(uri, context, result));

        verify(fetcher, times(1)).getObject(uri, context, fileContentSpecification, result);
    }

    @Test
    public void shouldCacheFailureFromGetManifest() {
        when(fetcher.getManifest(uri, context, result)).thenReturn(null);

        assertEquals(null, subject.getManifest(uri, context, result));
        assertEquals(null, subject.getManifest(uri, context, result));
        assertEquals(null, subject.getObject(uri, context, fileContentSpecification, result));

        verify(fetcher, times(1)).getManifest(uri, context, result);
    }

    @Test
    public void shouldCacheSuccessFromGetManifest() {
        ManifestCms object = RepositoryObjectsSetUpHelper.getRootManifestCms();
        when(fetcher.getManifest(uri, context, result)).thenReturn(object);

        assertEquals(object, subject.getManifest(uri, context, result));
        assertEquals(object, subject.getManifest(uri, context, result));
        assertEquals(object, subject.getObject(uri, context, fileContentSpecification, result));

        verify(fetcher, times(1)).getManifest(uri, context, result);
    }

    @Test
    public void shouldCacheSuccessFromGetCrl() {
        X509Crl object = RepositoryObjectsSetUpHelper.getRootCrl();
        when(fetcher.getCrl(uri, context, result)).thenReturn(object);

        assertEquals(object, subject.getCrl(uri, context, result));
        assertEquals(object, subject.getCrl(uri, context, result));
        assertEquals(object, subject.getObject(uri, context, fileContentSpecification, result));

        verify(fetcher, times(1)).getCrl(uri, context, result);
    }

    @Test
    public void shouldCacheFailureFromGetCrl() {
        when(fetcher.getCrl(uri, context, result)).thenReturn(null);

        assertEquals(null, subject.getCrl(uri, context, result));
        assertEquals(null, subject.getCrl(uri, context, result));
        assertEquals(null, subject.getObject(uri, context, fileContentSpecification, result));

        verify(fetcher, times(1)).getCrl(uri, context, result);
    }

    @Test
    public void shouldCacheCrlFromGetObject() {
        X509Crl object = RepositoryObjectsSetUpHelper.getRootCrl();
        when(fetcher.getObject(uri, context, fileContentSpecification, result)).thenReturn(object);

        assertEquals(object, subject.getObject(uri, context, fileContentSpecification, result));
        assertEquals(object, subject.getCrl(uri, context, result));
        assertNull(subject.getManifest(uri, context, result));

        verify(fetcher, times(1)).getObject(uri, context, fileContentSpecification, result);
    }

}
