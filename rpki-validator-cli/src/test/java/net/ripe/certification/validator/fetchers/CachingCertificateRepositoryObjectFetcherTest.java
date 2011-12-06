/**
 * The BSD License
 *
 * Copyright (c) 2010, 2011 RIPE NCC
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

import static org.easymock.EasyMock.*;

import java.net.URI;

import net.ripe.certification.validator.RepositoryObjectsSetUpHelper;
import net.ripe.commons.certification.cms.manifest.ManifestCms;
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.util.Specification;
import net.ripe.commons.certification.util.Specifications;
import net.ripe.commons.certification.validation.CertificateRepositoryObjectValidationContextTest;
import net.ripe.commons.certification.validation.ValidationLocation;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;

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
        result = new ValidationResult();
        result.setLocation(new ValidationLocation(uri));
        fetcher = createMock(CertificateRepositoryObjectFetcher.class);
        subject = new CachingCertificateRepositoryObjectFetcher(fetcher);
    }

    @Test
    public void shouldPassOnPrefetch() {
        fetcher.prefetch(uri, result); expectLastCall().times(2);
        replay(fetcher);

        subject.prefetch(uri, result);
        subject.prefetch(uri, result);

        verify(fetcher);
    }

    @Test
    public void shouldCacheSuccessFromGetObject() {
        X509ResourceCertificate object = RepositoryObjectsSetUpHelper.getChildResourceCertificate();
        expect(fetcher.getObject(uri, context, fileContentSpecification, result)).andReturn(object).once();
        replay(fetcher);

        assertEquals(object, subject.getObject(uri, context, fileContentSpecification, result));
        assertEquals(object, subject.getObject(uri, context, fileContentSpecification, result));

        verify(fetcher);
    }

    @Test
    public void shouldCacheFailureFromGetObject() {
        expect(fetcher.getObject(uri, context, fileContentSpecification, result)).andReturn(null).once();
        replay(fetcher);

        assertEquals(null, subject.getObject(uri, context, fileContentSpecification, result));
        assertEquals(null, subject.getObject(uri, context, fileContentSpecification, result));
        assertEquals(null, subject.getCrl(uri, context, result));
        assertEquals(null, subject.getManifest(uri, context, result));

        verify(fetcher);
    }

    @Test
    public void shouldCacheManifestFromGetObject() {
        ManifestCms object = RepositoryObjectsSetUpHelper.getRootManifestCms();
        expect(fetcher.getObject(uri, context, fileContentSpecification, result)).andReturn(object).once();
        replay(fetcher);

        assertEquals(object, subject.getObject(uri, context, fileContentSpecification, result));
        assertEquals(object, subject.getManifest(uri, context, result));
        assertNull(subject.getCrl(uri, context, result));

        verify(fetcher);
    }

    @Test
    public void shouldCacheFailureFromGetManifest() {
        expect(fetcher.getManifest(uri, context, result)).andReturn(null).once();
        replay(fetcher);

        assertEquals(null, subject.getManifest(uri, context, result));
        assertEquals(null, subject.getManifest(uri, context, result));
        assertEquals(null, subject.getObject(uri, context, fileContentSpecification, result));

        verify(fetcher);
    }

    @Test
    public void shouldCacheSuccessFromGetManifest() {
        ManifestCms object = RepositoryObjectsSetUpHelper.getRootManifestCms();
        expect(fetcher.getManifest(uri, context, result)).andReturn(object).once();
        replay(fetcher);

        assertEquals(object, subject.getManifest(uri, context, result));
        assertEquals(object, subject.getManifest(uri, context, result));
        assertEquals(object, subject.getObject(uri, context, fileContentSpecification, result));

        verify(fetcher);
    }

    @Test
    public void shouldCacheSuccessFromGetCrl() {
        X509Crl object = RepositoryObjectsSetUpHelper.getRootCrl();
        expect(fetcher.getCrl(uri, context, result)).andReturn(object).once();
        replay(fetcher);

        assertEquals(object, subject.getCrl(uri, context, result));
        assertEquals(object, subject.getCrl(uri, context, result));
        assertEquals(object, subject.getObject(uri, context, fileContentSpecification, result));

        verify(fetcher);
    }

    @Test
    public void shouldCacheFailureFromGetCrl() {
        expect(fetcher.getCrl(uri, context, result)).andReturn(null).once();
        replay(fetcher);

        assertEquals(null, subject.getCrl(uri, context, result));
        assertEquals(null, subject.getCrl(uri, context, result));
        assertEquals(null, subject.getObject(uri, context, fileContentSpecification, result));

        verify(fetcher);
    }

    @Test
    public void shouldCacheCrlFromGetObject() {
        X509Crl object = RepositoryObjectsSetUpHelper.getRootCrl();
        expect(fetcher.getObject(uri, context, fileContentSpecification, result)).andReturn(object).once();
        replay(fetcher);

        assertEquals(object, subject.getObject(uri, context, fileContentSpecification, result));
        assertEquals(object, subject.getCrl(uri, context, result));
        assertNull(subject.getManifest(uri, context, result));

        verify(fetcher);
    }

}
