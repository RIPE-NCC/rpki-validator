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

import static net.ripe.rpki.validator.RepositoryObjectsSetUpHelper.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.util.Specification;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationString;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.rpki.validator.RepositoryObjectsSetUpHelper;
import org.junit.Before;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;


public class ValidatingCertificateRepositoryObjectFetcherTest {

    private ValidatingCertificateRepositoryObjectFetcher subject;
    private CertificateRepositoryObjectFetcher rsyncFetcher;
    private CertificateRepositoryObjectFetcher decorator;
    private ValidationResult result;
    private X509ResourceCertificate rootCertificate;
    private CertificateRepositoryObjectValidationContext rootContext;
    private X509ResourceCertificate childCertificate;

    @Before
    public void setUp() {
        rsyncFetcher = mock(CertificateRepositoryObjectFetcher.class);
        decorator = mock(CertificateRepositoryObjectFetcher.class);

        subject = new ValidatingCertificateRepositoryObjectFetcher(rsyncFetcher);
        subject.setOuterMostDecorator(decorator);

        result = ValidationResult.withLocation(ROOT_CERTIFICATE_LOCATION);
        rootCertificate = getRootResourceCertificate();
        rootContext = new CertificateRepositoryObjectValidationContext(ROOT_CERTIFICATE_LOCATION, rootCertificate);

        childCertificate = getChildResourceCertificate();

    }

    @Test
    public void shouldPassOnPrefetch() {
        subject.prefetch(ROOT_CERTIFICATE_LOCATION, result);
        subject.prefetch(ROOT_CERTIFICATE_LOCATION, result);

        verify(rsyncFetcher, times(2)).prefetch(ROOT_CERTIFICATE_LOCATION, result);
    }

    @Test
    public void shouldGetCrlHappyFlow() {
        X509Crl crlFromRepository = getRootCrl();
        when(rsyncFetcher.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result)).thenReturn(crlFromRepository);

        final ManifestCms manifestFromRsync = getRootManifestCmsWithEntry("bar%20space.crl", crlFromRepository.getEncoded());
        when(rsyncFetcher.getManifest(rootContext.getManifestURI(), rootContext, result)).thenAnswer(new Answer<ManifestCms>() {
            @Override
            public ManifestCms answer(InvocationOnMock invocationOnMock) throws Throwable {
                assertEquals("manifest location not pushed before trying to retrieve manifest", new ValidationLocation(rootContext.getManifestURI()), result.getCurrentLocation());
                return manifestFromRsync;
            }
        });

        result.setLocation(new ValidationLocation(ROOT_MANIFEST_CRL_LOCATION));
        X509Crl crlActual = subject.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result);

        assertEquals(crlFromRepository, crlActual);
        assertEquals("crl location not restored", new ValidationLocation(ROOT_MANIFEST_CRL_LOCATION), result.getCurrentLocation());
    }


    @Test
    public void shouldRejectCrlWhenHashInvalid() {
        X509Crl crlFromRepository = getRootCrl();
        when(rsyncFetcher.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result)).thenReturn(crlFromRepository);

        ManifestCms manifestFromRsync = getRootManifestCmsWithEntry("bar%20space.crl", CONTENT_FOO);
        when(rsyncFetcher.getManifest(rootContext.getManifestURI(), rootContext, result)).thenReturn(manifestFromRsync);

        result.setLocation(new ValidationLocation(ROOT_MANIFEST_CRL_LOCATION));
        X509Crl crlActual = subject.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result);

        assertNull(crlActual);
        ValidationLocation expectedRootCrlErrorLocation = new ValidationLocation(ROOT_MANIFEST_CRL_LOCATION);
        assertTrue(result.hasFailureForLocation(expectedRootCrlErrorLocation));
        assertEquals(ValidationString.VALIDATOR_FILE_CONTENT,result.getFailures(expectedRootCrlErrorLocation).get(0).getKey());
    }

    @Test
    public void shouldRejectCrlWithoutManifestEntry() {
        X509Crl crlFromRepository = getRootCrl();
        when(rsyncFetcher.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result)).thenReturn(crlFromRepository);

        ManifestCms manifestFromRsync = getRootManifestCms();
        when(rsyncFetcher.getManifest(rootContext.getManifestURI(), rootContext, result)).thenReturn(manifestFromRsync);

        result.setLocation(new ValidationLocation(ROOT_MANIFEST_CRL_LOCATION));
        X509Crl crlActual = subject.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result);

        assertNull(crlActual);
        ValidationLocation expectedRootCrlErrorLocation = new ValidationLocation(ROOT_MANIFEST_CRL_LOCATION);
        assertTrue(result.hasFailureForLocation(expectedRootCrlErrorLocation));
        assertEquals(ValidationString.VALIDATOR_MANIFEST_DOES_NOT_CONTAIN_FILE, result.getFailures(expectedRootCrlErrorLocation).get(0).getKey());
    }

    @Test
    public void shouldRejectCrlWhenManifestInvalid() {
        X509Crl crlFromRepository = getRootCrl();
        when(rsyncFetcher.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result)).thenReturn(crlFromRepository);

        ManifestCms manifestFromRsync = getFutureDatedManifestCms();
        when(rsyncFetcher.getManifest(rootContext.getManifestURI(), rootContext, result)).thenReturn(manifestFromRsync);

        result.setLocation(new ValidationLocation(ROOT_MANIFEST_CRL_LOCATION));
        X509Crl crlActual = subject.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result);

        assertNull(crlActual);
        assertEquals(new ValidationLocation(ROOT_MANIFEST_CRL_LOCATION), result.getCurrentLocation());
        assertTrue(result.hasFailureForCurrentLocation());
    }

    @Test
    public void shouldRejectInvalidCrl() {
        result.setLocation(new ValidationLocation(ROOT_CERTIFICATE_LOCATION));

        X509Crl crlFromRepository = getRootCrlWithInvalidSignature();
        when(rsyncFetcher.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result)).thenReturn(crlFromRepository);

        ManifestCms manifestFromRsync = getRootManifestCmsWithEntry("bar space.crl", crlFromRepository.getEncoded());
        when(rsyncFetcher.getManifest(rootContext.getManifestURI(), rootContext, result)).thenReturn(manifestFromRsync);

        X509Crl crlValidated = subject.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result);

        assertNull(crlValidated);
        ValidationLocation rootManifestCrlValidationLocation = new ValidationLocation(ROOT_MANIFEST_CRL_LOCATION);
        assertTrue(result.hasFailureForLocation(rootManifestCrlValidationLocation));
        assertTrue(ValidationString.CRL_SIGNATURE_VALID.equals(result.getFailures(rootManifestCrlValidationLocation).get(0).getKey()));
    }

    @Test
    public void shouldReturnNullForCrlWhenCrlNotReturnedFromRsync() {
        result.setLocation(new ValidationLocation(ROOT_CERTIFICATE_LOCATION));

        X509Crl crlFromRepository = null;
        when(rsyncFetcher.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result)).thenReturn(crlFromRepository);

        X509Crl crlValidated = subject.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result);

        assertNull(crlValidated);
    }

    @Test
    public void shouldGetManifestHappyFlow() {
        ManifestCms cmsExpected = getRootManifestCms();
        X509Crl crlFromRepository = getRootCrl();

        when(rsyncFetcher.getManifest(ROOT_SIA_MANIFEST_RSYNC_LOCATION, rootContext, result)).thenReturn(cmsExpected);
        when(decorator.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result)).thenReturn(crlFromRepository);

        ManifestCms cmsActual = subject.getManifest(ROOT_SIA_MANIFEST_RSYNC_LOCATION, rootContext, result);

        assertEquals(cmsExpected, cmsActual);
    }

    @Test
    public void shouldRejectInvalidManifest() {
        ManifestCms cmsReturnedByRsyncFetcher = getFutureDatedManifestCms();
        X509Crl crlFromRepository = getRootCrl();

        when(rsyncFetcher.getManifest(ROOT_SIA_MANIFEST_RSYNC_LOCATION, rootContext, result)).thenReturn(cmsReturnedByRsyncFetcher);
        when(decorator.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result)).thenReturn(crlFromRepository);

        ManifestCms cmsReturnedByValidatingFetcher = subject.getManifest(ROOT_SIA_MANIFEST_RSYNC_LOCATION, rootContext, result);

        assertNull(cmsReturnedByValidatingFetcher);
    }

    @Test
    public void shouldReturnNullForManifestWhenManifestFromRsyncIsNull() {
        ManifestCms cmsFromRsync = null;

        when(rsyncFetcher.getManifest(ROOT_SIA_MANIFEST_RSYNC_LOCATION, rootContext, result)).thenReturn(cmsFromRsync);

        ManifestCms cmsFromValidatingFetcher = subject.getManifest(ROOT_SIA_MANIFEST_RSYNC_LOCATION, rootContext, result);

        assertNull(cmsFromValidatingFetcher);
    }


    @Test
    public void shouldGetCertificateRepositoryObjectHappyFlow() {
        Specification<byte[]> fileContentSpecification = null;
        when(rsyncFetcher.getObject(FIRST_CHILD_CERTIFICATE_LOCATION, rootContext, fileContentSpecification, result)).thenReturn(childCertificate);
        when(decorator.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result)).thenReturn(getRootCrl());

        CertificateRepositoryObject certificateFromValidatingFetcher = subject.getObject(FIRST_CHILD_CERTIFICATE_LOCATION, rootContext, fileContentSpecification, result);

        assertTrue(certificateFromValidatingFetcher instanceof X509ResourceCertificate);
        assertSame(certificateFromValidatingFetcher, childCertificate);
    }

    @Test
    public void shouldNotGetCrlWhenValidatingRootCertificate() {
        Specification<byte[]> fileContentSpecification = null;
        when(rsyncFetcher.getObject(ROOT_CERTIFICATE_LOCATION, rootContext, fileContentSpecification, result)).thenReturn(rootCertificate);

        CertificateRepositoryObject certificateFromValidatingFetcher = subject.getObject(ROOT_CERTIFICATE_LOCATION, rootContext, fileContentSpecification, result);

        assertTrue(certificateFromValidatingFetcher instanceof X509ResourceCertificate);
        assertSame(certificateFromValidatingFetcher, rootCertificate);
    }

    @Test
    public void shouldUseResourcesFromContextNotFromCertificate() {
        X509ResourceCertificate childCertificate = getChildResourceCertificate();
        X509ResourceCertificate grandchildCertificate = getSecondChildResourceCertificate();
        X509Crl crl = getChildCrl();

        Specification<byte[]> fileContentSpecification = null;
        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(FIRST_CHILD_CERTIFICATE_LOCATION, childCertificate, ROOT_RESOURCE_SET);
        when(rsyncFetcher.getObject(SECOND_CHILD_CERTIFICATE_LOCATION, context, fileContentSpecification, result)).thenReturn(grandchildCertificate);
        when(decorator.getCrl(FIRST_CHILD_MANIFEST_CRL_LOCATION, context, result)).thenReturn(crl);

        CertificateRepositoryObject certificateFromValidatingFetcher = subject.getObject(SECOND_CHILD_CERTIFICATE_LOCATION, context, fileContentSpecification, result);

        assertTrue(certificateFromValidatingFetcher instanceof X509ResourceCertificate);
        assertSame(certificateFromValidatingFetcher, grandchildCertificate);
    }

    @Test
    public void shouldRejectInvalidCertificateRepositoryObject() {
        Specification<byte[]> fileContentSpecification = null;
        when(rsyncFetcher.getObject(ROOT_CERTIFICATE_LOCATION, rootContext, fileContentSpecification, result)).thenReturn(RepositoryObjectsSetUpHelper.getExpiredRootResourceCertificate());

        CertificateRepositoryObject certificateFromValidatingFetcher = subject.getObject(ROOT_CERTIFICATE_LOCATION, rootContext, fileContentSpecification, result);

        assertNull(certificateFromValidatingFetcher);
        ValidationLocation rootCertValidationLocation = new ValidationLocation(ROOT_CERTIFICATE_LOCATION);
        assertTrue(result.hasFailureForLocation(rootCertValidationLocation));
        assertTrue(ValidationString.NOT_VALID_AFTER.equals(result.getFailures(rootCertValidationLocation).get(0).getKey()));
    }

    @Test
    public void shouldReturnNullForCROWhenCRONotReturnedFromRsync() {
        Specification<byte[]> fileContentSpecification = null;
        when(rsyncFetcher.getObject(ROOT_CERTIFICATE_LOCATION, rootContext, fileContentSpecification, result)).thenReturn(null);

        CertificateRepositoryObject certificateFromValidatingFetcher = subject.getObject(ROOT_CERTIFICATE_LOCATION, rootContext, fileContentSpecification, result);

        assertNull(certificateFromValidatingFetcher);
    }
}
