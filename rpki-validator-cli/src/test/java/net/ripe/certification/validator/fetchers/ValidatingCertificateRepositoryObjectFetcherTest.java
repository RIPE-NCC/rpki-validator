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

import net.ripe.certification.validator.RepositoryObjectsSetUpHelper;
import net.ripe.commons.certification.CertificateRepositoryObject;
import net.ripe.commons.certification.cms.manifest.ManifestCms;
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.util.Specification;
import net.ripe.commons.certification.validation.ValidationLocation;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.ValidationString;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import org.easymock.IAnswer;
import org.junit.Before;
import org.junit.Test;

import static net.ripe.certification.validator.RepositoryObjectsSetUpHelper.*;
import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;


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
        rsyncFetcher = createMock(CertificateRepositoryObjectFetcher.class);
        decorator = createMock(CertificateRepositoryObjectFetcher.class);

        subject = new ValidatingCertificateRepositoryObjectFetcher(rsyncFetcher);
        subject.setOuterMostDecorator(decorator);

        result = new ValidationResult();

        rootCertificate = getRootResourceCertificate();
        rootContext = new CertificateRepositoryObjectValidationContext(ROOT_CERTIFICATE_LOCATION, rootCertificate);

        childCertificate = getChildResourceCertificate();

    }

    @Test
    public void shouldPassOnPrefetch() {
        rsyncFetcher.prefetch(ROOT_CERTIFICATE_LOCATION, result); expectLastCall().times(2);
        replay(rsyncFetcher);

        subject.prefetch(ROOT_CERTIFICATE_LOCATION, result);
        subject.prefetch(ROOT_CERTIFICATE_LOCATION, result);

        verify(rsyncFetcher);
    }

    @Test
    public void shouldGetCrlHappyFlow() {
        X509Crl crlFromRepository = getRootCrl();
        expect(rsyncFetcher.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result)).andReturn(crlFromRepository);

        final ManifestCms manifestFromRsync = getRootManifestCmsWithEntry("bar%20space.crl", crlFromRepository.getEncoded());
        expect(rsyncFetcher.getManifest(rootContext.getManifestURI(), rootContext, result)).andAnswer(new IAnswer<ManifestCms>() {
            @Override
            public ManifestCms answer() throws Throwable {
                assertEquals("manifest location not pushed before trying to retrieve manifest", new ValidationLocation(rootContext.getManifestURI()), result.getCurrentLocation());
                return manifestFromRsync;
            }
        });
        replayMocks();

        result.setLocation(new ValidationLocation(ROOT_MANIFEST_CRL_LOCATION));
        X509Crl crlActual = subject.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result);

        verifyMocks();
        assertEquals(crlFromRepository, crlActual);
        assertEquals("crl location not restored", new ValidationLocation(ROOT_MANIFEST_CRL_LOCATION), result.getCurrentLocation());
    }


    @Test
    public void shouldRejectCrlWhenHashInvalid() {
        X509Crl crlFromRepository = getRootCrl();
        expect(rsyncFetcher.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result)).andReturn(crlFromRepository);

        ManifestCms manifestFromRsync = getRootManifestCmsWithEntry("bar%20space.crl", CONTENT_FOO);
        expect(rsyncFetcher.getManifest(rootContext.getManifestURI(), rootContext, result)).andReturn(manifestFromRsync);
        replayMocks();

        result.setLocation(new ValidationLocation(ROOT_MANIFEST_CRL_LOCATION));
        X509Crl crlActual = subject.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result);

        verifyMocks();
        assertNull(crlActual);
        ValidationLocation expectedRootCrlErrorLocation = new ValidationLocation(ROOT_MANIFEST_CRL_LOCATION);
        assertTrue(result.hasFailureForLocation(expectedRootCrlErrorLocation));
        assertEquals(ValidationString.VALIDATOR_FILE_CONTENT,result.getFailures(expectedRootCrlErrorLocation).get(0).getKey());
    }

    @Test
    public void shouldRejectCrlWithoutManifestEntry() {
        X509Crl crlFromRepository = getRootCrl();
        expect(rsyncFetcher.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result)).andReturn(crlFromRepository);

        ManifestCms manifestFromRsync = getRootManifestCms();
        expect(rsyncFetcher.getManifest(rootContext.getManifestURI(), rootContext, result)).andReturn(manifestFromRsync);
        replayMocks();

        result.setLocation(new ValidationLocation(ROOT_MANIFEST_CRL_LOCATION));
        X509Crl crlActual = subject.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result);

        verifyMocks();
        assertNull(crlActual);
        ValidationLocation expectedRootCrlErrorLocation = new ValidationLocation(ROOT_MANIFEST_CRL_LOCATION);
        assertTrue(result.hasFailureForLocation(expectedRootCrlErrorLocation));
        assertEquals(ValidationString.VALIDATOR_MANIFEST_DOES_NOT_CONTAIN_FILE, result.getFailures(expectedRootCrlErrorLocation).get(0).getKey());
    }

    @Test
    public void shouldRejectCrlWhenManifestInvalid() {
        X509Crl crlFromRepository = getRootCrl();
        expect(rsyncFetcher.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result)).andReturn(crlFromRepository);

        ManifestCms manifestFromRsync = getFutureDatedManifestCms();
        expect(rsyncFetcher.getManifest(rootContext.getManifestURI(), rootContext, result)).andReturn(manifestFromRsync);
        replayMocks();

        result.setLocation(new ValidationLocation(ROOT_MANIFEST_CRL_LOCATION));
        X509Crl crlActual = subject.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result);

        verifyMocks();
        assertNull(crlActual);
        assertEquals(new ValidationLocation(ROOT_MANIFEST_CRL_LOCATION), result.getCurrentLocation());
        assertTrue(result.hasFailureForCurrentLocation());
    }

    @Test
    public void shouldRejectInvalidCrl() {
        result.setLocation(new ValidationLocation(ROOT_CERTIFICATE_LOCATION));

        X509Crl crlFromRepository = getRootCrlWithInvalidSignature();
        expect(rsyncFetcher.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result)).andReturn(crlFromRepository);

        ManifestCms manifestFromRsync = getRootManifestCmsWithEntry("bar space.crl", crlFromRepository.getEncoded());
        expect(rsyncFetcher.getManifest(rootContext.getManifestURI(), rootContext, result)).andReturn(manifestFromRsync);


        replayMocks();
        X509Crl crlValidated = subject.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result);
        verifyMocks();

        assertNull(crlValidated);
        ValidationLocation rootManifestCrlValidationLocation = new ValidationLocation(ROOT_MANIFEST_CRL_LOCATION);
        assertTrue(result.hasFailureForLocation(rootManifestCrlValidationLocation));
        assertTrue(ValidationString.CRL_SIGNATURE_VALID.equals(result.getFailures(rootManifestCrlValidationLocation).get(0).getKey()));
    }

    @Test
    public void shouldReturnNullForCrlWhenCrlNotReturnedFromRsync() {
        result.setLocation(new ValidationLocation(ROOT_CERTIFICATE_LOCATION));

        X509Crl crlFromRepository = null;
        expect(rsyncFetcher.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result)).andReturn(crlFromRepository);

        replayMocks();
        X509Crl crlValidated = subject.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result);
        verifyMocks();

        assertNull(crlValidated);
    }

    @Test
    public void shouldGetManifestHappyFlow() {

        ManifestCms cmsExpected = getRootManifestCms();
        X509Crl crlFromRepository = getRootCrl();

        expect(rsyncFetcher.getManifest(ROOT_SIA_MANIFEST_RSYNC_LOCATION, rootContext, result)).andReturn(cmsExpected);
        expect(decorator.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result)).andReturn(crlFromRepository);

        replayMocks();
        ManifestCms cmsActual = subject.getManifest(ROOT_SIA_MANIFEST_RSYNC_LOCATION, rootContext, result);
        verifyMocks();

        assertEquals(cmsExpected, cmsActual);
    }

    @Test
    public void shouldRejectInvalidManifest() {
        ManifestCms cmsReturnedByRsyncFetcher = getFutureDatedManifestCms();
        X509Crl crlFromRepository = getRootCrl();

        expect(rsyncFetcher.getManifest(ROOT_SIA_MANIFEST_RSYNC_LOCATION, rootContext, result)).andReturn(cmsReturnedByRsyncFetcher);
        expect(decorator.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result)).andReturn(crlFromRepository);

        replayMocks();
        ManifestCms cmsReturnedByValidatingFetcher = subject.getManifest(ROOT_SIA_MANIFEST_RSYNC_LOCATION, rootContext, result);
        verifyMocks();

        assertNull(cmsReturnedByValidatingFetcher);
    }

    @Test
    public void shouldReturnNullForManifestWhenManifestFromRsyncIsNull() {
        ManifestCms cmsFromRsync = null;

        expect(rsyncFetcher.getManifest(ROOT_SIA_MANIFEST_RSYNC_LOCATION, rootContext, result)).andReturn(cmsFromRsync);

        replayMocks();
        ManifestCms cmsFromValidatingFetcher = subject.getManifest(ROOT_SIA_MANIFEST_RSYNC_LOCATION, rootContext, result);
        verifyMocks();

        assertNull(cmsFromValidatingFetcher);
    }


    @Test
    public void shouldGetCertificateRepositoryObjectHappyFlow() {
        Specification<byte[]> fileContentSpecification = null;
        expect(rsyncFetcher.getObject(FIRST_CHILD_CERTIFICATE_LOCATION, rootContext, fileContentSpecification, result)).andReturn(childCertificate);
        expect(decorator.getCrl(ROOT_MANIFEST_CRL_LOCATION, rootContext, result)).andReturn(getRootCrl());

        replayMocks();
        CertificateRepositoryObject certificateFromValidatingFetcher = subject.getObject(FIRST_CHILD_CERTIFICATE_LOCATION, rootContext, fileContentSpecification, result);
        verifyMocks();

        assertTrue(certificateFromValidatingFetcher instanceof X509ResourceCertificate);
        assertSame(certificateFromValidatingFetcher, childCertificate);
    }

    @Test
    public void shouldNotGetCrlWhenValidatingRootCertificate() {
        Specification<byte[]> fileContentSpecification = null;
        expect(rsyncFetcher.getObject(ROOT_CERTIFICATE_LOCATION, rootContext, fileContentSpecification, result)).andReturn(rootCertificate);

        replayMocks();
        CertificateRepositoryObject certificateFromValidatingFetcher = subject.getObject(ROOT_CERTIFICATE_LOCATION, rootContext, fileContentSpecification, result);
        verifyMocks();

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
        expect(rsyncFetcher.getObject(SECOND_CHILD_CERTIFICATE_LOCATION, context, fileContentSpecification, result)).andReturn(grandchildCertificate);
        expect(decorator.getCrl(FIRST_CHILD_MANIFEST_CRL_LOCATION, context, result)).andReturn(crl);

        replayMocks();
        CertificateRepositoryObject certificateFromValidatingFetcher = subject.getObject(SECOND_CHILD_CERTIFICATE_LOCATION, context, fileContentSpecification, result);
        verifyMocks();

        assertTrue(certificateFromValidatingFetcher instanceof X509ResourceCertificate);
        assertSame(certificateFromValidatingFetcher, grandchildCertificate);
    }

    @Test
    public void shouldRejectInvalidCertificateRepositoryObject() {
        Specification<byte[]> fileContentSpecification = null;
        expect(rsyncFetcher.getObject(ROOT_CERTIFICATE_LOCATION, rootContext, fileContentSpecification, result)).andReturn(RepositoryObjectsSetUpHelper.getExpiredRootResourceCertificate());

        replayMocks();
        CertificateRepositoryObject certificateFromValidatingFetcher = subject.getObject(ROOT_CERTIFICATE_LOCATION, rootContext, fileContentSpecification, result);
        verifyMocks();

        assertNull(certificateFromValidatingFetcher);
        ValidationLocation rootCertValidationLocation = new ValidationLocation(ROOT_CERTIFICATE_LOCATION);
        assertTrue(result.hasFailureForLocation(rootCertValidationLocation));
        assertTrue(ValidationString.NOT_VALID_AFTER.equals(result.getFailures(rootCertValidationLocation).get(0).getKey()));
    }

    @Test
    public void shouldReturnNullForCROWhenCRONotReturnedFromRsync() {
        Specification<byte[]> fileContentSpecification = null;
        expect(rsyncFetcher.getObject(ROOT_CERTIFICATE_LOCATION, rootContext, fileContentSpecification, result)).andReturn(null);

        replayMocks();
        CertificateRepositoryObject certificateFromValidatingFetcher = subject.getObject(ROOT_CERTIFICATE_LOCATION, rootContext, fileContentSpecification, result);
        verifyMocks();

        assertNull(certificateFromValidatingFetcher);
    }


    private void verifyMocks() {
        verify(rsyncFetcher);
        verify(decorator);
    }

    private void replayMocks() {
        replay(rsyncFetcher);
        replay(decorator);
    }
}
