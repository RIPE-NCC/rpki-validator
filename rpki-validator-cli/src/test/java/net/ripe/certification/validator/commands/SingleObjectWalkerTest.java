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
package net.ripe.certification.validator.commands;

import static net.ripe.certification.validator.RepositoryObjectsSetUpHelper.*;

import static org.junit.Assert.*;

import static org.easymock.EasyMock.*;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import net.ripe.certification.validator.fetchers.CertificateRepositoryObjectFetcher;
import net.ripe.certification.validator.fetchers.NotifyingCertificateRepositoryObjectFetcher;
import net.ripe.commons.certification.CertificateRepositoryObject;
import net.ripe.commons.certification.util.Specification;
import net.ripe.commons.certification.util.Specifications;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.ValidationString;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;

import org.junit.Before;
import org.junit.Test;



public class SingleObjectWalkerTest {

    SingleObjectWalker subject;
    private X509ResourceCertificate root = getRootResourceCertificate();
    private X509ResourceCertificate child = getChildResourceCertificate();
    private X509ResourceCertificate grandChild = getSecondChildResourceCertificate();
    private ArrayList<URI> certificateChain;
    private CertificateRepositoryObjectFetcher chainBuildFetcher;
    private CertificateRepositoryObjectFetcher validatingFetcher;
    private ValidationResult result;
    private CertificateRepositoryObjectValidationContext context;
    private Specification<byte[]> fileContentSpecification;
    private List<CertificateRepositoryObjectValidationContext> trustAnchors;
	private NotifyingCertificateRepositoryObjectFetcher.FetchNotificationCallback chainBuildLogger;



    @SuppressWarnings("deprecation")
    @Before
    public void setUp() {
        trustAnchors = new ArrayList<CertificateRepositoryObjectValidationContext>();
        trustAnchors.add(new CertificateRepositoryObjectValidationContext(ROOT_CERTIFICATE_LOCATION, root));

        chainBuildFetcher = createMock(CertificateRepositoryObjectFetcher.class);
        validatingFetcher = createMock(CertificateRepositoryObjectFetcher.class);
        chainBuildLogger = createMock(NotifyingCertificateRepositoryObjectFetcher.FetchNotificationCallback.class);

        subject = new SingleObjectWalker(grandChild, SECOND_CHILD_CERTIFICATE_LOCATION, chainBuildFetcher, chainBuildLogger, validatingFetcher);
        certificateChain = new ArrayList<URI>();
        subject.setParentCertificateChain(certificateChain);

        result = new ValidationResult();
        subject.setValidationResult(result);

        context = null;
        fileContentSpecification = Specifications.<byte[]>alwaysTrue();
    }

    @Test
    public void shouldBuildUpChain() {

        expect(chainBuildFetcher.getObject(FIRST_CHILD_CERTIFICATE_LOCATION, context , fileContentSpecification, result)).andReturn(child);
        expect(chainBuildFetcher.getObject(ROOT_CERTIFICATE_LOCATION, context , fileContentSpecification, result)).andReturn(root);

        replayMocks();
        subject.buildUpChain();
        verifyMocks();

        assertEquals(2, certificateChain.size());
        assertEquals(ROOT_CERTIFICATE_LOCATION, certificateChain.get(0));
        assertEquals(FIRST_CHILD_CERTIFICATE_LOCATION, certificateChain.get(1));
        assertFalse(result.hasFailures());
    }

    @Test
    public void shouldStopBuildingChainWhenCertificateCantBeFound() {
        expect(chainBuildFetcher.getObject(FIRST_CHILD_CERTIFICATE_LOCATION, context , fileContentSpecification, result)).andReturn(null);

        replayMocks();
        subject.buildUpChain();
        verifyMocks();

        assertEquals(0, certificateChain.size());
        assertFalse(result.hasFailures()); // This is up to the rsync fetcher..
    }

    @Test
    public void shouldStopBuildingChainAndComplainWhenAIAPointsToNonCertificate() {
        expect(chainBuildFetcher.getObject(FIRST_CHILD_CERTIFICATE_LOCATION, context , fileContentSpecification, result)).andReturn(getRootManifestCms());
        chainBuildLogger.afterFetchFailure(FIRST_CHILD_CERTIFICATE_LOCATION, result);

        replayMocks();
        subject.buildUpChain();
        verifyMocks();

        assertEquals(0, certificateChain.size());
        assertTrue(result.hasFailures());
        assertEquals(ValidationString.CERT_AIA_NOT_POINTING_TO_CERT, result.getFailures(FIRST_CHILD_CERTIFICATE_LOCATION.toString()).get(0).getKey());
    }

    @Test
    public void shouldStopBuildingChainAndComplainWhenCircularReferenceFound() {
    	X509ResourceCertificate invalidRootCertificate = getRootResourceCertificateWithAiaFieldPointingToItself();
    	expect(chainBuildFetcher.getObject(FIRST_CHILD_CERTIFICATE_LOCATION, context , fileContentSpecification, result)).andReturn(child);
        expect(chainBuildFetcher.getObject(ROOT_CERTIFICATE_LOCATION, context , fileContentSpecification, result)).andReturn(invalidRootCertificate);
        chainBuildLogger.afterFetchFailure(ROOT_CERTIFICATE_LOCATION, result);


    	replayMocks();
    	subject.buildUpChain();
    	verifyMocks();

    	assertTrue(result.hasFailures());
    	assertEquals(1, result.getFailures(ROOT_CERTIFICATE_LOCATION.toString()).size());
    	assertEquals(ValidationString.CERT_CHAIN_CIRCULAR_REFERENCE, result.getFailures(ROOT_CERTIFICATE_LOCATION.toString()).get(0).getKey());
    }

    @Test
    public void shouldVerifyTrustAnchorHappyFlow() {
    	certificateChain.add(ROOT_CERTIFICATE_LOCATION);

        expect(chainBuildFetcher.getObject(ROOT_CERTIFICATE_LOCATION, context , fileContentSpecification, result)).andReturn(root);

        replayMocks();
        subject.validateTrustAnchor(trustAnchors);
        verifyMocks();

        assertFalse(result.hasFailures());
    }

    @Test
    public void shouldRejectChainWithInvalidTrustAnchor() {
    	certificateChain.add(ROOT_CERTIFICATE_LOCATION);

        expect(chainBuildFetcher.getObject(ROOT_CERTIFICATE_LOCATION, context , fileContentSpecification, result)).andReturn(root);
        chainBuildLogger.afterFetchFailure(ROOT_CERTIFICATE_LOCATION, result);

        replayMocks();
        subject.validateTrustAnchor(new ArrayList<CertificateRepositoryObjectValidationContext>());
        verifyMocks();

        assertTrue(result.hasFailures());
        assertEquals(1, result.getResults(ROOT_CERTIFICATE_LOCATION.toString()).size());
        assertEquals(ValidationString.ROOT_IS_TA, result.getFailures(ROOT_CERTIFICATE_LOCATION.toString()).get(0).getKey());
    }


    @Test
    public void shouldValidateChainHappyFlow() {
    	certificateChain.add(ROOT_CERTIFICATE_LOCATION);
    	certificateChain.add(FIRST_CHILD_CERTIFICATE_LOCATION);

    	expect(chainBuildFetcher.getObject(ROOT_CERTIFICATE_LOCATION, context , fileContentSpecification, result)).andReturn(root);

        expect(validatingFetcher.getObject(eq(ROOT_CERTIFICATE_LOCATION), isA(CertificateRepositoryObjectValidationContext.class), eq(fileContentSpecification), eq(result))).andReturn(root);
        expect(validatingFetcher.getObject(eq(FIRST_CHILD_CERTIFICATE_LOCATION),isA(CertificateRepositoryObjectValidationContext.class), eq(fileContentSpecification), eq(result))).andReturn(child);
        expect(validatingFetcher.getObject(eq(SECOND_CHILD_CERTIFICATE_LOCATION),isA(CertificateRepositoryObjectValidationContext.class), eq(fileContentSpecification), eq(result))).andReturn(child);

        replayMocks();
        subject.validateChain();
        verifyMocks();

        assertFalse(result.hasFailures());
    }

    @Test
    public void shouldValidationFailOnInvalidCertificate() {
    	certificateChain.add(ROOT_CERTIFICATE_LOCATION);
    	certificateChain.add(FIRST_CHILD_CERTIFICATE_LOCATION);

    	CertificateRepositoryObject expiredCertificate = getExpiredRootResourceCertificate();
		expect(chainBuildFetcher.getObject(ROOT_CERTIFICATE_LOCATION, context , fileContentSpecification, result)).andReturn(expiredCertificate);

    	expect(validatingFetcher.getObject(eq(ROOT_CERTIFICATE_LOCATION), isA(CertificateRepositoryObjectValidationContext.class), eq(fileContentSpecification), eq(result))).andReturn(null);

    	replayMocks();
    	subject.validateChain();
    	verifyMocks();

    	assertFalse(result.hasFailures());
    }

    @Test
    public void shouldDoCompleteTestHappyFlow() {

    	// build up
        expect(chainBuildFetcher.getObject(FIRST_CHILD_CERTIFICATE_LOCATION, context , fileContentSpecification, result)).andReturn(child);
        expect(chainBuildFetcher.getObject(ROOT_CERTIFICATE_LOCATION, context , fileContentSpecification, result)).andReturn(root);

        // trust anchor
        expect(chainBuildFetcher.getObject(ROOT_CERTIFICATE_LOCATION, context , fileContentSpecification, result)).andReturn(root);

        // validation
    	expect(chainBuildFetcher.getObject(ROOT_CERTIFICATE_LOCATION, context , fileContentSpecification, result)).andReturn(root);
        expect(validatingFetcher.getObject(eq(ROOT_CERTIFICATE_LOCATION), isA(CertificateRepositoryObjectValidationContext.class), eq(fileContentSpecification), eq(result))).andReturn(root);
        expect(validatingFetcher.getObject(eq(FIRST_CHILD_CERTIFICATE_LOCATION),isA(CertificateRepositoryObjectValidationContext.class), eq(fileContentSpecification), eq(result))).andReturn(child);
        expect(validatingFetcher.getObject(eq(SECOND_CHILD_CERTIFICATE_LOCATION),isA(CertificateRepositoryObjectValidationContext.class), eq(fileContentSpecification), eq(result))).andReturn(child);


    	replayMocks();
    	subject.execute(trustAnchors);
    	verifyMocks();

    	assertFalse(result.hasFailures());
    }



    private void replayMocks() {
        replay(chainBuildFetcher);
        replay(chainBuildLogger);
        replay(validatingFetcher);
    }

    private void verifyMocks() {
        verify(chainBuildFetcher);
        verify(chainBuildLogger);
        verify(validatingFetcher);
    }
}
