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
package net.ripe.rpki.validator.commands;

import static net.ripe.rpki.validator.RepositoryObjectsSetUpHelper.*;
import static org.mockito.Mockito.*;
import static org.junit.Assert.*;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.util.Specification;
import net.ripe.rpki.commons.util.Specifications;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationString;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.rpki.validator.fetchers.CertificateRepositoryObjectFetcher;
import net.ripe.rpki.validator.fetchers.NotifyingCertificateRepositoryObjectFetcher;
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
    private NotifyingCertificateRepositoryObjectFetcher.Listener chainBuildLogger;



    @SuppressWarnings("deprecation")
    @Before
    public void setUp() {
        trustAnchors = new ArrayList<CertificateRepositoryObjectValidationContext>();
        trustAnchors.add(new CertificateRepositoryObjectValidationContext(ROOT_CERTIFICATE_LOCATION, root));

        chainBuildFetcher = mock(CertificateRepositoryObjectFetcher.class);
        validatingFetcher = mock(CertificateRepositoryObjectFetcher.class);
        chainBuildLogger = mock(NotifyingCertificateRepositoryObjectFetcher.Listener.class);

        subject = new SingleObjectWalker(grandChild, SECOND_CHILD_CERTIFICATE_LOCATION, chainBuildFetcher, chainBuildLogger, validatingFetcher);
        certificateChain = new ArrayList<URI>();
        subject.setParentCertificateChain(certificateChain);

        result = ValidationResult.withLocation("n/a");
        subject.setValidationResult(result);

        context = null;
        fileContentSpecification = Specifications.alwaysTrue();
    }

    @Test
    public void shouldBuildUpChain() {
        when(chainBuildFetcher.getObject(FIRST_CHILD_CERTIFICATE_LOCATION, context , fileContentSpecification, result)).thenReturn(child);
        when(chainBuildFetcher.getObject(ROOT_CERTIFICATE_LOCATION, context , fileContentSpecification, result)).thenReturn(root);

        subject.buildUpChain();

        assertEquals(2, certificateChain.size());
        assertEquals(ROOT_CERTIFICATE_LOCATION, certificateChain.get(0));
        assertEquals(FIRST_CHILD_CERTIFICATE_LOCATION, certificateChain.get(1));
        assertFalse(result.hasFailures());
    }

    @Test
    public void shouldStopBuildingChainWhenCertificateCantBeFound() {
        when(chainBuildFetcher.getObject(FIRST_CHILD_CERTIFICATE_LOCATION, context , fileContentSpecification, result)).thenReturn(null);

        subject.buildUpChain();

        assertEquals(0, certificateChain.size());
        assertFalse(result.hasFailures()); // This is up to the rsync fetcher..
    }

    @Test
    public void shouldStopBuildingChainAndComplainWhenAIAPointsToNonCertificate() {
        when(chainBuildFetcher.getObject(FIRST_CHILD_CERTIFICATE_LOCATION, context , fileContentSpecification, result)).thenReturn(getRootManifestCms());

        subject.buildUpChain();

        assertEquals(0, certificateChain.size());
        assertTrue(result.hasFailures());
        assertEquals(ValidationString.CERT_AIA_NOT_POINTING_TO_CERT, result.getFailures(new ValidationLocation(FIRST_CHILD_CERTIFICATE_LOCATION)).get(0).getKey());
        verify(chainBuildLogger).afterFetchFailure(FIRST_CHILD_CERTIFICATE_LOCATION, result);
    }

    @Test
    public void shouldStopBuildingChainAndComplainWhenCircularReferenceFound() {
        X509ResourceCertificate invalidRootCertificate = getRootResourceCertificateWithAiaFieldPointingToItself();
        when(chainBuildFetcher.getObject(FIRST_CHILD_CERTIFICATE_LOCATION, context , fileContentSpecification, result)).thenReturn(child);
        when(chainBuildFetcher.getObject(ROOT_CERTIFICATE_LOCATION, context , fileContentSpecification, result)).thenReturn(invalidRootCertificate);

        subject.buildUpChain();

        assertTrue(result.hasFailures());
        assertEquals(1, result.getFailures(new ValidationLocation(ROOT_CERTIFICATE_LOCATION)).size());
        assertEquals(ValidationString.CERT_CHAIN_CIRCULAR_REFERENCE, result.getFailures(new ValidationLocation(ROOT_CERTIFICATE_LOCATION)).get(0).getKey());
        verify(chainBuildLogger).afterFetchFailure(ROOT_CERTIFICATE_LOCATION, result);
    }

    @Test
    public void shouldVerifyTrustAnchorHappyFlow() {
        certificateChain.add(ROOT_CERTIFICATE_LOCATION);

        when(chainBuildFetcher.getObject(ROOT_CERTIFICATE_LOCATION, context , fileContentSpecification, result)).thenReturn(root);

        subject.validateTrustAnchor(trustAnchors);

        assertFalse(result.hasFailures());
    }

    @Test
    public void shouldRejectChainWithInvalidTrustAnchor() {
        certificateChain.add(ROOT_CERTIFICATE_LOCATION);

        when(chainBuildFetcher.getObject(ROOT_CERTIFICATE_LOCATION, context , fileContentSpecification, result)).thenReturn(root);

        subject.validateTrustAnchor(new ArrayList<CertificateRepositoryObjectValidationContext>());

        assertTrue(result.hasFailures());
        assertEquals(1, result.getAllValidationChecksForLocation(new ValidationLocation(ROOT_CERTIFICATE_LOCATION)).size());
        assertEquals(ValidationString.ROOT_IS_TA, result.getFailures(new ValidationLocation(ROOT_CERTIFICATE_LOCATION)).get(0).getKey());
        verify(chainBuildLogger).afterFetchFailure(ROOT_CERTIFICATE_LOCATION, result);
    }


    @Test
    public void shouldValidateChainHappyFlow() {
        certificateChain.add(ROOT_CERTIFICATE_LOCATION);
        certificateChain.add(FIRST_CHILD_CERTIFICATE_LOCATION);

        when(chainBuildFetcher.getObject(ROOT_CERTIFICATE_LOCATION, context , fileContentSpecification, result)).thenReturn(root);

        when(validatingFetcher.getObject(eq(ROOT_CERTIFICATE_LOCATION), isA(CertificateRepositoryObjectValidationContext.class), eq(fileContentSpecification), eq(result))).thenReturn(root);
        when(validatingFetcher.getObject(eq(FIRST_CHILD_CERTIFICATE_LOCATION),isA(CertificateRepositoryObjectValidationContext.class), eq(fileContentSpecification), eq(result))).thenReturn(child);
        when(validatingFetcher.getObject(eq(SECOND_CHILD_CERTIFICATE_LOCATION),isA(CertificateRepositoryObjectValidationContext.class), eq(fileContentSpecification), eq(result))).thenReturn(child);

        subject.validateChain();

        assertFalse(result.hasFailures());
    }

    @Test
    public void shouldValidationFailOnInvalidCertificate() {
        certificateChain.add(ROOT_CERTIFICATE_LOCATION);
        certificateChain.add(FIRST_CHILD_CERTIFICATE_LOCATION);

        CertificateRepositoryObject expiredCertificate = getExpiredRootResourceCertificate();
        when(chainBuildFetcher.getObject(ROOT_CERTIFICATE_LOCATION, context , fileContentSpecification, result)).thenReturn(expiredCertificate);

        when(validatingFetcher.getObject(eq(ROOT_CERTIFICATE_LOCATION), isA(CertificateRepositoryObjectValidationContext.class), eq(fileContentSpecification), eq(result))).thenReturn(null);

        subject.validateChain();

        assertFalse(result.hasFailures());
    }

    @Test
    public void shouldDoCompleteTestHappyFlow() {
        // build up
        when(chainBuildFetcher.getObject(FIRST_CHILD_CERTIFICATE_LOCATION, context , fileContentSpecification, result)).thenReturn(child);
        when(chainBuildFetcher.getObject(ROOT_CERTIFICATE_LOCATION, context , fileContentSpecification, result)).thenReturn(root);

        // trust anchor
        when(chainBuildFetcher.getObject(ROOT_CERTIFICATE_LOCATION, context , fileContentSpecification, result)).thenReturn(root);

        // validation
        when(chainBuildFetcher.getObject(ROOT_CERTIFICATE_LOCATION, context , fileContentSpecification, result)).thenReturn(root);
        when(validatingFetcher.getObject(eq(ROOT_CERTIFICATE_LOCATION), isA(CertificateRepositoryObjectValidationContext.class), eq(fileContentSpecification), eq(result))).thenReturn(root);
        when(validatingFetcher.getObject(eq(FIRST_CHILD_CERTIFICATE_LOCATION),isA(CertificateRepositoryObjectValidationContext.class), eq(fileContentSpecification), eq(result))).thenReturn(child);
        when(validatingFetcher.getObject(eq(SECOND_CHILD_CERTIFICATE_LOCATION),isA(CertificateRepositoryObjectValidationContext.class), eq(fileContentSpecification), eq(result))).thenReturn(child);

        subject.execute(trustAnchors);

        assertFalse(result.hasFailures());
    }

}
