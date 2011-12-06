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

import static net.ripe.commons.certification.validation.ValidationString.*;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import net.ripe.certification.validator.fetchers.CertificateRepositoryObjectFetcher;
import net.ripe.certification.validator.fetchers.NotifyingCertificateRepositoryObjectFetcher;
import net.ripe.commons.certification.CertificateRepositoryObject;
import net.ripe.commons.certification.util.Specifications;
import net.ripe.commons.certification.validation.ValidationLocation;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.ValidationString;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;


/**
 * Validation implementation for single objects (certificates, ROAs, manifests).
 *
 * The mechanics are as follows:
 * - First build up the certificate chain bottom-up
 * - Then validate the complete chain top-down, similar to top-down walker, but.. only one path
 * - For now: skip manifest validation
 */
public class SingleObjectWalker {

	private static final int MAX_CHAIN_LENGTH = 30;

    private CertificateRepositoryObject startingPoint;
    private URI startingPointUri;

    private CertificateRepositoryObjectFetcher chainBuildFetcher;
    private NotifyingCertificateRepositoryObjectFetcher.FetchNotificationCallback chainBuildLogger;
    private CertificateRepositoryObjectFetcher validationFetcher;
    private List<URI> parentCertificateChain = new ArrayList<URI>();
    private ValidationResult result = new ValidationResult();

    public SingleObjectWalker(CertificateRepositoryObject startingPoint, URI startingPointUri, CertificateRepositoryObjectFetcher chainBuildFetcher, NotifyingCertificateRepositoryObjectFetcher.FetchNotificationCallback chainBuildLogger, CertificateRepositoryObjectFetcher validationFetcher) {
        this.startingPoint = startingPoint;
        this.startingPointUri = startingPointUri;
        this.chainBuildFetcher = chainBuildFetcher;
        this.chainBuildLogger = chainBuildLogger;
        this.validationFetcher = validationFetcher;
    }

    /**
     * Use for unit testing only
     * @deprecated
     */
    void setParentCertificateChain(List<URI> certificateChain) {
        this.parentCertificateChain = certificateChain;
    }

    /**
     * Use for unit testing only
     * @deprecated
     */
    void setValidationResult(ValidationResult result) {
        this.result = result;
    }

    public ValidationResult execute(List<CertificateRepositoryObjectValidationContext> trustAnchors) {
    	buildUpChain();
    	if (result.hasFailures() ) {
    		return result;
    	}

    	validateTrustAnchor(trustAnchors);
    	if (result.hasFailures() ) {
    		return result;
    	}

    	validateChain();
    	return result;
	}

    /**
     * Build up a chain of objects (typically the object under test and its parent
     * certificate chain) without validating anything.
     */
    void buildUpChain() {
        URI parentURI = startingPoint.getParentCertificateUri();

        while(parentURI != null) {
            result.setLocation(new ValidationLocation(parentURI));
            CertificateRepositoryObject parent = chainBuildFetcher.getObject(parentURI, null, Specifications.<byte[]>alwaysTrue(), result);

            if (parent instanceof X509ResourceCertificate) {
                parentCertificateChain.add(0, parentURI);
                if (!result.isTrue(parentCertificateChain.size() <= MAX_CHAIN_LENGTH, CERT_CHAIN_LENGTH, MAX_CHAIN_LENGTH)) {
                	chainBuildLogger.afterFetchFailure(parentURI, result);
                	return; // break the chain building
                }

                URI newParentURI = parent.getParentCertificateUri();

                if (parentCertificateChain.contains(newParentURI)) {
                	result.isTrue(false, CERT_CHAIN_CIRCULAR_REFERENCE);
                	chainBuildLogger.afterFetchFailure(parentURI, result);
                	return; // break the chain building
                }
                parentURI = newParentURI;

            } else if (parent == null) {
                parentURI = null; // found TA
            } else {
                result.isTrue(false, CERT_AIA_NOT_POINTING_TO_CERT);
                chainBuildLogger.afterFetchFailure(parentURI, result);
                return; // break the chain building
            }
        }
    }

    /**
     * Verify the certificate found at the top against the specified TA(s)
     * @param trustAnchors
     */
    void validateTrustAnchor(List<CertificateRepositoryObjectValidationContext> trustAnchors) {
        URI rootURI = parentCertificateChain.get(0);
        result.setLocation(new ValidationLocation(rootURI));
        X509ResourceCertificate rootCertificate = (X509ResourceCertificate) chainBuildFetcher.getObject(rootURI, null, Specifications.<byte[]>alwaysTrue(), result);

        boolean rootCertIsTa = false;
        for (CertificateRepositoryObjectValidationContext context : trustAnchors) {
			if (context.getCertificate().equals(rootCertificate)) {
				rootCertIsTa = true;
				break;
			}
		}
        if (!result.isTrue(rootCertIsTa, ValidationString.ROOT_IS_TA)) {
        	chainBuildLogger.afterFetchFailure(rootURI, result);
        }
    }

    /**
     * Process the chain top-down
     */
    void validateChain() {
    	URI rootURI = parentCertificateChain.get(0);
    	X509ResourceCertificate rootCertificate = (X509ResourceCertificate) chainBuildFetcher.getObject(rootURI, null, Specifications.<byte[]>alwaysTrue(), result);

    	CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(rootURI, rootCertificate);
        for (URI uri: parentCertificateChain) {
            X509ResourceCertificate cert = (X509ResourceCertificate) validationFetcher.getObject(uri, context, Specifications.<byte[]>alwaysTrue(), result);
            if (cert == null) {
            	return;
            }
            context = context.createChildContext(uri, cert);
        }

        validationFetcher.getObject(startingPointUri, context, Specifications.<byte[]>alwaysTrue(), result);
    }

}
