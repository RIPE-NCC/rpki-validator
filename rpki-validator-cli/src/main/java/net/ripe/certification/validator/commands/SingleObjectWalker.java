package net.ripe.certification.validator.commands;

import static net.ripe.commons.certification.validation.ValidationString.*;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import net.ripe.certification.validator.fetchers.CertificateRepositoryObjectFetcher;
import net.ripe.certification.validator.fetchers.NotifyingCertificateRepositoryObjectFetcher;
import net.ripe.commons.certification.CertificateRepositoryObject;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.ValidationString;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.utils.Specifications;


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
            result.push(parentURI.toString());
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
        result.push(rootURI);
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
