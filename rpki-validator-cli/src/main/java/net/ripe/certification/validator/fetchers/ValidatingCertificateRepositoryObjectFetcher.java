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

import java.io.File;
import java.net.URI;

import net.ripe.commons.certification.CertificateRepositoryObject;
import net.ripe.commons.certification.cms.manifest.ManifestCms;
import net.ripe.commons.certification.crl.CrlLocator;
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.util.Specification;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.ValidationString;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;

import static  net.ripe.commons.certification.validation.ValidationString.VALIDATOR_INTERNAL_ERROR;

import org.apache.commons.lang.Validate;
import org.apache.log4j.Logger;


public class ValidatingCertificateRepositoryObjectFetcher implements CertificateRepositoryObjectFetcher {
    
    private static final Logger log = Logger.getLogger(ValidatingCertificateRepositoryObjectFetcher.class);

    private final CertificateRepositoryObjectFetcher fetcher;

    private CertificateRepositoryObjectFetcher outerMostDecorator;

    /**
     * A validating CROFetcher. All objects retrieved are being validated. Invalid objects result in
     * null values being returned instead. Note that validation requires a CrlLocator. Because other
     * decorating CROFetchers are likely to be used (notifying, caching) a setter is provided to
     * allow for the outermost decorator to be used for the CRL retrieval.
     */
    public ValidatingCertificateRepositoryObjectFetcher(CertificateRepositoryObjectFetcher fetcher) {
        this.fetcher = fetcher;
        this.outerMostDecorator = this;
    }

    /**
     * Set the outermost decorator which will be used as the CrlLocator for validation
     */
    public void setOuterMostDecorator(CertificateRepositoryObjectFetcher outerMostDecorator) {
        this.outerMostDecorator = outerMostDecorator;
    }

    @Override
    public X509Crl getCrl(URI uri, CertificateRepositoryObjectValidationContext context, ValidationResult result) {
        Validate.notNull(context);
        Validate.notNull(result);
        Validate.notNull(uri);

        /*
         * Three step process:
         * - Get the CRL and validate it ignoring hash for content
         * - Get its manifest and validate the manifest based on this CRL
         * - Re-validate the CRL for its hash
         */

        // 1: Get the CRL without hash validation
        X509Crl crl = fetcher.getCrl(uri, context, result);
        if (crl == null) {
            return null;
        }
        crl = (X509Crl) processCertificateRepositoryObject(uri, context, result, crl);

        // 2: Get the manifest and validate it based on this CRL
        ManifestCms manifest = getManifestValidatedForCrl(uri, context, result, crl);
        result.isTrue(manifest != null, ValidationString.CRL_MANIFEST_VALID);
        if (manifest == null) {
            return null;
        }

        // 3: Re-validate the hash for this CRL
        checkHashValueForCrl(uri, result, crl, manifest);
        if (result.hasFailureForCurrentLocation()) {
            return null;
        }

        return crl;
    }


    @Override
    public ManifestCms getManifest(URI uri, CertificateRepositoryObjectValidationContext context, ValidationResult result) {
        Validate.notNull(context);
        Validate.notNull(result);

        try{
            ManifestCms manifestCms = fetcher.getManifest(uri, context, result);
            return (ManifestCms) processCertificateRepositoryObject(uri, context, result, manifestCms);
        } catch (Exception e) {
            log.error("There was an exception trying to get manifest: " + uri.toString(), e);
            result.isTrue(false, VALIDATOR_INTERNAL_ERROR);
            return null;
        }

    }

    @Override
    public CertificateRepositoryObject getObject(URI uri, CertificateRepositoryObjectValidationContext context,
            Specification<byte[]> fileContentSpecification, ValidationResult result) {
        Validate.notNull(context);
        Validate.notNull(result);

        try {
        CertificateRepositoryObject certificateRepositoryObject = fetcher.getObject(uri, context, fileContentSpecification, result);
        return processCertificateRepositoryObject(uri, context, result, certificateRepositoryObject);
        } catch (Exception e) {
            log.error("There was an exception trying to get object for uri: " + uri.toString(), e);
            result.isTrue(false, VALIDATOR_INTERNAL_ERROR);
            return null;
        }
    }

    @Override
    public void prefetch(URI uri, ValidationResult result) {
        fetcher.prefetch(uri, result);
    }

    private CertificateRepositoryObject processCertificateRepositoryObject(URI uri, CertificateRepositoryObjectValidationContext context,
            ValidationResult result, CertificateRepositoryObject certificateRepositoryObject) {
        if (certificateRepositoryObject == null) {
            return null;
        }
        certificateRepositoryObject.validate(uri.toString(), context, outerMostDecorator, result);
        if (result.hasFailureForCurrentLocation()) {
            return null;
        }
        return certificateRepositoryObject;
    }


    private void checkHashValueForCrl(URI uri, ValidationResult result, X509Crl crl, ManifestCms manifest) {
        String crlFileName = new File(uri.getRawPath()).getName();

        // FIXME: is this really the right way to go with error locations?
        //        this way the manifest check error does end up with the CRL which I believe is right..
        result.setLocation(uri.toString());
        result.isTrue(manifest.containsFile(crlFileName), ValidationString.VALIDATOR_MANIFEST_DOES_NOT_CONTAIN_FILE, crlFileName);
        if (result.hasFailureForCurrentLocation()) {
            return;
        }
        result.isTrue(manifest.verifyFileContents(crlFileName, crl.getEncoded()), ValidationString.VALIDATOR_FILE_CONTENT);
    }


    private ManifestCms getManifestValidatedForCrl(URI crlUri, CertificateRepositoryObjectValidationContext context, ValidationResult result, X509Crl crl) {
        String savedCurrentLocation = result.getCurrentLocation();
        result.setLocation(context.getManifestURI());
        try {
            ManifestCms manifest = fetcher.getManifest(context.getManifestURI(), context, result);
            if (manifest == null) {
                return null;
            }

            final X509Crl crlForCrlLocator = crl;
            final URI expectedURIforCrlLocator = crlUri;

            manifest.validate(context.getManifestURI().toString(), context, new CrlLocator() {

                @Override
                public X509Crl getCrl(URI uri, CertificateRepositoryObjectValidationContext context, ValidationResult result) {
                    Validate.isTrue(uri.equals(expectedURIforCrlLocator));
                    return crlForCrlLocator;
                }

            }, result);
            if (result.hasFailureForCurrentLocation()) {
                return null;
            }
            return manifest;
        } finally {
            result.setLocation(savedCurrentLocation);
        }
    }

}
