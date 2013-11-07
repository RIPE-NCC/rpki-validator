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

import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationString;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.rpki.validator.fetchers.CertificateRepositoryObjectFetcher;
import org.apache.commons.lang.Validate;

import java.net.URI;
import java.util.LinkedList;
import java.util.Queue;

public class TopDownWalker {

    private final CertificateRepositoryObjectFetcher certificateRepositoryObjectFetcher;
    private final TopDownWalkerWorkQueue workQueue;
    private final ValidationResult validationResult;

    public TopDownWalker(CertificateRepositoryObjectFetcher certificateRepositoryObjectFetcher) {
        this(new LinkedList<CertificateRepositoryObjectValidationContext>(), certificateRepositoryObjectFetcher, ValidationResult.withLocation("n/a"));
    }

    public TopDownWalker(CertificateRepositoryObjectFetcher certificateRepositoryObjectFetcher, ValidationResult validationResult) {
        this(new LinkedList<CertificateRepositoryObjectValidationContext>(), certificateRepositoryObjectFetcher, validationResult);
    }

    /**
     * Convenience constructor for unit testing, allowing injection of the work queue
     */
    TopDownWalker(Queue<CertificateRepositoryObjectValidationContext> workQueue, CertificateRepositoryObjectFetcher certificateRepositoryObjectFetcher, ValidationResult validationResult) {
        this.certificateRepositoryObjectFetcher = certificateRepositoryObjectFetcher;
        this.workQueue = new TopDownWalkerWorkQueue(workQueue);
        this.validationResult = validationResult;
    }

    public void addTrustAnchor(CertificateRepositoryObjectValidationContext trustAnchor) {
        Validate.isTrue(trustAnchor.getCertificate().isObjectIssuer(), "trust anchor must be an object issuer");
        workQueue.add(trustAnchor);
    }

    public void execute() {
        while (!workQueue.isEmpty()) {
            CertificateRepositoryObjectValidationContext context = workQueue.remove();
            prefetch(context);
            processManifest(context);
        }
    }

    void prefetch(CertificateRepositoryObjectValidationContext context) {
        URI repositoryURI = context.getRepositoryURI();
        if (repositoryURI != null) {
            validationResult.setLocation(new ValidationLocation(repositoryURI));
            certificateRepositoryObjectFetcher.prefetch(repositoryURI, validationResult);
        }
    }

    void processManifest(CertificateRepositoryObjectValidationContext context) {
        URI manifestURI = context.getManifestURI();
        ManifestCms manifestCms = fetchManifest(manifestURI, context);
        if (manifestCms != null) {
            processManifestFiles(context, manifestCms);
        }
    }

    ManifestCms fetchManifest(URI manifestURI, CertificateRepositoryObjectValidationContext context) {
        validationResult.setLocation(new ValidationLocation(manifestURI));
        try {
            return certificateRepositoryObjectFetcher.getManifest(manifestURI, context, validationResult);
        } catch (RuntimeException e) {
            validationResult.error(ValidationString.VALIDATOR_OBJECT_PROCESSING_EXCEPTION, manifestURI.toString());
            return null;
        }
    }

    void processManifestFiles(CertificateRepositoryObjectValidationContext context, ManifestCms manifestCms) {
        URI repositoryURI = context.getRepositoryURI();
        for (String fileName: manifestCms.getFileNames()) {
            try {
                processManifestEntry(manifestCms, context, repositoryURI, fileName);
            } catch (RuntimeException e) {
                validationResult.error(ValidationString.VALIDATOR_OBJECT_PROCESSING_EXCEPTION, repositoryURI.resolve(fileName).toString());
            }
        }
    }

    void processManifestEntry(ManifestCms manifestCms, CertificateRepositoryObjectValidationContext context, URI repositoryURI, String fileName) {
        URI uri = repositoryURI.resolve(fileName);
        validationResult.setLocation(new ValidationLocation(uri));
        CertificateRepositoryObject object = certificateRepositoryObjectFetcher.getObject(uri, context, manifestCms.getFileContentSpecification(fileName), validationResult);
        addToWorkQueueIfObjectIssuer(context, uri, object);
    }

    void addToWorkQueueIfObjectIssuer(CertificateRepositoryObjectValidationContext context, URI objectURI, CertificateRepositoryObject object) {
        if (object instanceof X509ResourceCertificate) {
            X509ResourceCertificate childCertificate = (X509ResourceCertificate) object;
            if (childCertificate.isObjectIssuer()) {
                workQueue.add(context.createChildContext(objectURI, childCertificate));
            }
        }
    }

}
