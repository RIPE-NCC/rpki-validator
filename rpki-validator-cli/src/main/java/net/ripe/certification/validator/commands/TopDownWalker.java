package net.ripe.certification.validator.commands;

import java.net.URI;
import java.util.LinkedList;
import java.util.Queue;

import net.ripe.certification.validator.fetchers.CertificateRepositoryObjectFetcher;
import net.ripe.commons.certification.CertificateRepositoryObject;
import net.ripe.commons.certification.cms.manifest.ManifestCms;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;

import org.apache.commons.lang.Validate;

public class TopDownWalker {

    private final CertificateRepositoryObjectFetcher certificateRepositoryObjectFetcher;
    private final TopDownWalkerWorkQueue workQueue;
    private final ValidationResult validationResult;

    public TopDownWalker(CertificateRepositoryObjectFetcher certificateRepositoryObjectFetcher) {
    	this(new LinkedList<CertificateRepositoryObjectValidationContext>(), certificateRepositoryObjectFetcher);
    }

    public TopDownWalker(Queue<CertificateRepositoryObjectValidationContext> workQueue, CertificateRepositoryObjectFetcher certificateRepositoryObjectFetcher) {
    	this.certificateRepositoryObjectFetcher = certificateRepositoryObjectFetcher;
    	this.workQueue = new TopDownWalkerWorkQueue(workQueue);
        this.validationResult = new ValidationResult();
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
        validationResult.push(repositoryURI);
        certificateRepositoryObjectFetcher.prefetch(repositoryURI, validationResult);
    }

    void processManifest(CertificateRepositoryObjectValidationContext context) {
        URI manifestURI = context.getManifestURI();
    	ManifestCms manifestCms = fetchManifest(manifestURI, context);
    	if (manifestCms != null) {
    		processManifestFiles(context, manifestCms);
    	}
    }

    ManifestCms fetchManifest(URI manifestURI, CertificateRepositoryObjectValidationContext context) {
        validationResult.push(manifestURI);
        return certificateRepositoryObjectFetcher.getManifest(manifestURI, context, validationResult);
    }

    void processManifestFiles(CertificateRepositoryObjectValidationContext context, ManifestCms manifestCms) {
        URI repositoryURI = context.getRepositoryURI();
        for (String fileName: manifestCms.getFileNames()) {
			processManifestEntry(manifestCms, context, repositoryURI, fileName);
        }
    }

    void processManifestEntry(ManifestCms manifestCms, CertificateRepositoryObjectValidationContext context, URI repositoryURI, String fileName) {
        URI uri = repositoryURI.resolve(fileName);
        validationResult.push(uri);
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
