package net.ripe.certification.validator.fetchers;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import net.ripe.commons.certification.CertificateRepositoryObject;
import net.ripe.commons.certification.cms.manifest.ManifestCms;
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.utils.Specification;

/**
 * Caches the results from fetching objects using another {@link CertificateRepositoryObjectFetcher}.
 */
public class CachingCertificateRepositoryObjectFetcher implements CertificateRepositoryObjectFetcher {

    private final Map<URI, CertificateRepositoryObject> objectCache = new HashMap<URI, CertificateRepositoryObject>();
    private final Map<URI, ManifestCms> manifestCache = new HashMap<URI, ManifestCms>();
    private final Map<URI, X509Crl> crlCache = new HashMap<URI, X509Crl>();

    private final CertificateRepositoryObjectFetcher fetcher;

    public CachingCertificateRepositoryObjectFetcher(CertificateRepositoryObjectFetcher fetcher) {
        this.fetcher = fetcher;
    }

    @Override
    public X509Crl getCrl(URI uri, CertificateRepositoryObjectValidationContext context, ValidationResult result) {
        if (crlCache.containsKey(uri)) {
            return crlCache.get(uri);
        }
        X509Crl crl = fetcher.getCrl(uri, context, result);
        updateCache(uri, crl);
        return crl;
    }

    @Override
    public ManifestCms getManifest(URI uri, CertificateRepositoryObjectValidationContext context, ValidationResult result) {
        if (manifestCache.containsKey(uri)) {
            return manifestCache.get(uri);
        }
        ManifestCms manifest = fetcher.getManifest(uri, context, result);
        updateCache(uri, manifest);
        return manifest;
    }

    @Override
    public CertificateRepositoryObject getObject(URI uri, CertificateRepositoryObjectValidationContext context,
            Specification<byte[]> fileContentSpecification, ValidationResult result) {
        if (objectCache.containsKey(uri)) {
            return objectCache.get(uri);
        }
        CertificateRepositoryObject object = fetcher.getObject(uri, context, fileContentSpecification, result);
        updateCache(uri, object);
        return object;
    }

    @Override
    public void prefetch(URI uri, ValidationResult result) {
        fetcher.prefetch(uri, result);
    }

    public void updateCache(URI uri, CertificateRepositoryObject object) {
        objectCache.put(uri, object);
        if (object instanceof X509Crl) {
            crlCache.put(uri, (X509Crl) object);
            manifestCache.put(uri, null);
        } else if (object instanceof ManifestCms) {
            manifestCache.put(uri, (ManifestCms) object);
            crlCache.put(uri, null);
        } else {
            manifestCache.put(uri, null);
            crlCache.put(uri, null);
        }
    }

}
