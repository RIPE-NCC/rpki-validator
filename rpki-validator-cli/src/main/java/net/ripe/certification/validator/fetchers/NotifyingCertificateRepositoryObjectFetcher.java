package net.ripe.certification.validator.fetchers;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import net.ripe.commons.certification.CertificateRepositoryObject;
import net.ripe.commons.certification.cms.manifest.ManifestCms;
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.utils.Specification;

import org.apache.commons.lang.Validate;

/**
 * Object fetcher that notifies a callback about failed and successful
 * operations.
 */
public class NotifyingCertificateRepositoryObjectFetcher implements CertificateRepositoryObjectFetcher {

    public interface FetchNotificationCallback {

        /**
         * Called after a failure of
         * {@link NotifyingCertificateRepositoryObjectFetcher#prefetch(URI, ValidationResult)}.
         *
         * @param uri
         *            the URI of the prefetch directory.
         * @param result
         *            the validation results.
         */
        void afterPrefetchFailure(URI uri, ValidationResult result);

        /**
         * Called after a success of
         * {@link NotifyingCertificateRepositoryObjectFetcher#prefetch(URI, ValidationResult)}.
         *
         * @param uri
         *            the URI of the prefetch directory.
         * @param result
         *            the validation results.
         */
        void afterPrefetchSuccess(URI uri, ValidationResult result);

        /**
         * Called after a failure of
         * {@link NotifyingCertificateRepositoryObjectFetcher#getCrl(URI, CertificateRepositoryObjectValidationContext, ValidationResult)},
         * {@link NotifyingCertificateRepositoryObjectFetcher#getManifest(URI, CertificateRepositoryObjectValidationContext, ValidationResult), and
         * {@link NotifyingCertificateRepositoryObjectFetcher#getObject(URI, CertificateRepositoryObjectValidationContext, Specification, ValidationResult).
         *
         * @param uri
         *            the URI of the object.
         * @param result
         *            the validation results.
         */
        void afterFetchFailure(URI uri, ValidationResult result);

        /**
         * Called after a success of
         * {@link NotifyingCertificateRepositoryObjectFetcher#getCrl(URI, CertificateRepositoryObjectValidationContext, ValidationResult)},
         * {@link NotifyingCertificateRepositoryObjectFetcher#getManifest(URI, CertificateRepositoryObjectValidationContext, ValidationResult), and
         * {@link NotifyingCertificateRepositoryObjectFetcher#getObject(URI, CertificateRepositoryObjectValidationContext, Specification, ValidationResult).
         *
         * @param uri
         *            the URI of the object.
         * @param object
         *            the fetched object.
         * @param result
         *            the validation results.
         */
        void afterFetchSuccess(URI uri, CertificateRepositoryObject object, ValidationResult result);

    }

    private final CertificateRepositoryObjectFetcher fetcher;
    private final List<FetchNotificationCallback> callbacks;

    public NotifyingCertificateRepositoryObjectFetcher(CertificateRepositoryObjectFetcher fetcher) {
        Validate.notNull(fetcher);
        this.fetcher = fetcher;
        this.callbacks = new ArrayList<FetchNotificationCallback>();
    }

    public void addCallback(FetchNotificationCallback callback) {
        Validate.notNull(callback);
        callbacks.add(callback);
    }

    @Override
    public X509Crl getCrl(URI uri, CertificateRepositoryObjectValidationContext context, ValidationResult result) {
        X509Crl crl = fetcher.getCrl(uri, context, result);
        notifyAfterFetch(uri, crl, result);
        return crl;
    }

    @Override
    public ManifestCms getManifest(URI uri, CertificateRepositoryObjectValidationContext context, ValidationResult result) {
        ManifestCms manifest = fetcher.getManifest(uri, context, result);
        notifyAfterFetch(uri, manifest, result);
        return manifest;
    }

    @Override
    public CertificateRepositoryObject getObject(URI uri, CertificateRepositoryObjectValidationContext context,
            Specification<byte[]> fileContentSpecification, ValidationResult result) {
        CertificateRepositoryObject object = fetcher.getObject(uri, context, fileContentSpecification, result);
        notifyAfterFetch(uri, object, result);
        return object;
    }

    @Override
    public void prefetch(URI uri, ValidationResult result) {
        fetcher.prefetch(uri, result);
        if (result.hasFailureForCurrentLocation()) {
            for (FetchNotificationCallback callback : callbacks) {
                callback.afterPrefetchFailure(uri, result);
            }
        } else {
            for (FetchNotificationCallback callback : callbacks) {
                callback.afterPrefetchSuccess(uri, result);
            }
        }
    }

    private void notifyAfterFetch(URI uri, CertificateRepositoryObject object, ValidationResult result) {
        if (result.hasFailureForCurrentLocation()) {
            for (FetchNotificationCallback callback : callbacks) {
                callback.afterFetchFailure(uri, result);
            }
        } else {
            for (FetchNotificationCallback callback : callbacks) {
                callback.afterFetchSuccess(uri, object, result);
            }
        }
    }

}
