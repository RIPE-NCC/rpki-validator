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

import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.util.Specification;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import org.apache.commons.lang.Validate;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * Object fetcher that notifies a callback about failed and successful
 * operations.
 */
public class NotifyingCertificateRepositoryObjectFetcher implements CertificateRepositoryObjectFetcher {

    public static interface Listener {


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

    /**
     * Adapter that provides empty implementations.
     */
    public static class ListenerAdapter implements Listener {
        @Override
        public void afterPrefetchFailure(URI uri, ValidationResult result) {
        }

        @Override
        public void afterPrefetchSuccess(URI uri, ValidationResult result) {
        }

        @Override
        public void afterFetchFailure(URI uri, ValidationResult result) {
        }

        @Override
        public void afterFetchSuccess(URI uri, CertificateRepositoryObject object, ValidationResult result) {
        }
    }

    private final CertificateRepositoryObjectFetcher fetcher;
    private final List<Listener> callbacks;

    public NotifyingCertificateRepositoryObjectFetcher(CertificateRepositoryObjectFetcher fetcher) {
        Validate.notNull(fetcher);
        this.fetcher = fetcher;
        this.callbacks = new ArrayList<Listener>();
    }

    public void addCallback(Listener callback) {
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
            for (Listener callback : callbacks) {
                callback.afterPrefetchFailure(uri, result);
            }
        } else {
            for (Listener callback : callbacks) {
                callback.afterPrefetchSuccess(uri, result);
            }
        }
    }

    private void notifyAfterFetch(URI uri, CertificateRepositoryObject object, ValidationResult result) {
        if (result.hasFailureForCurrentLocation()) {
            for (Listener callback : callbacks) {
                callback.afterFetchFailure(uri, result);
            }
        } else {
            for (Listener callback : callbacks) {
                callback.afterFetchSuccess(uri, object, result);
            }
        }
    }

}
