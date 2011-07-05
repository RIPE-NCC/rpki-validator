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

import static net.ripe.commons.certification.validation.ValidationString.*;

import java.io.File;
import java.io.IOException;
import java.net.URI;

import net.ripe.certification.validator.util.HierarchicalUriCache;
import net.ripe.certification.validator.util.UriToFileMapper;
import net.ripe.commons.certification.CertificateRepositoryObject;
import net.ripe.commons.certification.cms.manifest.ManifestCms;
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.rsync.Rsync;
import net.ripe.commons.certification.util.CertificateRepositoryObjectFactory;
import net.ripe.commons.certification.util.CertificateRepositoryObjectParserException;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.utils.Specification;
import net.ripe.utils.Specifications;

import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;

public class RsyncCertificateRepositoryObjectFetcher implements CertificateRepositoryObjectFetcher {

    private static final Logger LOG = Logger.getLogger(RsyncCertificateRepositoryObjectFetcher.class);

    private static final String[] STANDARD_OPTIONS = { "--update", "--times", "--copy-links" };
    private static final String[] PREFETCH_OPTIONS = { "--recursive", "--delete" };
    private static final String[] SINGLE_FILE_OPTIONS = {};

    private final HierarchicalUriCache uriCache;
    private final Rsync rsync;
    private final UriToFileMapper uriToFileMapper;


    public RsyncCertificateRepositoryObjectFetcher(Rsync rsync, UriToFileMapper uriToFileMapper) {
        this.rsync = rsync;
        this.uriToFileMapper = uriToFileMapper;
        this.uriCache = new HierarchicalUriCache();
    }

    @Override
    public X509Crl getCrl(URI uri, CertificateRepositoryObjectValidationContext context, ValidationResult result) {
        CertificateRepositoryObject object = getObject(uri, context, Specifications.<byte[]>alwaysTrue(), result);
        if (result.hasFailureForCurrentLocation()) {
            return null;
        }

        result.isTrue(object instanceof X509Crl, VALIDATOR_FETCHED_OBJECT_IS_CRL, object);
        if (result.hasFailureForCurrentLocation()) {
            return null;
        }
        return (X509Crl) object;
    }

    @Override
    public ManifestCms getManifest(URI uri, CertificateRepositoryObjectValidationContext context, ValidationResult result) {
        CertificateRepositoryObject object = getObject(uri, context, Specifications.<byte[]>alwaysTrue(), result);
        if (result.hasFailureForCurrentLocation()) {
            return null;
        }

        result.isTrue(object instanceof ManifestCms, VALIDATOR_FETCHED_OBJECT_IS_MANIFEST, object);
        if (result.hasFailureForCurrentLocation()) {
            return null;
        }
        return (ManifestCms) object;
    }

    @Override
    public CertificateRepositoryObject getObject(URI uri, CertificateRepositoryObjectValidationContext context, Specification<byte[]> fileContentSpecification, ValidationResult result) {
        File destinationFile = uriToFileMapper.map(uri, result);
        if (destinationFile == null) {
            return null;
        }

        fetchFile(uri, destinationFile, result);
        if (result.hasFailureForCurrentLocation()) {
            return null;
        }

        byte[] contents = readFile(destinationFile, result);
        if (result.hasFailureForCurrentLocation()) {
            return null;
        }

        result.isTrue(fileContentSpecification.isSatisfiedBy(contents), VALIDATOR_FILE_CONTENT, uri);
        if (result.hasFailureForCurrentLocation()) {
            return null;
        }

        CertificateRepositoryObject cro;
        try {
            cro = CertificateRepositoryObjectFactory.createCertificateRepositoryObject(contents);
        } catch (CertificateRepositoryObjectParserException ex) {
            cro = null;
        }
        result.notNull(cro, KNOWN_OBJECT_TYPE, uri);
        return cro;
    }

    @Override
    public void prefetch(URI uri, ValidationResult result) {
        if (uriCache.contains(uri)) {
            LOG.debug("rsync cache hit for URI " + uri);
            return;
        }

        File destinationDirectory = uriToFileMapper.map(uri, result);
        if (result.hasFailureForCurrentLocation()) {
            return;
        }

        rsync.reset();
        rsync.addOptions(STANDARD_OPTIONS);
        rsync.addOptions(PREFETCH_OPTIONS);
        rsync.setSource(uri.toString());
        rsync.setDestination(destinationDirectory.getAbsolutePath());

        destinationDirectory.mkdirs();
        int rc = rsync.execute();
        result.isTrue(rc == 0, VALIDATOR_RSYNC_COMMAND, uri);
        if (rc == 0) {
            uriCache.add(uri);
        }
    }

    private void fetchFile(URI uri, File destinationFile, ValidationResult result) {
        if (uriCache.contains(uri)) {
            LOG.debug("rsync cache hit for URI " + uri);
            return;
        }

        rsync.reset();
        rsync.addOptions(STANDARD_OPTIONS);
        rsync.addOptions(SINGLE_FILE_OPTIONS);
        rsync.setSource(uri.toString());
        rsync.setDestination(destinationFile.getAbsolutePath());

        destinationFile.getParentFile().mkdirs();
        int rc = rsync.execute();
        result.isTrue(rc == 0, VALIDATOR_RSYNC_COMMAND, uri);
        if (rc == 0) {
            uriCache.add(uri);
        }
    }

    private byte[] readFile(File destinationFile, ValidationResult validationResult) {
        byte[] result;
        try {
           result = FileUtils.readFileToByteArray(destinationFile);
        } catch (IOException e) {
            result = null;
        }
        validationResult.notNull(result, VALIDATOR_READ_FILE, destinationFile.getAbsolutePath());
        return result;
    }
}
