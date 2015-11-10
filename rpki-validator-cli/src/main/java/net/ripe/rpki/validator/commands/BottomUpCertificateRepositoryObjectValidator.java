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
import net.ripe.rpki.commons.rsync.Rsync;
import net.ripe.rpki.commons.util.ConfigurationUtil;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.rpki.validator.fetchers.CachingCertificateRepositoryObjectFetcher;
import net.ripe.rpki.validator.fetchers.CertificateRepositoryObjectFetcher;
import net.ripe.rpki.validator.fetchers.NotifyingCertificateRepositoryObjectFetcher;
import net.ripe.rpki.validator.fetchers.RpkiRepositoryObjectFetcherAdapter;
import net.ripe.rpki.validator.fetchers.RsyncRpkiRepositoryObjectFetcher;
import net.ripe.rpki.validator.fetchers.ValidatingCertificateRepositoryObjectFetcher;
import net.ripe.rpki.validator.output.ObjectFetcherResultLogger;
import net.ripe.rpki.validator.runtimeproblems.ValidatorIOException;
import net.ripe.rpki.validator.util.UriToFileMapper;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

public class BottomUpCertificateRepositoryObjectValidator {

    private CertificateRepositoryObjectFetcher chainBuildFetcher;
    private CertificateRepositoryObjectFetcher validationFetcher;
    private CachingCertificateRepositoryObjectFetcher cachingFetcher;
    private SingleObjectWalker singleObjectWalker;
    private ObjectFetcherResultLogger chainBuildResultLogger;
    private File tempDir;
    private List<CertificateRepositoryObjectValidationContext> trustAnchors;


    public BottomUpCertificateRepositoryObjectValidator(List<CertificateRepositoryObjectValidationContext> trustAnchors, CertificateRepositoryObject startingPoint, URI startingPointUri) {
        chainBuildResultLogger = new ObjectFetcherResultLogger(false);
        tempDir = getUniqueTempDir();
        wireUpFetcherForChainBuilding();
        wireUpFetcherForValidation();
        cachingFetcher.updateCache(startingPointUri, startingPoint);
        singleObjectWalker = new SingleObjectWalker(startingPoint, startingPointUri, chainBuildFetcher, chainBuildResultLogger, validationFetcher);
        this.trustAnchors = trustAnchors;
    }

    File getTempDirectory() {
        return tempDir;
    }

    public ValidationResult validate() {
        ValidationResult result = singleObjectWalker.execute(trustAnchors);
        try {
            FileUtils.deleteDirectory(tempDir);
            return result;
        } catch (IOException e) {
            throw new ValidatorIOException("Could not delete temp directory: " + tempDir, e);
        }
    }

    private void wireUpFetcherForValidation() {
        ValidatingCertificateRepositoryObjectFetcher validatingCertificateRepositoryObjectFetcher = new ValidatingCertificateRepositoryObjectFetcher(cachingFetcher);
        NotifyingCertificateRepositoryObjectFetcher notifyingCertificateRepositoryObjectFetcher = new NotifyingCertificateRepositoryObjectFetcher(validatingCertificateRepositoryObjectFetcher);
        notifyingCertificateRepositoryObjectFetcher.addCallback(new ObjectFetcherResultLogger());
        CachingCertificateRepositoryObjectFetcher cachingCertificateRepositoryObjectFetcher = new CachingCertificateRepositoryObjectFetcher(notifyingCertificateRepositoryObjectFetcher);
        validatingCertificateRepositoryObjectFetcher.setOuterMostDecorator(cachingCertificateRepositoryObjectFetcher);
        validationFetcher = cachingCertificateRepositoryObjectFetcher;
    }

    private void wireUpFetcherForChainBuilding() {
        CertificateRepositoryObjectFetcher rsyncCertificateRepositoryObjectFetcher = new RpkiRepositoryObjectFetcherAdapter(new RsyncRpkiRepositoryObjectFetcher(new Rsync(), new UriToFileMapper(tempDir)));
        CachingCertificateRepositoryObjectFetcher cachingCertificateRepositoryObjectFetcher = new CachingCertificateRepositoryObjectFetcher(rsyncCertificateRepositoryObjectFetcher);
        NotifyingCertificateRepositoryObjectFetcher notifyingCertificateRepositoryObjectFetcher = new NotifyingCertificateRepositoryObjectFetcher(cachingCertificateRepositoryObjectFetcher);
        notifyingCertificateRepositoryObjectFetcher.addCallback(chainBuildResultLogger);
        cachingFetcher = cachingCertificateRepositoryObjectFetcher;
        chainBuildFetcher =  notifyingCertificateRepositoryObjectFetcher;
    }

    private File getUniqueTempDir() {
        try {
            return Files.createTempDirectory(Paths.get(ConfigurationUtil.getTempDirectory()), "val").toFile();
        } catch (IOException e) {
            throw new ValidatorIOException("Could not create temp directory", e);
        }
    }

    // for unit testing
    void setSingleObjectWalker(SingleObjectWalker singleObjectWalker ) {
        this.singleObjectWalker = singleObjectWalker;
    }
}
