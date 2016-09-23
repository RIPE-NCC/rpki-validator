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
package net.ripe.rpki.validator.util;

import com.google.common.base.Joiner;
import com.google.common.base.Preconditions;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateUtil;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.rsync.Rsync;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.rpki.validator.cli.CommandLineOptions;
import net.ripe.rpki.validator.runtimeproblems.ValidatorIOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;


public class TrustAnchorExtractor {

    private final static Logger LOGGER = LoggerFactory.getLogger(TrustAnchorExtractor.class);

    private final Rsync rsync;

    public TrustAnchorExtractor() {
        this(new Rsync());
    }

    public TrustAnchorExtractor(Rsync rsync) {
        this.rsync = rsync;
    }

    public List<CertificateRepositoryObjectValidationContext> extractTAS(CommandLineOptions options) {
        return extractTAS(options.getTrustAnchorFiles(), options.getOutputDir().getAbsolutePath());
    }

    public List<CertificateRepositoryObjectValidationContext> extractTAS(List<TrustAnchorLocator> list, String rootCertificateOutputDir) {
        List<CertificateRepositoryObjectValidationContext> tas = new ArrayList<CertificateRepositoryObjectValidationContext>();
        for (TrustAnchorLocator tal : list) {
            tas.add(extractTA(tal, rootCertificateOutputDir));
        }
        return tas;
    }

    public CertificateRepositoryObjectValidationContext extractTA(TrustAnchorLocator tal, String rootCertificateOutputDir) {
        X509ResourceCertificate cert = getRemoteCertificate(tal, rootCertificateOutputDir);

        verifyTrustAnchor(tal, cert);

        return new CertificateRepositoryObjectValidationContext(tal.getFetchedCertificateUri(), cert);
    }

    private void verifyTrustAnchor(TrustAnchorLocator tal, X509ResourceCertificate resourceCertificate) {
        String encodedSubjectPublicKeyInfo;
        try {
            encodedSubjectPublicKeyInfo = X509CertificateUtil.getEncodedSubjectPublicKeyInfo(resourceCertificate.getCertificate());
        } catch (Exception e) {
            throw new TrustAnchorExtractorException("Problem parsing remote Trust Anchor certificate", e);
        }
        if (!encodedSubjectPublicKeyInfo.equals(tal.getPublicKeyInfo())) {
            throw new TrustAnchorExtractorException("Remote Trust Anchor does not match public key mentioned in TAL");
        }
    }

    private X509ResourceCertificate getRemoteCertificate(TrustAnchorLocator tal, String rootCertificateOutputDir) {
        Preconditions.checkArgument(! tal.getCertificateLocations().isEmpty(),
                                    "TAL without a certificate location: " + tal.getCaName());

        final Path targetDirectory = Paths.get(rootCertificateOutputDir);
        try {
            Files.createDirectories(targetDirectory);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        File dest = targetDirectory.resolve(tal.getFile().getName() + ".cer").toFile();
        final URI uri = fetchRootCertificate(tal.getCertificateLocations(), dest);
        tal.setFetchedCertificateUri(uri);
        return CertificateRepositoryObjectLocalFileHelper.readCertificate(dest);
    }

    private URI fetchRootCertificate(Iterable<URI> certificateLocations, File dest) {
        int exitStatus = -1;
        URI certUri;
        final Iterator<URI> certificateLocationsIterator = certificateLocations.iterator();
        do {
            certUri = certificateLocationsIterator.next();
            if ("rsync".equalsIgnoreCase(certUri.getScheme())) {
                rsync.reset();
                rsync.setSource(certUri.toString());
                rsync.setDestination(dest.toString());
                exitStatus = rsync.execute();
            } else {
                LOGGER.info("Only rsync protocol is supported for TA certificate fetch. Skipping " + certUri.toString());
            }
        } while (exitStatus != 0 && certificateLocationsIterator.hasNext());

        if (exitStatus != 0) throw new ValidatorIOException(
                "Failed to retrieve TA certificate from all locations:" + Joiner.on(", ").join(certificateLocations));
        else return certUri;
    }
}
