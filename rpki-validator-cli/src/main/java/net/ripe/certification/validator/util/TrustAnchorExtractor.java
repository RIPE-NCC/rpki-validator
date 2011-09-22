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
package net.ripe.certification.validator.util;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import net.ripe.certification.validator.cli.CommandLineOptions;
import net.ripe.commons.certification.rsync.Rsync;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.commons.certification.x509cert.X509CertificateUtil;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;

import org.apache.commons.io.FileUtils;


public class TrustAnchorExtractor {


    public List<CertificateRepositoryObjectValidationContext> extractTAS(CommandLineOptions options) {
        List<File> trustAnchorFiles = options.getTrustAnchorFiles();
        return extractTAS(trustAnchorFiles, options.getOutputDir().getAbsolutePath());
    }

    public List<CertificateRepositoryObjectValidationContext> extractTAS(List<File> trustAnchorFiles, String rootCertificateOutputDir) {
        List<CertificateRepositoryObjectValidationContext> tas = new ArrayList<CertificateRepositoryObjectValidationContext>();
        for (File talFile : trustAnchorFiles) {
            tas.add(extractTA(talFile, rootCertificateOutputDir));
        }
        return tas;
    }

    public CertificateRepositoryObjectValidationContext extractTA(File talFile, String rootCertificateOutputDir) {
        String content = getContent(talFile);
        List<String> lines = new ArrayList<String>(Arrays.asList(content.split("\n")));

        String rsyncLocation = lines.remove(0);
        X509ResourceCertificate cert = getRemoteCertificate(rsyncLocation, talFile, rootCertificateOutputDir);

        verifyTrustAnchor(lines.remove(0), cert);

        return new CertificateRepositoryObjectValidationContext(URI.create(rsyncLocation), cert);
    }

    private void verifyTrustAnchor(String join, X509ResourceCertificate resourceCertificate) {
        String encodedSubjectPublicKeyInfo;
        try {
            encodedSubjectPublicKeyInfo = X509CertificateUtil.getEncodedSubjectPublicKeyInfo(resourceCertificate.getCertificate());
        } catch (Exception e) {
            throw new TrustAnchorExtractorException("Problem parsing remote Trust Anchor certificate", e);
        }
        if (!encodedSubjectPublicKeyInfo.equals(join)) {
            throw new TrustAnchorExtractorException("Remote Trust Anchor does not match public key mentioned in TAL");
        }
    }

    // Extracted for unit testing
    private String getContent(File talFile) {
        try {
            return FileUtils.readFileToString(talFile);
        } catch (IOException e) {
            throw new TrustAnchorExtractorException("Can not read tal file " + talFile.getAbsolutePath(), e);
        }
    }

    private X509ResourceCertificate getRemoteCertificate(String rsyncLocation, File talFile, String rootCertificateOutputDir) {
        Rsync rsync = new Rsync();
        rsync.setSource(rsyncLocation);

        String targetDirectoryPath = rootCertificateOutputDir;
        File targetDirectory = new File(targetDirectoryPath);
        if (!targetDirectory.exists()) {
            targetDirectory.mkdirs();
        }

        String dest = targetDirectoryPath + "/" + talFile.getName() + ".cer";
        rsync.setDestination(dest);
        rsync.execute();

        return CertificateRepositoryObjectLocalFileHelper.readCertificate(new File(dest));
    }
}
