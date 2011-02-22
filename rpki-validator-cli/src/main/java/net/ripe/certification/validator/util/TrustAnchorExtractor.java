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
import org.apache.commons.lang.StringUtils;


public class TrustAnchorExtractor {


    public List<CertificateRepositoryObjectValidationContext> extractTAS(CommandLineOptions options) {
        List<File> trustAnchorFiles = options.getTrustAnchorFiles();
        return extractTAS(trustAnchorFiles, options.getOutputDir().getAbsolutePath());
    }

    public List<CertificateRepositoryObjectValidationContext> extractTAS(List<File> trustAnchorFiles, String rootCertificateOutputDir) {
        List<CertificateRepositoryObjectValidationContext> tas = new ArrayList<CertificateRepositoryObjectValidationContext>();
        for (File talFile : trustAnchorFiles) {
            tas.add(getValidationContextForTAL(talFile, rootCertificateOutputDir));
        }
        return tas;
    }

    private CertificateRepositoryObjectValidationContext getValidationContextForTAL(File talFile, String rootCertificateOutputDir) {
        String content = getContent(talFile);
        List<String> lines = new ArrayList<String>(Arrays.asList(content.split("\n")));

        String rsyncLocation = lines.remove(0);
        X509ResourceCertificate cert = getRemoteCertificate(rsyncLocation, talFile, rootCertificateOutputDir);

        verifyTrustAnchor(StringUtils.join(lines.toArray()), cert);

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
