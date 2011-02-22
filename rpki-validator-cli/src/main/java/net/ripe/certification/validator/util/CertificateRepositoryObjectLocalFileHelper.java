package net.ripe.certification.validator.util;

import java.io.File;
import java.io.IOException;

import net.ripe.certification.validator.runtimeproblems.ValidatorIOException;
import net.ripe.commons.certification.CertificateRepositoryObject;
import net.ripe.commons.certification.util.CertificateRepositoryObjectFactory;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;

import org.apache.commons.io.FileUtils;

public final class CertificateRepositoryObjectLocalFileHelper {

    private CertificateRepositoryObjectLocalFileHelper() {
        //Utility classes should not have a public or default constructor.
    }

    public static X509ResourceCertificate readCertificate(File certificate) {
        return (X509ResourceCertificate) readCertificateRepositoryObject(certificate);
    }

    public static CertificateRepositoryObject readCertificateRepositoryObject(File file) {
        byte[] contents;
        try {
            contents = FileUtils.readFileToByteArray(file);
        } catch (IOException e) {
            throw new ValidatorIOException("Can't read file: " + file.getAbsolutePath(), e);
        }
        return CertificateRepositoryObjectFactory.createCertificateRepositoryObject(contents);
    }

}
