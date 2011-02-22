package net.ripe.certification.validator;

import static net.ripe.commons.certification.util.KeyPairFactoryTest.*;
import static net.ripe.commons.certification.x509cert.X509CertificateBuilder.*;

import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.cms.manifest.ManifestCms;
import net.ripe.commons.certification.cms.manifest.ManifestCmsBuilder;
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.crl.X509CrlBuilder;
import net.ripe.commons.certification.util.KeyPairFactory;
import net.ripe.commons.certification.util.KeyPairFactoryTest;
import net.ripe.commons.certification.x509cert.X509CertificateBuilder;
import net.ripe.commons.certification.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.ipresource.InheritedIpResourceSet;
import net.ripe.ipresource.IpResourceSet;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;

public class RepositoryObjectsSetUpHelper {

    public static final URI ROOT_SIA_REPO_RSYNC_LOCATION = URI.create("rsync://foo.host/bar/");
    public static final URI ROOT_SIA_MANIFEST_RSYNC_LOCATION = URI.create("rsync://foo.host/bar/manifest.mft");
    public static final URI ROOT_SIA_REPO_HTTP_LOCATION = URI.create("http://foo.host/bar/");
    public static final URI ROOT_MANIFEST_CRL_LOCATION = URI.create("rsync://foo.host/bar/bar%20space.crl");
    public static final URI ROOT_CERTIFICATE_LOCATION = URI.create("rsync://foo.host/bar/bar.cer");
    public static final URI FIRST_CHILD_CERTIFICATE_LOCATION = URI.create("rsync://foo.host/bar//child/bar.cer");
    public static final URI FIRST_CHILD_MANIFEST_CRL_LOCATION = URI.create("rsync://foo.host/bar/child/bar.crl");
    public static final URI SECOND_CHILD_CERTIFICATE_LOCATION = URI.create("rsync://foo.host/bar/child/grandchild/bar.cer");

    // Trust anchor test data
    public static final X500Principal ROOT_CERTIFICATE_NAME = new X500Principal("CN=TestingRoot");
    public static final IpResourceSet ROOT_RESOURCE_SET = IpResourceSet.parse("10.0.0.0/8, 192.168.0.0/16, ffce::/16, AS21212");
    public static final BigInteger ROOT_SERIAL_NUMBER = BigInteger.valueOf(900);
    public static final ValidityPeriod VALIDITY_PERIOD = new ValidityPeriod(new DateTime().minusMinutes(1), new DateTime().plusYears(1));
    public static final KeyPair ROOT_KEY_PAIR = KeyPairFactory.getInstance().generate(512, DEFAULT_KEYPAIR_GENERATOR_PROVIDER);

    // Manifest data
    public static final KeyPair MANIFEST_KEY_PAIR = KeyPairFactoryTest.getKeyPair("Manifest");
    public static final X500Principal MANIFEST_CERTIFICATE_NAME = new X500Principal("CN=Manifest");
    public static final DateTime THIS_UPDATE_TIME = new DateTime();
    public static final DateTime NEXT_UPDATE_TIME = new DateTime().plusDays(1);
    public static final byte[] HASH_1 = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
    public static final byte[] HASH_2 = { 32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };

    // Child cert data
    private static final KeyPair FIRST_CHILD_KEY_PAIR = KeyPairFactory.getInstance().generate(512, DEFAULT_KEYPAIR_GENERATOR_PROVIDER);
    private static final KeyPair SECOND_CHILD_KEY_PAIR = KeyPairFactory.getInstance().generate(512, DEFAULT_KEYPAIR_GENERATOR_PROVIDER);

    private static final X500Principal FIRST_CHILD_CERTIFICATE_NAME = new X500Principal("CN=For Testing Only, CN=First Child, C=NL");
	private static final BigInteger FIRST_CHILD_SERIAL_NUMBER = ROOT_SERIAL_NUMBER.add(BigInteger.valueOf(1));
	private static final X500Principal SECOND_CHILD_CERTIFICATE_NAME = new X500Principal("CN=For Testing Only, CN=Second Child, C=NL");
	private static final BigInteger SECOND_CHILD_SERIAL_NUMBER = FIRST_CHILD_SERIAL_NUMBER.add(BigInteger.valueOf(1));
	private static final IpResourceSet SECOND_CHILD_RESOURCE_SET = IpResourceSet.parse("10.0.0.0/8, 192.168.0.0/17, ffce::/16, AS21212");

    public static ManifestCms getRootManifestCms() {
        return getRootManifestBuilder().build(MANIFEST_KEY_PAIR.getPrivate());
    }

    public static ManifestCms getRootManifestCmsWithEntry(String fileName, byte[] contents) {
        ManifestCmsBuilder rootManifestBuilder = getRootManifestBuilder();
        rootManifestBuilder.addFile(fileName, contents);
        return rootManifestBuilder.build(MANIFEST_KEY_PAIR.getPrivate());
    }

    public static ManifestCms getInvalidRootManifestCms() {
    	ManifestCmsBuilder rootManifestBuilder = getRootManifestBuilder();
    	X509ResourceCertificate expiredCert = getManifestEEResourceCertificateBuilder().withValidityPeriod(new ValidityPeriod(new DateTime().minusMonths(1), new DateTime().minusMinutes(1))).buildResourceCertificate();
    	rootManifestBuilder.withCertificate(expiredCert);
    	return rootManifestBuilder.build(MANIFEST_KEY_PAIR.getPrivate());
    }

    public static X509Crl getRootCrl() {
    	return getRootCrlBuilder().build(ROOT_KEY_PAIR.getPrivate());
    }

    public static X509Crl getRootCrlWithInvalidSignature() {
    	return getRootCrlBuilder().build(FIRST_CHILD_KEY_PAIR.getPrivate());
    }

    public static X509Crl getChildCrl() {
    	return getRootCrlBuilder().build(FIRST_CHILD_KEY_PAIR.getPrivate());
    }

    public static X509ResourceCertificate getRootResourceCertificate() {
    	X509CertificateBuilder builder = getRootResourceCertificateBuilder();
    	return builder.buildResourceCertificate();
    }

    public static X509ResourceCertificate getRootResourceCertificate(IpResourceSet resources) {
        X509CertificateBuilder builder = getRootResourceCertificateBuilder().withResources(resources);
        return builder.buildResourceCertificate();
    }

    public static X509ResourceCertificate getExpiredRootResourceCertificate() {
        X509CertificateBuilder builder = getRootResourceCertificateBuilder();
        builder.withValidityPeriod(new ValidityPeriod(new DateTime().minusMonths(1), new DateTime().minusDays(1)));
        return builder.buildResourceCertificate();
    }

    public static X509ResourceCertificate getRootResourceCertificateWithAiaFieldPointingToItself() {
    	X509CertificateBuilder builder = getRootResourceCertificateBuilder();
    	X509CertificateInformationAccessDescriptor[] descriptors = {
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS, ROOT_CERTIFICATE_LOCATION),
        };
    	builder.withAuthorityInformationAccess(descriptors);
    	return builder.buildResourceCertificate();
    }

    public static X509ResourceCertificate getChildResourceCertificate() {
    	return createChildBuilder().buildResourceCertificate();
    }

    public static X509ResourceCertificate getSecondChildResourceCertificate() {
    	return createSecondChildBuilder().buildResourceCertificate();
    }

    private static X509CrlBuilder getRootCrlBuilder() {
        X509CrlBuilder builder = new X509CrlBuilder();
        builder.withIssuerDN(new X500Principal("CN=issuer"));
        builder.withThisUpdateTime(new DateTime());
        builder.withNextUpdateTime(new DateTime().plusHours(8));
        builder.withNumber(BigInteger.TEN);
        builder.withAuthorityKeyIdentifier(ROOT_KEY_PAIR.getPublic());
        builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);
        return builder;
    }

    private static ManifestCmsBuilder getRootManifestBuilder() {
        ManifestCmsBuilder builder = new ManifestCmsBuilder();
        builder.withCertificate(getManifestEEResourceCertificateBuilder().buildResourceCertificate());
        builder.withManifestNumber(BigInteger.valueOf(68));
        builder.withThisUpdateTime(THIS_UPDATE_TIME).withNextUpdateTime(NEXT_UPDATE_TIME);
        builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);
        builder.putFile("foo1", HASH_1);
        builder.putFile("BaR", HASH_2);
        return builder;
    }

    private static X509CertificateBuilder getManifestEEResourceCertificateBuilder() {
        X509CertificateBuilder builder = new X509CertificateBuilder();
        builder.withCa(false).withSubjectDN(MANIFEST_CERTIFICATE_NAME).withIssuerDN(ROOT_CERTIFICATE_NAME).withSerial(BigInteger.ONE);
        builder.withPublicKey(MANIFEST_KEY_PAIR.getPublic());
        builder.withSigningKeyPair(ROOT_KEY_PAIR);
        builder.withResources(InheritedIpResourceSet.getInstance());
        builder.withValidityPeriod(new ValidityPeriod(THIS_UPDATE_TIME, NEXT_UPDATE_TIME));
        builder.withCrlDistributionPoints(ROOT_MANIFEST_CRL_LOCATION);

        return builder;
    }

    private static X509CertificateBuilder getRootResourceCertificateBuilder() {
        X509CertificateBuilder builder = new X509CertificateBuilder();

        builder.withSubjectDN(ROOT_CERTIFICATE_NAME);
        builder.withIssuerDN(ROOT_CERTIFICATE_NAME);
        builder.withSerial(ROOT_SERIAL_NUMBER);
        builder.withValidityPeriod(VALIDITY_PERIOD);
        builder.withPublicKey(ROOT_KEY_PAIR.getPublic());
        builder.withCa(true);
        builder.withKeyUsage(KeyUsage.keyCertSign);
        builder.withAuthorityKeyIdentifier(true);
        builder.withSubjectKeyIdentifier(true);
        builder.withResources(ROOT_RESOURCE_SET);
        builder.withAuthorityKeyIdentifier(false);
        builder.withSigningKeyPair(ROOT_KEY_PAIR);

        X509CertificateInformationAccessDescriptor[] descriptors = {
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY, ROOT_SIA_REPO_HTTP_LOCATION),
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY, ROOT_SIA_REPO_RSYNC_LOCATION),
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST, ROOT_SIA_MANIFEST_RSYNC_LOCATION),
        };
        builder.withSubjectInformationAccess(descriptors);
        builder.withCrlDistributionPoints(ROOT_MANIFEST_CRL_LOCATION);
        return builder;
    }

    private static X509CertificateBuilder createChildBuilder() {
		X509CertificateBuilder builder = new X509CertificateBuilder();

    	builder.withSubjectDN(FIRST_CHILD_CERTIFICATE_NAME);
        builder.withIssuerDN(ROOT_CERTIFICATE_NAME);
        builder.withSerial(FIRST_CHILD_SERIAL_NUMBER);
        builder.withPublicKey(FIRST_CHILD_KEY_PAIR.getPublic());
        builder.withAuthorityKeyIdentifier(true);
        builder.withSigningKeyPair(ROOT_KEY_PAIR);
        builder.withCa(true);
        builder.withKeyUsage(KeyUsage.keyCertSign);
        builder.withAuthorityKeyIdentifier(true);
        builder.withSubjectKeyIdentifier(true);
        builder.withResources(InheritedIpResourceSet.getInstance());
        builder.withValidityPeriod(VALIDITY_PERIOD);
        builder.withCrlDistributionPoints(new URI[] { ROOT_MANIFEST_CRL_LOCATION });

        X509CertificateInformationAccessDescriptor[] descriptors = {
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS, ROOT_CERTIFICATE_LOCATION),
        };
        builder.withAuthorityInformationAccess(descriptors);

		return builder;
	}

	private static X509CertificateBuilder createSecondChildBuilder() {
		X509CertificateBuilder builder = new X509CertificateBuilder();

    	builder.withSubjectDN(SECOND_CHILD_CERTIFICATE_NAME);
        builder.withIssuerDN(FIRST_CHILD_CERTIFICATE_NAME);
        builder.withSerial(SECOND_CHILD_SERIAL_NUMBER);
        builder.withPublicKey(SECOND_CHILD_KEY_PAIR.getPublic());
        builder.withAuthorityKeyIdentifier(true);
        builder.withSigningKeyPair(FIRST_CHILD_KEY_PAIR);
    	builder.withValidityPeriod(VALIDITY_PERIOD);
    	builder.withAuthorityKeyIdentifier(true);
        builder.withSubjectKeyIdentifier(true);
    	builder.withResources(SECOND_CHILD_RESOURCE_SET);
    	builder.withCrlDistributionPoints(new URI[] { FIRST_CHILD_MANIFEST_CRL_LOCATION });

        X509CertificateInformationAccessDescriptor[] descriptors = {
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS, FIRST_CHILD_CERTIFICATE_LOCATION),
        };
        builder.withAuthorityInformationAccess(descriptors);

		return builder;
	}
}

