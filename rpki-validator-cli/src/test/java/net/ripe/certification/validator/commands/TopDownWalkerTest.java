package net.ripe.certification.validator.commands;

import static net.ripe.commons.certification.util.KeyPairFactoryTest.*;
import static net.ripe.commons.certification.x509cert.X509CertificateBuilderHelper.*;
import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.util.LinkedList;
import java.util.Queue;

import javax.security.auth.x500.X500Principal;

import net.ripe.certification.validator.fetchers.CertificateRepositoryObjectFetcher;
import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.cms.manifest.ManifestCms;
import net.ripe.commons.certification.cms.manifest.ManifestCmsBuilder;
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.crl.X509CrlBuilder;
import net.ripe.commons.certification.util.KeyPairFactory;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.commons.certification.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateBuilder;
import net.ripe.ipresource.InheritedIpResourceSet;
import net.ripe.ipresource.IpResourceSet;

import org.apache.commons.lang.mutable.MutableBoolean;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Before;
import org.junit.Test;


public class TopDownWalkerTest {

    private static final URI ROOT_SIA_REPO_RSYNC_LOCATION = URI.create("rsync://foo.host/bar/");
    private static final URI ROOT_SIA_MANIFEST_RSYNC_LOCATION = URI.create("rsync://foo.host/bar/manifest.mft");
    private static final URI ROOT_SIA_REPO_HTTP_LOCATION = URI.create("http://foo.host/bar/");

    // Trust anchor test data
    private static final X500Principal ROOT_CERTIFICATE_NAME = new X500Principal("CN=For Testing Only, CN=RIPE NCC, C=NL");
    private static final IpResourceSet ROOT_RESOURCE_SET = IpResourceSet.parse("10.0.0.0/8, 192.168.0.0/16, ffce::/16, AS21212");
    private static final BigInteger ROOT_SERIAL_NUMBER = BigInteger.valueOf(900);
    private static final ValidityPeriod VALIDITY_PERIOD = new ValidityPeriod(new DateTime().minusMinutes(1), new DateTime().plusYears(1));
    private static final KeyPair ROOT_KEY_PAIR = KeyPairFactory.getInstance().generate(512, DEFAULT_KEYPAIR_GENERATOR_PROVIDER);

    // Manifest data
    public static final DateTime THIS_UPDATE_TIME = new DateTime(2008, 9, 1, 22, 43, 29, 0, DateTimeZone.UTC);
    public static final DateTime NEXT_UPDATE_TIME = new DateTime(2008, 9, 2, 6, 43, 29, 0, DateTimeZone.UTC);
    public static final byte[] HASH_1 = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
    public static final byte[] HASH_2 = { 32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };


    private Queue<CertificateRepositoryObjectValidationContext> workQueue;
    private TopDownWalker subject;
    private CertificateRepositoryObjectFetcher certificateRepositoryObjectFetcher;
    private X509ResourceCertificate ta;
	private CertificateRepositoryObjectValidationContext taContext;

    private Object[] mocks;


    @Before
    public void setUp() {
        certificateRepositoryObjectFetcher = createMock(CertificateRepositoryObjectFetcher.class);
        mocks = new Object[] { certificateRepositoryObjectFetcher };

        ta = getRootResourceCertificate();
        taContext = new CertificateRepositoryObjectValidationContext(URI.create("rsync://host/ta"), ta);
        workQueue = new LinkedList<CertificateRepositoryObjectValidationContext>();
        subject = new TopDownWalker(workQueue, certificateRepositoryObjectFetcher);
    }


    @Test
    public void shouldPrefetchRepository() {
        certificateRepositoryObjectFetcher.prefetch(eq(ROOT_SIA_REPO_RSYNC_LOCATION), isA(ValidationResult.class));
        replay(mocks);

        subject.prefetch(taContext);

        verify(mocks);
    }

    @Test
    public void shouldProcessManifestFromObjectIssuingCertificate() {
        final ManifestCms manifestCms = getRootManifestCms();
        final MutableBoolean fetchManifestCalled = new MutableBoolean(false);
        final MutableBoolean processedManifestFilesCalled = new MutableBoolean(false);

        subject = new TopDownWalker(workQueue, certificateRepositoryObjectFetcher) {
            @Override
            ManifestCms fetchManifest(URI manifestURI, CertificateRepositoryObjectValidationContext context) {
                fetchManifestCalled.setValue(true);
                assertEquals(ta.getManifestUri(), manifestURI);
                return manifestCms;
            }

            @Override
            void processManifestFiles(CertificateRepositoryObjectValidationContext context, ManifestCms actualManifestCms) {
                processedManifestFilesCalled.setValue(true);
                assertEquals(ta, context.getCertificate());
                assertEquals(manifestCms, actualManifestCms);
            }
        };

        replay(mocks);

        subject.processManifest(taContext);

        verify(mocks);
        assertTrue(fetchManifestCalled.booleanValue());
        assertTrue(processedManifestFilesCalled.booleanValue());
    }

    @Test
    public void shouldNotProcessFilesWhenManifestIsNull() {
        expect(certificateRepositoryObjectFetcher.getManifest(eq(ROOT_SIA_MANIFEST_RSYNC_LOCATION), eq(taContext), isA(ValidationResult.class))).andReturn(null);
        replay(mocks);

        subject.processManifest(taContext);

        verify(mocks);
    }

    @Test
    public void shouldFetchManifest() {
        ManifestCms manifestCms = getRootManifestCms();
        expect(certificateRepositoryObjectFetcher.getManifest(eq(ROOT_SIA_MANIFEST_RSYNC_LOCATION), eq(taContext), isA(ValidationResult.class))).andReturn(manifestCms);
        replay(mocks);

        assertEquals(manifestCms, subject.fetchManifest(ROOT_SIA_MANIFEST_RSYNC_LOCATION, taContext));

        verify(mocks);
    }

    @Test
    public void shouldAddObjectIssuerCertificatesToWorkQueue() {
    	subject.addToWorkQueueIfObjectIssuer(taContext, taContext.getLocation(), ta);

    	assertTrue(workQueue.size() == 1);
    	CertificateRepositoryObjectValidationContext context = workQueue.remove();
		assertEquals(ta, context.getCertificate());
    }

    @Test
    public void shouldSkipNotObjectIssuerCertificateObjects() {
        X509ResourceCertificate certificate = createManifestEECertificate();
        X509Crl crl = getCrl();

    	subject.addToWorkQueueIfObjectIssuer(taContext, URI.create("rsync://host/cert"), certificate);
        assertTrue(workQueue.isEmpty());

        subject.addToWorkQueueIfObjectIssuer(taContext, URI.create("rsync://host/crl"), crl);
        assertTrue(workQueue.isEmpty());
    }

    @Test
    public void shouldAddFetchedObjectIssuerToWorkQueue() {
        ManifestCms manifestCms = getRootManifestCms();
        X509Crl crl = getCrl();

        expect(certificateRepositoryObjectFetcher.getObject(eq(ROOT_SIA_REPO_RSYNC_LOCATION.resolve("foo1")), eq(taContext), eq(manifestCms.getFileContentSpecification("foo1")), isA(ValidationResult.class))).andReturn(ta);
        expect(certificateRepositoryObjectFetcher.getObject(eq(ROOT_SIA_REPO_RSYNC_LOCATION.resolve("BaR")), eq(taContext), eq(manifestCms.getFileContentSpecification("BaR")), isA(ValidationResult.class))).andReturn(crl);

        replay(mocks);

        subject.processManifestFiles(taContext, manifestCms);

        verify(mocks);

        assertEquals(1, workQueue.size());
        assertEquals(ta, workQueue.remove().getCertificate());
    }

    @Test
    public void shouldSkipInvalidObjects() {
        ManifestCms manifestCms = getRootManifestCms();

        expect(certificateRepositoryObjectFetcher.getObject(eq(ROOT_SIA_REPO_RSYNC_LOCATION.resolve("foo1")), eq(taContext), eq(manifestCms.getFileContentSpecification("foo1")), isA(ValidationResult.class))).andReturn(null);
        expect(certificateRepositoryObjectFetcher.getObject(eq(ROOT_SIA_REPO_RSYNC_LOCATION.resolve("BaR")), eq(taContext), eq(manifestCms.getFileContentSpecification("BaR")), isA(ValidationResult.class))).andReturn(null);
        replay(mocks);

        subject.processManifestFiles(taContext, manifestCms);

        verify(mocks);

        assertTrue(workQueue.isEmpty());
    }


    @SuppressWarnings("deprecation")
    public static ManifestCms getRootManifestCms() {
        ManifestCmsBuilder builder = new ManifestCmsBuilder();
        builder.withCertificate(createManifestEECertificate()).withManifestNumber(BigInteger.valueOf(68));
        builder.withThisUpdateTime(THIS_UPDATE_TIME).withNextUpdateTime(NEXT_UPDATE_TIME);
        builder.putFile("foo1", HASH_1);
        builder.putFile("BaR", HASH_2);
        builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);
        return builder.build(ROOT_KEY_PAIR.getPrivate());
    }

    static X509ResourceCertificate createManifestEECertificate() {
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();
        builder.withCa(false).withSubjectDN(ROOT_CERTIFICATE_NAME).withIssuerDN(ROOT_CERTIFICATE_NAME).withSerial(BigInteger.ONE);
        builder.withPublicKey(ROOT_KEY_PAIR.getPublic());
        builder.withSigningKeyPair(ROOT_KEY_PAIR);
        builder.withResources(InheritedIpResourceSet.getInstance());
        builder.withValidityPeriod(new ValidityPeriod(THIS_UPDATE_TIME, NEXT_UPDATE_TIME));
        return builder.build();
    }


    static X509ResourceCertificate getRootResourceCertificate() {
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();

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

        return builder.build();
    }

    private X509Crl getCrl() {
        X509CrlBuilder builder = new X509CrlBuilder();
        builder.withIssuerDN(new X500Principal("CN=issuer"));
        builder.withThisUpdateTime(new DateTime());
        builder.withNextUpdateTime(new DateTime().plusHours(8));
        builder.withNumber(BigInteger.TEN);
        builder.withAuthorityKeyIdentifier(ROOT_KEY_PAIR.getPublic());
        return builder.build(ROOT_KEY_PAIR.getPrivate());
    }
}
