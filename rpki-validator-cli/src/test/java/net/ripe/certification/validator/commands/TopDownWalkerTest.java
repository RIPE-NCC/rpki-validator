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
package net.ripe.certification.validator.commands;

import net.ripe.certification.validator.fetchers.CertificateRepositoryObjectFetcher;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCmsBuilder;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.crl.X509CrlBuilder;
import net.ripe.rpki.commons.crypto.util.PregeneratedKeyPairFactory;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateBuilder;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import org.apache.commons.lang.mutable.MutableBoolean;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Before;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.util.EnumSet;
import java.util.LinkedList;
import java.util.Queue;

import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper.DEFAULT_SIGNATURE_PROVIDER;
import static org.easymock.EasyMock.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;


public class TopDownWalkerTest {

    private static final URI ROOT_SIA_REPO_RSYNC_LOCATION = URI.create("rsync://foo.host/bar/");
    private static final URI ROOT_SIA_MANIFEST_RSYNC_LOCATION = URI.create("rsync://foo.host/bar/manifest.mft");
    private static final URI ROOT_SIA_REPO_HTTP_LOCATION = URI.create("http://foo.host/bar/");

    // Trust anchor test data
    private static final X500Principal ROOT_CERTIFICATE_NAME = new X500Principal("CN=For Testing Only, CN=RIPE NCC, C=NL");
    private static final IpResourceSet ROOT_RESOURCE_SET = IpResourceSet.parse("10.0.0.0/8, 192.168.0.0/16, ffce::/16, AS21212");
    private static final BigInteger ROOT_SERIAL_NUMBER = BigInteger.valueOf(900);
    private static final ValidityPeriod VALIDITY_PERIOD = new ValidityPeriod(new DateTime().minusMinutes(1), new DateTime().plusYears(1));
    private static final KeyPair ROOT_KEY_PAIR = PregeneratedKeyPairFactory.getInstance().generate();

    // Manifest data
    public static final DateTime THIS_UPDATE_TIME = new DateTime(2008, 9, 1, 22, 43, 29, 0, DateTimeZone.UTC);
    public static final DateTime NEXT_UPDATE_TIME = new DateTime(2008, 9, 2, 6, 43, 29, 0, DateTimeZone.UTC);
    public static final byte[] FOO_CONTENT = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };

    public static final byte[] BAR_CONTENT = {32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6,
            5, 4, 3, 2, 1};


    private Queue<CertificateRepositoryObjectValidationContext> workQueue;
    private TopDownWalker subject;
    private CertificateRepositoryObjectFetcher certificateRepositoryObjectFetcher;
    private X509ResourceCertificate ta;
    private CertificateRepositoryObjectValidationContext taContext;
    private ValidationResult validitionResult;

    private Object[] mocks;


    @Before
    public void setUp() {
        certificateRepositoryObjectFetcher = createMock(CertificateRepositoryObjectFetcher.class);
        mocks = new Object[] { certificateRepositoryObjectFetcher };

        ta = getRootResourceCertificate();
        taContext = new CertificateRepositoryObjectValidationContext(URI.create("rsync://host/ta"), ta);
        workQueue = new LinkedList<CertificateRepositoryObjectValidationContext>();
        validitionResult = new ValidationResult();
        subject = new TopDownWalker(workQueue, certificateRepositoryObjectFetcher, validitionResult);
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

        subject = new TopDownWalker(workQueue, certificateRepositoryObjectFetcher, validitionResult) {
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


    public static ManifestCms getRootManifestCms() {
        ManifestCmsBuilder builder = new ManifestCmsBuilder();
        builder.withCertificate(createManifestEECertificate()).withManifestNumber(BigInteger.valueOf(68));
        builder.withThisUpdateTime(THIS_UPDATE_TIME).withNextUpdateTime(NEXT_UPDATE_TIME);
        builder.addFile("foo1", FOO_CONTENT);
        builder.addFile("BaR", BAR_CONTENT);
        builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);
        return builder.build(ROOT_KEY_PAIR.getPrivate());
    }

    static X509ResourceCertificate createManifestEECertificate() {
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();
        builder.withCa(false).withSubjectDN(ROOT_CERTIFICATE_NAME).withIssuerDN(ROOT_CERTIFICATE_NAME).withSerial(BigInteger.ONE);
        builder.withPublicKey(ROOT_KEY_PAIR.getPublic());
        builder.withSigningKeyPair(ROOT_KEY_PAIR);
        builder.withInheritedResourceTypes(EnumSet.allOf(IpResourceType.class));
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
