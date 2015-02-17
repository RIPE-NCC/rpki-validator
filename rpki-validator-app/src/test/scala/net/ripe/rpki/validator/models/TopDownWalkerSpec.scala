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
package net.ripe.rpki.validator.models

import java.math.BigInteger
import java.net.URI
import java.security.KeyPair
import javax.security.auth.x500.X500Principal

import net.ripe.ipresource.{IpResourceSet, IpResourceType}
import net.ripe.rpki.commons.crypto.ValidityPeriod
import net.ripe.rpki.commons.crypto.cms.manifest.{ManifestCms, ManifestCmsBuilder}
import net.ripe.rpki.commons.crypto.crl.{X509Crl, X509CrlBuilder}
import net.ripe.rpki.commons.crypto.util.PregeneratedKeyPairFactory
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper._
import net.ripe.rpki.commons.crypto.x509cert.{X509CertificateInformationAccessDescriptor, X509ResourceCertificate, X509ResourceCertificateBuilder}
import net.ripe.rpki.commons.validation.{ValidationOptions, ValidationString}
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import net.ripe.rpki.validator.fetchers.{Fetcher, FetcherConfig}
import net.ripe.rpki.validator.models.validation._
import net.ripe.rpki.validator.store.{CacheStore, DataSources, HttpFetcherStore, Storage}
import net.ripe.rpki.validator.support.ValidatorTestCase
import org.bouncycastle.asn1.x509.KeyUsage
import org.joda.time.{Instant, DateTime}
import org.scalatest._

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class TopDownWalkerSpec extends ValidatorTestCase with BeforeAndAfterEach {

  private val REPO_LOCATION: URI = URI.create("rsync://foo.host/bar/")
  private val RRDP_NOTIFICATION_LOCATION: URI = URI.create("http://foo.host/bar/notification.xml")
  private val ROOT_MANIFEST_LOCATION: URI = URI.create("rsync://foo.host/bar/manifest.mft")
  private val ROOT_CRL_LOCATION: URI = URI.create("rsync://foo.host/bar/ta.crl")

  private val ROOT_CERTIFICATE_NAME: X500Principal = new X500Principal("CN=For Testing Only, CN=RIPE NCC, C=NL")
  private val CERTIFICATE_NAME: X500Principal = new X500Principal("CN=123")
  private val ROOT_RESOURCE_SET: IpResourceSet = IpResourceSet.parse("10.0.0.0/8, 192.168.0.0/16, ffce::/16, AS21212")
  private val ROOT_SERIAL_NUMBER: BigInteger = BigInteger.valueOf(900)
  private val NOW: DateTime = DateTime.now()
  private val VALIDITY_PERIOD: ValidityPeriod = new ValidityPeriod(NOW.minusMinutes(1), NOW.plusYears(1))
  private val ROOT_KEY_PAIR: KeyPair = PregeneratedKeyPairFactory.getInstance.generate
  private val CERTIFICATE_KEY_PAIR: KeyPair = PregeneratedKeyPairFactory.getInstance.generate
  private val DEFAULT_VALIDATION_OPTIONS: ValidationOptions = new ValidationOptions

  private val storage = new CacheStore(DataSources.InMemoryDataSource)
  private var taContext: CertificateRepositoryObjectValidationContext = _

  private object HashUtil extends Hashing

  override def beforeEach() {
    storage.clear()
    taContext = createTaContext

    val childCertificateCrl = getCrl(CERTIFICATE_NAME, CERTIFICATE_KEY_PAIR)
    storage.storeCrl(CrlObject(REPO_LOCATION + "childCertificateCrl.cer", childCertificateCrl))
  }

  test("should ignore and remove from store expired certificates that are NOT on the manifest and not published") {
    val (expiredCertificateLocation, _) = createExpiredResourceCertificate("expired.cer")
    createMftWithEntry()

    val taCrl = getCrl(ROOT_CERTIFICATE_NAME, ROOT_KEY_PAIR)
    storage.storeCrl(CrlObject(ROOT_CRL_LOCATION.toString, taCrl))

    val subject = new TopDownWalker(taContext, storage, createRepoService(storage), DEFAULT_VALIDATION_OPTIONS, Instant.now)(scala.collection.mutable.Set())

    val result = subject.execute
    result.get(expiredCertificateLocation) should be('empty)
    storage.getCertificate(expiredCertificateLocation.toString) should be('empty)
  }

  test("should WARN about expired certificates that are NOT on the manifest BUT are published") {
    val (expiredCertificateLocation, _) = createExpiredResourceCertificate("expired.cer")
    createMftWithEntry()

    val taCrl = getCrl(ROOT_CERTIFICATE_NAME, ROOT_KEY_PAIR)
    storage.storeCrl(CrlObject(ROOT_CRL_LOCATION.toString, taCrl))

    val validationTime: Instant = new DateTime().minusDays(1).toInstant // before objects are stored in the Storage
    val subject = new TopDownWalker(taContext, storage, createRepoService(storage), DEFAULT_VALIDATION_OPTIONS, validationTime)(scala.collection.mutable.Set())

    val result = subject.execute
    result.get(expiredCertificateLocation).filter(_.hasCheckKey(ValidationString.VALIDATOR_REPOSITORY_EXPIRED_REVOKED_OBJECT)) should be('defined)
  }

  test("should warn about expired certificates that are on the manifest") {

    val (expiredCertificateLocation, _) = createExpiredResourceCertificate("expired.cer")
    createMftWithEntry(expiredCertificateLocation)

    val taCrl = getCrl(ROOT_CERTIFICATE_NAME, ROOT_KEY_PAIR)
    storage.storeCrl(CrlObject(ROOT_CRL_LOCATION.toString, taCrl))

    val subject = new TopDownWalker(taContext, storage, createRepoService(storage), DEFAULT_VALIDATION_OPTIONS, Instant.now)(scala.collection.mutable.Set())

    val result = subject.execute
    result.get(expiredCertificateLocation).exists(_.hasCheckKey(ValidationString.NOT_VALID_AFTER)) should be(true)

    val fetcher = new RepoFetcher(storage, HttpFetcherStore.inMemory, FetcherConfig("")) {
      override def fetch(repoUri: URI): Seq[Fetcher.Error] = Seq()
    }
  }

  test("should ignore revoked certificates that are not on the manifest and not in repository") {

    val (certificateLocation, certificate) = createValidResourceCertificate("expired.cer")
    createMftWithEntry()

    createCrlWithEntry(certificate)
    val subject = new TopDownWalker(taContext, storage, createRepoService(storage), DEFAULT_VALIDATION_OPTIONS, Instant.now)(scala.collection.mutable.Set())

    val result = subject.execute
    result.get(certificateLocation) should be('empty)
  }

  test("should not warn about revoked certificates not on the manifest and not in repository") {

    val (_, certificate) = createValidResourceCertificate("expired.cer")
    createMftWithEntry()

    createCrlWithEntry(certificate)

    val subject = new TopDownWalker(taContext, storage, createRepoService(storage), DEFAULT_VALIDATION_OPTIONS, Instant.now)(scala.collection.mutable.Set())

    val result = subject.execute
    result.get(ROOT_MANIFEST_LOCATION).filter(_.hasCheckKey(ValidationString.VALIDATOR_MANIFEST_DOES_NOT_CONTAIN_FILE)) should be('empty)
  }

  test("should warn about revoked certificates that are NOT on the manifest BUT still published") {

    val (certificateLocation, certificate) = createValidResourceCertificate("expired.cer")
    createMftWithEntry()

    createCrlWithEntry(certificate)

    val validationTime: Instant = new DateTime().minusDays(1).toInstant // before objects are put in the Storage
    val subject = new TopDownWalker(taContext, storage, createRepoService(storage), DEFAULT_VALIDATION_OPTIONS, validationTime)(scala.collection.mutable.Set())

    val result = subject.execute
    result.get(certificateLocation).filter(_.hasCheckKey(ValidationString.VALIDATOR_REPOSITORY_EXPIRED_REVOKED_OBJECT)) should be('defined)
  }

  test("Should prefer rpkiNotify URI over caRepository URI") {
    val subject = new TopDownWalker(taContext, storage, createRepoService(storage), DEFAULT_VALIDATION_OPTIONS, Instant.now)(scala.collection.mutable.Set())
    subject.preferredFetchLocation.get should be(RRDP_NOTIFICATION_LOCATION)
  }

  test("should update validation time for validated objects") {

    val (certificateLocation, certificate) = createValidResourceCertificate("valid.cer")
    createMftWithEntry()
    createCrlWithEntry(certificate)

    val validationTime: Instant = new DateTime().minusDays(1).toInstant // before objects are put in the Storage
    val now = Instant.now()
    val subject = new TopDownWalker(taContext, storage, createRepoService(storage), DEFAULT_VALIDATION_OPTIONS, validationTime)(scala.collection.mutable.Set())

    val result = subject.execute
    val certs = storage.getCertificates(certificate.getAuthorityKeyIdentifier)
    val mfts = storage.getManifests(certificate.getAuthorityKeyIdentifier)
    val crls = storage.getCrls(certificate.getAuthorityKeyIdentifier)

    certs.forall(_.validationTime.exists(now.isBefore(_))) should be(true)
    mfts.forall(_.validationTime.exists(now.isBefore(_))) should be(true)
    crls.forall(_.validationTime.exists(now.isBefore(_))) should be(true)
  }

  def getRootResourceCertificate: X509ResourceCertificate = {
    val builder: X509ResourceCertificateBuilder = new X509ResourceCertificateBuilder
    builder.withSubjectDN(ROOT_CERTIFICATE_NAME)
    builder.withIssuerDN(ROOT_CERTIFICATE_NAME)
    builder.withSerial(ROOT_SERIAL_NUMBER)
    builder.withValidityPeriod(VALIDITY_PERIOD)
    builder.withPublicKey(ROOT_KEY_PAIR.getPublic)
    builder.withCa(true)
    builder.withKeyUsage(KeyUsage.keyCertSign)
    builder.withAuthorityKeyIdentifier(true)
    builder.withSubjectKeyIdentifier(true)
    builder.withResources(ROOT_RESOURCE_SET)
    builder.withAuthorityKeyIdentifier(false)
    builder.withSigningKeyPair(ROOT_KEY_PAIR)
    builder.withCrlDistributionPoints(ROOT_CRL_LOCATION)

    builder.withSubjectInformationAccess(
      new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY, REPO_LOCATION),
      new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_NOTIFY, RRDP_NOTIFICATION_LOCATION),
      new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST, ROOT_MANIFEST_LOCATION)
    )
    builder.build
  }

  private def extractFileName(uri: URI): String = {
    uri.toString.split('/').last
  }

  def createCrlWithEntry(certificate: X509ResourceCertificate) {
    val taCrl = getCrl(ROOT_CERTIFICATE_NAME, ROOT_KEY_PAIR, certificate.getSerialNumber)
    storage.storeCrl(CrlObject(ROOT_CRL_LOCATION.toString, taCrl))
  }

  private def createMftWithEntry(uri: URI*): ManifestCms = {

    val thisUpdateTime = NOW.minusMinutes(1)
    val nextUpdateTime = NOW.plusYears(1)

    val builder: ManifestCmsBuilder = new ManifestCmsBuilder
    builder.withCertificate(createManifestEECertificate).withManifestNumber(BigInteger.valueOf(68))
    builder.withThisUpdateTime(thisUpdateTime).withNextUpdateTime(nextUpdateTime)

    uri.foreach(u => builder.addFile(extractFileName(u), (0 to 31).map(_.toByte).toArray))
    builder.addFile(extractFileName(ROOT_CRL_LOCATION), (1 to 32).map(_.toByte).toArray)

    builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER)

    val manifest = builder.build(ROOT_KEY_PAIR.getPrivate)
    storage.storeManifest(ManifestObject(ROOT_MANIFEST_LOCATION.toString, manifest))

    manifest
  }

  private def createManifestEECertificate: X509ResourceCertificate = {
    val builder: X509ResourceCertificateBuilder = new X509ResourceCertificateBuilder
    builder.withCa(false).withSubjectDN(new X500Principal("CN=EECert")).withIssuerDN(ROOT_CERTIFICATE_NAME).withSerial(BigInteger.ONE)
    builder.withPublicKey(ROOT_KEY_PAIR.getPublic)
    builder.withSigningKeyPair(ROOT_KEY_PAIR)
    builder.withInheritedResourceTypes(java.util.EnumSet.allOf(classOf[IpResourceType]))
    builder.withValidityPeriod(VALIDITY_PERIOD)
    builder.withCrlDistributionPoints(ROOT_CRL_LOCATION)
    builder.build
  }

  def createExpiredResourceCertificate(name: String) = {
    createResourceCertificate(name, new ValidityPeriod(NOW.minusYears(2), NOW.minusYears(1)))
  }

  def createValidResourceCertificate(name: String) = {
    createResourceCertificate(name, new ValidityPeriod(NOW.minusYears(2), NOW.plusYears(1)))
  }

  def createResourceCertificate(name: String, validityPeriod: ValidityPeriod): (URI, X509ResourceCertificate) = {
    val builder: X509ResourceCertificateBuilder = new X509ResourceCertificateBuilder
    builder.withValidityPeriod(validityPeriod)
    builder.withResources(ROOT_RESOURCE_SET)
    builder.withIssuerDN(ROOT_CERTIFICATE_NAME)
    builder.withSubjectDN(CERTIFICATE_NAME)
    builder.withSerial(ROOT_SERIAL_NUMBER.add(BigInteger.ONE))
    builder.withPublicKey(CERTIFICATE_KEY_PAIR.getPublic)
    builder.withSigningKeyPair(ROOT_KEY_PAIR)
    builder.withCrlDistributionPoints(URI.create("rsync://foo.host/bar/i_dont_care.crl"))
    builder.withCa(true)
    builder.withSubjectInformationAccess(
      new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY, REPO_LOCATION),
      new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST, ROOT_MANIFEST_LOCATION)
    )

    val certificate = builder.build

    val certificateLocation = new URI(REPO_LOCATION + name)
    storage.storeCertificate(CertificateObject(certificateLocation.toString, certificate))

    (certificateLocation, certificate)
  }


  private def getCrl(certificateName: X500Principal, keyPair: KeyPair, revokedSerials: BigInteger*): X509Crl = {
    val builder: X509CrlBuilder = new X509CrlBuilder
    builder.withIssuerDN(certificateName)
    builder.withThisUpdateTime(NOW)
    builder.withNextUpdateTime(NOW.plusHours(8))
    builder.withNumber(BigInteger.TEN)
    builder.withAuthorityKeyIdentifier(keyPair.getPublic)

    revokedSerials.foreach {
      i => builder.addEntry(i, NOW.minusDays(1))
    }

    builder.build(keyPair.getPrivate)
  }

  def createRepoService(storage: Storage): RepoService = {
    new RepoService(new RepoFetcher(storage, HttpFetcherStore.inMemory, FetcherConfig(""))) {
      override def visitRepo(repoUri: URI): Seq[Fetcher.Error] = Seq()
    }
  }

  def createTaContext: CertificateRepositoryObjectValidationContext = {
    val ta = getRootResourceCertificate
    val taContext = new CertificateRepositoryObjectValidationContext(URI.create("rsync://host/ta"), ta)
    taContext
  }
}
