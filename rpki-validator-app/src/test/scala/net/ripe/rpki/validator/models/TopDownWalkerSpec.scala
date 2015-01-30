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

import net.ripe.ipresource.{IpResourceType, IpResourceSet}
import net.ripe.rpki.commons.crypto.ValidityPeriod
import net.ripe.rpki.commons.crypto.cms.manifest.{ManifestCmsBuilder, ManifestCms}
import net.ripe.rpki.commons.crypto.crl.{X509CrlBuilder, X509Crl}
import net.ripe.rpki.commons.crypto.util.PregeneratedKeyPairFactory
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper._
import net.ripe.rpki.commons.crypto.x509cert.{X509CertificateInformationAccessDescriptor, X509ResourceCertificateBuilder, X509ResourceCertificate}
import net.ripe.rpki.commons.validation.{ValidationLocation, ValidationOptions}
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import net.ripe.rpki.validator.fetchers.FetcherConfig
import net.ripe.rpki.validator.models.validation._
import net.ripe.rpki.validator.store.Storage
import net.ripe.rpki.validator.support.ValidatorTestCase
import org.bouncycastle.asn1.x509.KeyUsage
import org.joda.time.{DateTimeZone, DateTime}
import org.scalatest._
import org.scalatest.matchers.{BePropertyMatcher, ShouldMatchers, ClassicMatchers}
import prop._

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class TopDownWalkerSpec extends ValidatorTestCase with BeforeAndAfter { //PropSpec with PropertyChecks

  private val ROOT_SIA_REPO_RSYNC_LOCATION: URI = URI.create("rsync://foo.host/bar/")
  private val ROOT_SIA_MANIFEST_RSYNC_LOCATION: URI = URI.create("rsync://foo.host/bar/manifest.mft")
  private val ROOT_SIA_REPO_HTTP_LOCATION: URI = URI.create("http://foo.host/bar/")
  private val CRL_LOCATION: URI = URI.create("rsync://host/ta.crl")

  private val ROOT_CERTIFICATE_NAME: X500Principal = new X500Principal("CN=For Testing Only, CN=RIPE NCC, C=NL")
  private val ROOT_RESOURCE_SET: IpResourceSet = IpResourceSet.parse("10.0.0.0/8, 192.168.0.0/16, ffce::/16, AS21212")
  private val ROOT_SERIAL_NUMBER: BigInteger = BigInteger.valueOf(900)
  private val VALIDITY_PERIOD: ValidityPeriod = new ValidityPeriod(new DateTime().minusMinutes(1), new DateTime().plusYears(1))
  private val ROOT_KEY_PAIR: KeyPair = PregeneratedKeyPairFactory.getInstance.generate
  private val KEY_PAIR: KeyPair = PregeneratedKeyPairFactory.getInstance.generate
  private val DEFAULT_VALIDATION_OPTIONS: ValidationOptions = new ValidationOptions

  private val THIS_UPDATE_TIME: DateTime = new DateTime(2008, 9, 1, 22, 43, 29, 0, DateTimeZone.UTC)
  private val NEXT_UPDATE_TIME: DateTime = new DateTime(2008, 9, 2, 6, 43, 29, 0, DateTimeZone.UTC)
  private val FOO_CONTENT: Array[Byte] = (0 to 31).map(_.toByte).toArray
  private val BAR_CONTENT: Array[Byte] = (1 to 32).map(_.toByte).toArray

  val ta = getRootResourceCertificate
  val taContext = new CertificateRepositoryObjectValidationContext(URI.create("rsync://host/ta"), ta)

  var certificatesByAki: Seq[CertificateObject] = _
  var manifestsByAki: Seq[ManifestObject] = _

  before {
    certificatesByAki = Seq()
    manifestsByAki = Seq()
  }

  val storage = new Storage {
    override def storeCertificate(certificate: CertificateObject): Unit = ???
    override def getCertificates(aki: Array[Byte]): Seq[CertificateObject] = certificatesByAki
    override def getRoas(aki: Array[Byte]): Seq[RoaObject] = Seq()
    override def getBroken(url: String): Option[BrokenObject] = ???
    override def getBroken: Seq[BrokenObject] = ???
    override def getManifests(aki: Array[Byte]): Seq[ManifestObject] = manifestsByAki
    override def storeBroken(brokenObject: BrokenObject): Unit = ???
    override def storeRoa(Roa: RoaObject): Unit = ???
    override def getCrls(aki: Array[Byte]): Seq[CrlObject] = Seq(CrlObject(CRL_LOCATION.toString, getCrl))
    override def storeCrl(crl: CrlObject): Unit = ???
    override def storeManifest(manifest: ManifestObject): Unit = ???
    override def getCertificate(uri: String): Option[CertificateObject] = ???
    override def delete(url: String, hash: String): Unit = ???
  }

  val fetcher = new net.ripe.rpki.validator.models.validation.RepoFetcher(storage, FetcherConfig("")) {
    override def fetch(repoUri: URI): Seq[String] = Seq()
  }

  test("should ignore expired certificates that are not on the manifest") {
    val subject = new TopDownWalker(taContext, storage, fetcher, DEFAULT_VALIDATION_OPTIONS)(scala.collection.mutable.Set())
    val certLocation = new URI("rsync://repo/1.cer")
    val mftLocation = new URI("rsync://repo/1.mft")
    certificatesByAki = Seq(CertificateObject(certLocation.toString, createExpiredResourceCertificate))
    manifestsByAki = Seq(ManifestObject(mftLocation.toString, createMftWithEntry()))

    val result = subject.execute
    result.get(certLocation) should be('empty)
  }

  test("should warn about expired certificates that are on the manifest") {
    val subject = new TopDownWalker(taContext, storage, fetcher, DEFAULT_VALIDATION_OPTIONS)(scala.collection.mutable.Set())
    val certLocation = new URI("rsync://repo/1.cer")
    val mftLocation = new URI("rsync://repo/1.mft")
    certificatesByAki = Seq(CertificateObject(certLocation.toString, createExpiredResourceCertificate))
    manifestsByAki = Seq(ManifestObject(mftLocation.toString, createMftWithEntry(certLocation)))

    val result = subject.execute
    result.get(certLocation) should be('defined)
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
    builder.withCrlDistributionPoints(CRL_LOCATION)
    builder.withSubjectInformationAccess(
      new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY, ROOT_SIA_REPO_HTTP_LOCATION),
      new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY, ROOT_SIA_REPO_RSYNC_LOCATION),
      new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST, ROOT_SIA_MANIFEST_RSYNC_LOCATION)
    )
    builder.build
  }

  private def extractFileName(uri: URI): String = {
    uri.toString.split('/').last
  }

  private def createMftWithEntry(uri: URI*): ManifestCms = {
    val builder: ManifestCmsBuilder = new ManifestCmsBuilder
    builder.withCertificate(createManifestEECertificate).withManifestNumber(BigInteger.valueOf(68))
    builder.withThisUpdateTime(THIS_UPDATE_TIME).withNextUpdateTime(NEXT_UPDATE_TIME)
    uri.foreach(u => builder.addFile(extractFileName(u), FOO_CONTENT))
    builder.addFile("BaR", BAR_CONTENT)
    builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER)
    builder.build(ROOT_KEY_PAIR.getPrivate)
  }

  private def createManifestEECertificate: X509ResourceCertificate = {
    val builder: X509ResourceCertificateBuilder = new X509ResourceCertificateBuilder
    builder.withCa(false).withSubjectDN(ROOT_CERTIFICATE_NAME).withIssuerDN(ROOT_CERTIFICATE_NAME).withSerial(BigInteger.ONE)
    builder.withPublicKey(ROOT_KEY_PAIR.getPublic)
    builder.withSigningKeyPair(ROOT_KEY_PAIR)
    builder.withInheritedResourceTypes(java.util.EnumSet.allOf(classOf[IpResourceType]))
    builder.withValidityPeriod(new ValidityPeriod(THIS_UPDATE_TIME, NEXT_UPDATE_TIME))
    builder.withCrlDistributionPoints(CRL_LOCATION)
    builder.build
  }

  def createExpiredResourceCertificate: X509ResourceCertificate = {
    val builder: X509ResourceCertificateBuilder = new X509ResourceCertificateBuilder
    builder.withValidityPeriod(new ValidityPeriod(new DateTime().minusYears(2), new DateTime().minusYears(1)))
    builder.withResources(ROOT_RESOURCE_SET)
    builder.withIssuerDN(ROOT_CERTIFICATE_NAME)
    builder.withSubjectDN(new X500Principal("CN=ExpiredCert"))
    builder.withSerial(ROOT_SERIAL_NUMBER.add(BigInteger.ONE))
    builder.withPublicKey(KEY_PAIR.getPublic)
    builder.withSigningKeyPair(ROOT_KEY_PAIR)
    builder.withCrlDistributionPoints(CRL_LOCATION)
    builder.withCa(true)
    builder.withSubjectInformationAccess(
      new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY, ROOT_SIA_REPO_RSYNC_LOCATION),
      new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST, ROOT_SIA_MANIFEST_RSYNC_LOCATION)
    )

    builder.build
  }

  private def getCrl: X509Crl = {
    val builder: X509CrlBuilder = new X509CrlBuilder
    builder.withIssuerDN(ROOT_CERTIFICATE_NAME)
    builder.withThisUpdateTime(new DateTime)
    builder.withNextUpdateTime(new DateTime().plusHours(8))
    builder.withNumber(BigInteger.TEN)
    builder.withAuthorityKeyIdentifier(ROOT_KEY_PAIR.getPublic)

    builder.build(ROOT_KEY_PAIR.getPrivate)
  }
}
