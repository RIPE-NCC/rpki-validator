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
import java.util
import javax.security.auth.x500.X500Principal

import net.ripe.ipresource.{IpResourceSet, IpResourceType}
import net.ripe.rpki.commons.crypto.ValidityPeriod
import net.ripe.rpki.commons.crypto.cms.manifest.{ManifestCms, ManifestCmsBuilder}
import net.ripe.rpki.commons.crypto.crl.{X509Crl, X509CrlBuilder}
import net.ripe.rpki.commons.crypto.util.PregeneratedKeyPairFactory
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper._
import net.ripe.rpki.commons.crypto.x509cert.{X509CertificateInformationAccessDescriptor, X509ResourceCertificate, X509ResourceCertificateBuilder}
import net.ripe.rpki.commons.validation.ValidationString._
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import net.ripe.rpki.commons.validation.{ValidationOptions, ValidationStatus, ValidationString}
import net.ripe.rpki.validator.fetchers.{Fetcher, FetcherConfig}
import net.ripe.rpki.validator.models.validation._
import net.ripe.rpki.validator.store.{CacheStore, DataSources, HttpFetcherStore, Storage}
import net.ripe.rpki.validator.support.ValidatorTestCase
import org.bouncycastle.asn1.x509.KeyUsage
import org.joda.time.{DateTime, Instant}
import org.scalatest._

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class TopDownWalkerSpec extends ValidatorTestCase with BeforeAndAfterEach with Hashing {

  private val REPO_LOCATION: URI = URI.create("rsync://foo.host/bar/")
  private val RRDP_NOTIFICATION_LOCATION: URI = URI.create("http://foo.host/bar/notification.xml")
  private val ROOT_MANIFEST_LOCATION: URI = URI.create("rsync://foo.host/bar/manifest.mft")
  private val ROOT_CRL_LOCATION: URI = URI.create("rsync://foo.host/bar/ta.crl")

  private val ROOT_CERTIFICATE_NAME: X500Principal = new X500Principal("CN=For Testing Only, CN=RIPE NCC, C=NL")
  private val ROOT_CERTIFICATE_NAME_2: X500Principal = new X500Principal("CN=For Testing Only 2, CN=RIPE NCC, C=NL")
  private val CERTIFICATE_NAME: X500Principal = new X500Principal("CN=123")
  private val ROOT_RESOURCE_SET: IpResourceSet = IpResourceSet.parse("10.0.0.0/8, 192.168.0.0/16, ffce::/16, AS21212")
  private val ROOT_SERIAL_NUMBER: BigInteger = BigInteger.valueOf(900)
  private val NOW: DateTime = DateTime.now()
  private val VALIDITY_PERIOD: ValidityPeriod = new ValidityPeriod(NOW.minusMinutes(1), NOW.plusYears(1))
  private val ROOT_KEY_PAIR: KeyPair = PregeneratedKeyPairFactory.getInstance.generate
  private val ROOT_KEY_PAIR_2: KeyPair = PregeneratedKeyPairFactory.getInstance.generate
  private val CERTIFICATE_KEY_PAIR: KeyPair = PregeneratedKeyPairFactory.getInstance.generate
  private val DEFAULT_VALIDATION_OPTIONS: ValidationOptions = new ValidationOptions

  private val DEFAULT_MANIFEST_NUMBER: BigInteger = BigInteger.valueOf(68)

  private val storage = new CacheStore(DataSources.InMemoryDataSource)
  private var rootResourceCertificate: X509ResourceCertificate = _
  private var taContext: CertificateRepositoryObjectValidationContext = _
  private var taCrl: X509Crl = _

  override def beforeEach() {
    storage.clear()

    rootResourceCertificate  = getRootResourceCertificate
    taContext = new CertificateRepositoryObjectValidationContext(URI.create("rsync://host/ta"), rootResourceCertificate)

    taCrl = getCrl(ROOT_CERTIFICATE_NAME, ROOT_KEY_PAIR)
    storage.storeCrl(CrlObject(ROOT_CRL_LOCATION.toString, taCrl))
  }

  test("should not give warnings when all entries are present in the manifest") {

    val (certificateLocation, certificate) = createLeafResourceCertificate(ROOT_KEY_PAIR, "valid.cer")
    createMftWithCrlAndEntries(ROOT_KEY_PAIR, taCrl.getEncoded, (certificateLocation, certificate.getEncoded))

    val subject = new TopDownWalker(taContext, storage, createRepoService(storage), DEFAULT_VALIDATION_OPTIONS, Instant.now)(scala.collection.mutable.Set())

    val result = subject.execute.map(vo => vo.uri -> vo).toMap

    result should have size 3

    result.get(certificateLocation).get.checks should be ('empty)
    result.get(certificateLocation).get.subjectChain should be("CN=For Testing Only,CN=RIPE NCC,C=NL - certificate")
    result.get(ROOT_CRL_LOCATION).get.checks should be ('empty)
    result.get(ROOT_CRL_LOCATION).get.subjectChain should be ("CN=For Testing Only,CN=RIPE NCC,C=NL - crl")
    result.get(ROOT_MANIFEST_LOCATION).get.checks should be ('empty)
    result.get(ROOT_MANIFEST_LOCATION).get.subjectChain should be ("CN=For Testing Only,CN=RIPE NCC,C=NL - manifest")
  }

  test("should not give warnings for valid certificate with child objects") {

    val childManifestLocation =  URI.create("rsync://foo.host/bar/childManifest.mft")

    val (certificateLocation, certificate) = createValidResourceCertificate(CERTIFICATE_KEY_PAIR, "valid.cer", childManifestLocation)
    createMftWithCrlAndEntries(ROOT_KEY_PAIR, taCrl.getEncoded, (certificateLocation, certificate.getEncoded))

    val childKeyPair = PregeneratedKeyPairFactory.getInstance.generate

    val childCrlLocation = URI.create("rsync://foo.host/bar/child.crl")
    val childCrl = getCrl(new X500Principal("CN=For Testing Only, CN=RIPE NCC, C=NL"), CERTIFICATE_KEY_PAIR)
    storage.storeCrl(CrlObject(URI.create("rsync://foo.host/bar/child.crl").toString, childCrl))

    val (childCertificateLocation, childCertificate) = createChildResourceCertificate(childKeyPair, CERTIFICATE_KEY_PAIR, "validChild.cer",  new X500Principal("CN=124"), CERTIFICATE_NAME)

    createChildMftWithCrlAndEntries(CERTIFICATE_KEY_PAIR, childManifestLocation, CERTIFICATE_NAME, childCrlLocation,
      childCrl.getEncoded, (childCertificateLocation, childCertificate.getEncoded))

    val subject = new TopDownWalker(taContext, storage, createRepoService(storage), DEFAULT_VALIDATION_OPTIONS, Instant.now)(scala.collection.mutable.Set())

    val result = subject.execute.map(vo => vo.uri -> vo).toMap

    result should have size 6

    result.get(certificateLocation).get.checks should be ('empty)
    result.get(ROOT_CRL_LOCATION).get.checks should be ('empty)
    result.get(ROOT_MANIFEST_LOCATION).get.checks should be ('empty)
    result.get(childCertificateLocation).get.checks should be ('empty)
    result.get(childManifestLocation).get.checks should be ('empty)
    result.get(childCrlLocation).get.checks should be ('empty)
  }

  test("should give warning when no mft refers to a certificate that is an object issuer") {

    val (certificateLocation, certificate) = createValidResourceCertificate(CERTIFICATE_KEY_PAIR, "valid.cer", ROOT_MANIFEST_LOCATION)
    createMftWithCrlAndEntries(ROOT_KEY_PAIR, taCrl.getEncoded, (certificateLocation, certificate.getEncoded))

    val subject = new TopDownWalker(taContext, storage, createRepoService(storage), DEFAULT_VALIDATION_OPTIONS, Instant.now)(scala.collection.mutable.Set())

    val result = subject.execute.map(vo => vo.uri -> vo).toMap

    result should have size 3
    result.get(certificateLocation).get.checks should not be 'empty
  }

  test("should give error when a cycle between a manifest and a certificate is found") {
    val childManifestLocation =  URI.create("rsync://foo.host/bar/childManifest.mft")

    val (certificateLocation, certificate) = createValidResourceCertificate(CERTIFICATE_KEY_PAIR, "valid.cer", childManifestLocation)
    createMftWithCrlAndEntries(ROOT_KEY_PAIR, taCrl.getEncoded, (certificateLocation, certificate.getEncoded))

    val childCrlLocation = URI.create("rsync://foo.host/bar/child.crl")
    val childCrl = getCrl(new X500Principal("CN=For Testing Only, CN=RIPE NCC, C=NL"), CERTIFICATE_KEY_PAIR)
    storage.storeCrl(CrlObject(URI.create("rsync://foo.host/bar/child.crl").toString, childCrl))

    createChildMftWithCrlAndEntries(CERTIFICATE_KEY_PAIR, childManifestLocation, CERTIFICATE_NAME, childCrlLocation,
      childCrl.getEncoded, (rootResourceCertificate.getRepositoryUri, rootResourceCertificate.getEncoded))     // Note that the child Mft holds a reference to the root certificate

    val subject = new TopDownWalker(taContext, storage, createRepoService(storage), DEFAULT_VALIDATION_OPTIONS, Instant.now)(scala.collection.mutable.Set())

    val result = subject.execute.map(vo => vo.uri -> vo).toMap

    result.get(childManifestLocation).get.checks should not be 'empty
    result.get(childManifestLocation).get should not be 'isValid
  }

  test("should give error when object referenced in manifest is not found by its hash") {
    val missingHash = Array[Byte] (1, 2, 3, 4)
    val (manifestLocation, _) = createMftWithCrlAndEntries(ROOT_KEY_PAIR, taCrl.getEncoded, ( new URI(REPO_LOCATION + "missing.cer"), missingHash))

    val subject = new TopDownWalker(taContext, storage, createRepoService(storage), DEFAULT_VALIDATION_OPTIONS, Instant.now)(scala.collection.mutable.Set())

    val result = subject.execute.map(vo => vo.uri -> vo).toMap

    result should have size 2
    result.get(manifestLocation).exists(o => o.hasCheckKey(ValidationString.VALIDATOR_REPOSITORY_OBJECT_NOT_IN_CACHE)) should be (true)
    result.get(manifestLocation).get should not be 'isValid
  }

  test("should give error when object is found by hash but location doesn't match location in manifest") {
    val (_, certificate) = createLeafResourceCertificate(CERTIFICATE_KEY_PAIR, "valid.cer")
    val (manifestLocation, _) = createMftWithCrlAndEntries(ROOT_KEY_PAIR, taCrl.getEncoded, (new URI(REPO_LOCATION + "missing.cer"), certificate.getEncoded))

    val subject = new TopDownWalker(taContext, storage, createRepoService(storage), DEFAULT_VALIDATION_OPTIONS, Instant.now)(scala.collection.mutable.Set())

    val result = subject.execute.map(vo => vo.uri -> vo).toMap

    result should have size 3
    val mft = result.get(manifestLocation)
    mft.exists(_.hasCheckKey(ValidationString.VALIDATOR_MANIFEST_URI_MISMATCH)) should be (true)
    mft.exists(_.isValid) should be (true)
  }

  test("should warn about expired certificates that are on the manifest") {

    val (expiredCertificateLocation, cert) = createExpiredResourceCertificate(CERTIFICATE_KEY_PAIR, "expired.cer")
    createMftWithCrlAndEntries(ROOT_KEY_PAIR, taCrl.getEncoded, (expiredCertificateLocation, cert.getEncoded))

    val subject = new TopDownWalker(taContext, storage, createRepoService(storage), DEFAULT_VALIDATION_OPTIONS, Instant.now)(scala.collection.mutable.Set())

    val result = subject.execute.map(vo => vo.uri -> vo).toMap

    result.get(expiredCertificateLocation).exists(o => o.hasCheckKey(ValidationString.NOT_VALID_AFTER) && o.uri == expiredCertificateLocation) should be(true)
  }

  test("should ignore alert messages for revoked certificates that are not on the manifest and not in repository") {

    val (certificateLocation, certificate) = createValidResourceCertificate(CERTIFICATE_KEY_PAIR, "valid.cer", ROOT_MANIFEST_LOCATION)
    val crl = createCrlWithEntry(certificate)
    createMftWithCrlAndEntries(crl.getEncoded)

    val subject = new TopDownWalker(taContext, storage, createRepoService(storage), DEFAULT_VALIDATION_OPTIONS, Instant.now)(scala.collection.mutable.Set())

    val result = subject.execute.map(vo => vo.uri -> vo).toMap

    result.get(certificateLocation) should be('empty)
  }

  test("should not warn about revoked certificates not on the manifest and not in repository") {

    val (_, certificate) = createValidResourceCertificate(CERTIFICATE_KEY_PAIR, "expired.cer", ROOT_MANIFEST_LOCATION)
    val crl = createCrlWithEntry(certificate)
    createMftWithCrlAndEntries(crl.getEncoded)

    val subject = new TopDownWalker(taContext, storage, createRepoService(storage), DEFAULT_VALIDATION_OPTIONS, Instant.now)(scala.collection.mutable.Set())

    val result = subject.execute.map(vo => vo.uri -> vo).toMap

    result.get(ROOT_MANIFEST_LOCATION).filter(_.hasCheckKey(ValidationString.VALIDATOR_MANIFEST_DOES_NOT_CONTAIN_FILE)) should be('empty)
  }

  test("Should prefer rpkiNotify URI over caRepository URI") {
    val subject = new TopDownWalker(taContext, storage, createRepoService(storage), DEFAULT_VALIDATION_OPTIONS, Instant.now)(scala.collection.mutable.Set())

    subject.preferredFetchLocation.get should be(RRDP_NOTIFICATION_LOCATION)
  }

  test("should update validation time for validated objects") {

    val (certificateLocation, certificate) = createValidResourceCertificate(CERTIFICATE_KEY_PAIR, "valid.cer", ROOT_MANIFEST_LOCATION)
    val cert = CertificateObject("", certificate)
    val crl = CrlObject("", createCrlWithEntry(certificate))
    val mft = ManifestObject("", createMftWithCrlAndEntries(crl.encoded, (certificateLocation, certificate.getEncoded))._2)

    val validationTime: Instant = new DateTime().minusDays(1).toInstant // before objects are put in the Storage
    val now = Instant.now()
    val subject = new TopDownWalker(taContext, storage, createRepoService(storage), DEFAULT_VALIDATION_OPTIONS, validationTime)(scala.collection.mutable.Set())

    subject.execute

    val certObj = storage.getObjects(stringify(cert.hash))
    val crlObj = storage.getObjects(stringify(crl.hash))
    val mftObj = storage.getObjects(stringify(mft.hash))

    certObj.head.validationTime.exists(!now.isAfter(_)) should be(true)
    crlObj.head.validationTime.exists(!now.isAfter(_)) should be(true)
    mftObj.head.validationTime.exists(!now.isAfter(_)) should be(true)
  }

  test("should give error when fetch fails") {

    val (_, certificate) = createValidResourceCertificate(CERTIFICATE_KEY_PAIR, "valid.cer", ROOT_MANIFEST_LOCATION)
    val crl = createCrlWithEntry(certificate)
    createMftWithCrlAndEntries(crl.getEncoded)

    val uri = new URI("http://some.uri")
    val message = "Some message"

    val errors = Seq[Fetcher.Error](new Fetcher.Error(uri, message))
    val subject = new TopDownWalker(taContext, storage, createRepoService(storage, errors), DEFAULT_VALIDATION_OPTIONS, Instant.now)(scala.collection.mutable.Set())

    val result = subject.execute

    val invalidObjects = result.filter(!_.isValid)
    invalidObjects.size should be(1)
    invalidObjects.head.uri should be(uri)
    invalidObjects.head.checks foreach { invalidObject =>
      invalidObject.getStatus should be(ValidationStatus.FETCH_ERROR)
      invalidObject.getKey should be(ValidationString.VALIDATOR_REPO_EXECUTION)
      invalidObject.getParams should contain(message)
    }
  }

  test("should find recent valid manifest with valid CRL") {
    val (_, certificate) = createValidResourceCertificate(CERTIFICATE_KEY_PAIR, "valid.cer", ROOT_MANIFEST_LOCATION)
    val crl = createCrlWithEntry(certificate)
    val (_, manifest) = createMftWithCrlAndEntries(crl.getEncoded)

    val subject = new TopDownWalker(taContext, storage, createRepoService(storage), DEFAULT_VALIDATION_OPTIONS, Instant.now)(scala.collection.mutable.Set())
    val manifestObject = ManifestObject("rsync://host.net/manifest.mft", manifest)
    val result = subject.findRecentValidMftWithCrl(Seq(manifestObject))

    result.get.manifest should be (manifestObject)
    result.get.crl.decoded should be (crl)
    result.get.crl.url should be ("rsync://foo.host/bar/ta.crl")
    result.get.crl.decoded should be (crl)
    result.get.manifestObjects should have size 1
    result.get.manifestObjects.head.url should be ("rsync://foo.host/bar/ta.crl")
    result.get.manifestObjects.head.decoded should be (crl)
    result.get.checksForManifest should have size 0
    result.get.skippedObjects should have size 0
  }

  test("should find recent valid manifest with valid CRL in case there is second invalid more recent manifest") {
    testWithBrokenManifest(DEFAULT_MANIFEST_NUMBER.add(BigInteger.valueOf(1)), 3)
  }

  test("should find recent valid manifest with valid CRL in case there is second invalid older manifest") {
    testWithBrokenManifest(DEFAULT_MANIFEST_NUMBER.subtract(BigInteger.valueOf(1)), 0)
  }

  private def testWithBrokenManifest(manifestNumber: BigInteger, errorNumber: Int) = {
    val (_, certificate) = createValidResourceCertificate(CERTIFICATE_KEY_PAIR, "valid.cer", ROOT_MANIFEST_LOCATION)
    val crl = createCrlWithEntry(certificate)
    val (_, manifest) = createMftWithCrlAndEntries(crl.getEncoded)
    val badManifestBuilder = createMftBuilder(ROOT_KEY_PAIR, ROOT_CERTIFICATE_NAME)

    // add some broken CRL to the bad manifest
    badManifestBuilder.addFile("rsync://host.net/bad_manifest_crl.crl", Array[Byte](1, 2, 3, 4))
    badManifestBuilder.withManifestNumber(manifestNumber)

    val subject = new TopDownWalker(taContext, storage, createRepoService(storage), DEFAULT_VALIDATION_OPTIONS, Instant.now)(scala.collection.mutable.Set())
    val manifestObject = ManifestObject("rsync://host.net/manifest.mft", manifest)
    val badManifestObject = ManifestObject("rsync://host.net/bad_manifest.mft", badManifestBuilder.build(ROOT_KEY_PAIR.getPrivate))
    val result = subject.findRecentValidMftWithCrl(Seq(manifestObject, badManifestObject))

    result.get.manifest should be(manifestObject)
    result.get.crl.decoded should be(crl)
    result.get.crl.url should be("rsync://foo.host/bar/ta.crl")
    result.get.crl.decoded should be(crl)
    result.get.manifestObjects should have size 1
    result.get.manifestObjects.head.url should be("rsync://foo.host/bar/ta.crl")
    result.get.manifestObjects.head.decoded should be(crl)
    result.get.checksForManifest should have size 0

    val skippedObjectsMap = result.get.skippedObjects.map(so => so.uri -> so).toMap
    if (errorNumber > 0) {
      skippedObjectsMap should have size 1
      skippedObjectsMap.get(new URI(badManifestObject.url)).get.checks should have size errorNumber
    } else {
      skippedObjectsMap should have size 0
    }
  }

  test("should find recent valid manifest in case there is second manifest with invalid CRL") {
    val (_, certificate) = createValidResourceCertificate(CERTIFICATE_KEY_PAIR, "valid.cer", ROOT_MANIFEST_LOCATION)
    val goodCrl = createCrlWithEntry(certificate)
    val bogusMftCrl = createCrlWithEntry(certificate, ROOT_KEY_PAIR_2, ROOT_CERTIFICATE_NAME_2, "rsync://host.net/bad_manifest_crl.crl")
    val (_, manifest1) = createMftWithCrlAndEntries(goodCrl.getEncoded)

    // add some broken CRL to the bad manifest
    val bogusManifestBuilder = createMftBuilder(ROOT_KEY_PAIR, ROOT_CERTIFICATE_NAME)
    bogusManifestBuilder.addFile("rsync://host.net/bad_manifest_crl.crl", bogusMftCrl.getEncoded)
    bogusManifestBuilder.withManifestNumber(DEFAULT_MANIFEST_NUMBER.add(BigInteger.valueOf(1)))

    val subject = new TopDownWalker(taContext, storage, createRepoService(storage), DEFAULT_VALIDATION_OPTIONS, Instant.now)(scala.collection.mutable.Set())
    val manifestObject = ManifestObject("rsync://host.net/manifest.mft", manifest1)
    val badManifestObject = ManifestObject("rsync://host.net/bad_manifest.mft", bogusManifestBuilder.build(ROOT_KEY_PAIR.getPrivate))
    val result = subject.findRecentValidMftWithCrl(Seq(manifestObject, badManifestObject))

    result.get.manifest should be(manifestObject)
    result.get.crl.decoded should be(goodCrl)
    result.get.crl.url should be("rsync://foo.host/bar/ta.crl")
    result.get.crl.decoded should be(goodCrl)
    result.get.manifestObjects should have size 1
    result.get.manifestObjects.head.url should be("rsync://foo.host/bar/ta.crl")
    result.get.manifestObjects.head.decoded should be(goodCrl)
    result.get.checksForManifest should have size 0
    result.get.skippedObjects should have size 2
    val skippedObjectsMap = result.get.skippedObjects.map(so => so.uri -> so).toMap
    skippedObjectsMap.get(new URI(badManifestObject.url)).get.checks should have size 1
    skippedObjectsMap.get(new URI(badManifestObject.url)).get.checks.head.getKey should be (ValidationString.VALIDATOR_MANIFEST_IS_INVALID)
    skippedObjectsMap.get(new URI(badManifestObject.url)).get.checks.head.getStatus should be (ValidationStatus.WARNING)
    skippedObjectsMap.get(new URI("rsync://host.net/bad_manifest_crl.crl")).get.checks should have size 2
    skippedObjectsMap.get(new URI("rsync://host.net/bad_manifest_crl.crl")).get.checks.exists(ch => ch.getKey == CRL_AKI_MISMATCH) should be(true)
    skippedObjectsMap.get(new URI("rsync://host.net/bad_manifest_crl.crl")).get.checks.exists(ch => ch.getKey == CRL_SIGNATURE_VALID) should be(true)
  }

  test("should validate only the CRL of the most recent (valid) manifest") {
    val (_, certificate) = createValidResourceCertificate(CERTIFICATE_KEY_PAIR, "valid.cer", ROOT_MANIFEST_LOCATION)
    val goodCrl = createCrlWithEntry(certificate)
    val bogusMftCrl = createCrlWithEntry(certificate, ROOT_KEY_PAIR_2, ROOT_CERTIFICATE_NAME_2, ROOT_CRL_LOCATION.toString)// "bad_manifest_crl.crl")
    val (manifestLocation, _) = createMftWithCrlAndEntries(goodCrl.getEncoded)

    // add some broken CRL to the older manifest
    val bogusManifestBuilder = createMftBuilder(ROOT_KEY_PAIR, ROOT_CERTIFICATE_NAME)
    bogusManifestBuilder.addFile(ROOT_CRL_LOCATION.toString, bogusMftCrl.getEncoded)
    bogusManifestBuilder.withManifestNumber(DEFAULT_MANIFEST_NUMBER.add(BigInteger.valueOf(-1)))
    val bogusManifest = bogusManifestBuilder.build(ROOT_KEY_PAIR.getPrivate)
    storage.storeManifest(ManifestObject("rsync://host.net/bad_manifest.mft", bogusManifest))

    val subject = new TopDownWalker(taContext, storage, createRepoService(storage), DEFAULT_VALIDATION_OPTIONS, Instant.now)(scala.collection.mutable.Set())

    val result = subject.execute.map(vo => vo.uri -> vo).toMap

    result should have size 2 // Only the valid recent manifest and its crl should be here
    result.get(manifestLocation).get should be('isValid)
    result.get(manifestLocation).get.checks should have size 0
    result.get(ROOT_CRL_LOCATION).get should be('isValid)
  }

  test("should skip the recent manifest if its Crl is invalid but return a warning for the manifest and for the crl") {
    val (_, certificate) = createValidResourceCertificate(CERTIFICATE_KEY_PAIR, "valid.cer", ROOT_MANIFEST_LOCATION)
    val goodCrl = createCrlWithEntry(certificate)
    val bogusMftCrl = createCrlWithEntry(certificate, ROOT_KEY_PAIR_2, ROOT_CERTIFICATE_NAME_2, ROOT_CRL_LOCATION.toString)
    val (manifestLocation, _) = createMftWithCrlAndEntries(goodCrl.getEncoded)

    // add some broken CRL to the newer manifest
    val bogusManifestBuilder = createMftBuilder(ROOT_KEY_PAIR, ROOT_CERTIFICATE_NAME)
    bogusManifestBuilder.addFile(ROOT_CRL_LOCATION.toString, bogusMftCrl.getEncoded)
    bogusManifestBuilder.withManifestNumber(DEFAULT_MANIFEST_NUMBER.add(BigInteger.valueOf(1)))
    val bogusManifest = bogusManifestBuilder.build(ROOT_KEY_PAIR.getPrivate)
    storage.storeManifest(ManifestObject(manifestLocation.toString, bogusManifest))

    val subject = new TopDownWalker(taContext, storage, createRepoService(storage), DEFAULT_VALIDATION_OPTIONS, Instant.now)(scala.collection.mutable.Set())

    val result = subject.execute.map(vo => vo.uri -> vo).toMap

    result should have size 2
    result.get(manifestLocation).get should not be 'isValid
    result.get(manifestLocation).get.checks should have size 1
    result.get(manifestLocation).get.checks.head.getStatus should be(ValidationStatus.WARNING)
    result.get(ROOT_CRL_LOCATION).get should not be 'isValid
    result.get(ROOT_CRL_LOCATION).get.checks should have size 2
  }

  test("should give overclaim warning if a child certificate claims more resources than its parent") {
    val childManifestLocation =  URI.create("rsync://foo.host/bar/childManifest.mft")

    val (certificateLocation, certificate) = createValidResourceCertificate(CERTIFICATE_KEY_PAIR, "valid.cer", childManifestLocation)
    createMftWithCrlAndEntries(ROOT_KEY_PAIR, taCrl.getEncoded, (certificateLocation, certificate.getEncoded))

    val childKeyPair = PregeneratedKeyPairFactory.getInstance.generate

    val childCrlLocation = URI.create("rsync://foo.host/bar/child.crl")
    val childCrl = getCrl(new X500Principal("CN=For Testing Only, CN=RIPE NCC, C=NL"), CERTIFICATE_KEY_PAIR)
    storage.storeCrl(CrlObject(URI.create("rsync://foo.host/bar/child.crl").toString, childCrl))

    val (childCertificateLocation, childCertificate) = createOverClaimingResourceCertificate(childKeyPair, CERTIFICATE_KEY_PAIR,
      "validChild.cer", ROOT_MANIFEST_LOCATION, new X500Principal("CN=124"), CERTIFICATE_NAME,
      new ValidityPeriod(NOW.minusYears(2), NOW.plusYears(1)), isObjectIssuer = false)

    createChildMftWithCrlAndEntries(CERTIFICATE_KEY_PAIR, childManifestLocation, CERTIFICATE_NAME, childCrlLocation,
      childCrl.getEncoded, (childCertificateLocation, childCertificate.getEncoded))

    val subject = new TopDownWalker(taContext, storage, createRepoService(storage), DEFAULT_VALIDATION_OPTIONS, Instant.now)(scala.collection.mutable.Set())

    val result = subject.execute.map(vo => vo.uri -> vo).toMap

    result should have size 6
    result.get(childCertificateLocation).get should not be 'isValid
  }

  test("should not give invalid overclaim warning if a certificate inherits its parents resources") {
    val childManifestLocation =  URI.create("rsync://foo.host/bar/childManifest.mft")

    val (certificateLocation, certificate) = createInheritingResourceCertificate(CERTIFICATE_KEY_PAIR, "valid.cer", childManifestLocation)
    createMftWithCrlAndEntries(ROOT_KEY_PAIR, taCrl.getEncoded, (certificateLocation, certificate.getEncoded))

    val childKeyPair = PregeneratedKeyPairFactory.getInstance.generate

    val childCrlLocation = URI.create("rsync://foo.host/bar/child.crl")
    val childCrl = getCrl(new X500Principal("CN=For Testing Only, CN=RIPE NCC, C=NL"), CERTIFICATE_KEY_PAIR)
    storage.storeCrl(CrlObject(URI.create("rsync://foo.host/bar/child.crl").toString, childCrl))

    val (childCertificateLocation, childCertificate) = createChildResourceCertificate(childKeyPair, CERTIFICATE_KEY_PAIR, "validChild.cer", new X500Principal("CN=124"), CERTIFICATE_NAME)

    createChildMftWithCrlAndEntries(CERTIFICATE_KEY_PAIR, childManifestLocation, CERTIFICATE_NAME, childCrlLocation,
      childCrl.getEncoded, (childCertificateLocation, childCertificate.getEncoded))

    val subject = new TopDownWalker(taContext, storage, createRepoService(storage), DEFAULT_VALIDATION_OPTIONS, Instant.now)(scala.collection.mutable.Set())

    val result = subject.execute.map(vo => vo.uri -> vo).toMap

    result should have size 6
    result.get(certificateLocation).get should be('isValid)
    result.get(certificateLocation).get.checks should be ('empty)
    result.get(childCertificateLocation).get should be('isValid)
    result.get(childCertificateLocation).get.checks should be ('empty)
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

  def createEmptyCrl(keyPair: KeyPair) = {
    val taCrl = getCrl(ROOT_CERTIFICATE_NAME, keyPair)
    storage.storeCrl(CrlObject(ROOT_CRL_LOCATION.toString, taCrl))
    taCrl
  }

  private def createCrlWithEntry(certificate: X509ResourceCertificate) : X509Crl =
    createCrlWithEntry(certificate, ROOT_CERTIFICATE_NAME, ROOT_CRL_LOCATION.toString)

  private def createCrlWithEntry(certificate: X509ResourceCertificate, certName: X500Principal, crlLocation: String) : X509Crl =
    createCrlWithEntry(certificate, ROOT_KEY_PAIR, certName, crlLocation)

  private def createCrlWithEntry(certificate: X509ResourceCertificate, keyPair: KeyPair, certName: X500Principal, crlLocation: String) : X509Crl = {
    val taCrl = getCrl(certName, keyPair, certificate.getSerialNumber)
    storage.storeCrl(CrlObject(crlLocation, taCrl))
    taCrl
  }

  private def createMftWithCrlAndEntries(crlContent: Array[Byte], entries: (URI, Array[Byte])*): (URI, ManifestCms) = {
    createMftWithEntries(ROOT_KEY_PAIR, ROOT_MANIFEST_LOCATION, ROOT_CERTIFICATE_NAME, entries.toSeq :+(ROOT_CRL_LOCATION, crlContent):_*)
  }

  private def createMftWithCrlAndEntries(keyPair: KeyPair, crlContent: Array[Byte], entries: (URI, Array[Byte])*): (URI, ManifestCms) = {
    createMftWithEntries(keyPair, ROOT_MANIFEST_LOCATION, ROOT_CERTIFICATE_NAME, entries.toSeq :+(ROOT_CRL_LOCATION, crlContent):_*)
  }

  private def createChildMftWithCrlAndEntries(keyPair: KeyPair, manifestLocation: URI,  issuer: X500Principal, crlLocation: URI, crlContent: Array[Byte], entries: (URI, Array[Byte])*): (URI, ManifestCms) = {
    createMftWithEntries(keyPair, manifestLocation, issuer, entries.toSeq :+(crlLocation, crlContent):_*)
  }


  private def createMftWithEntries(keyPair: KeyPair, manifestLocation: URI, issuer: X500Principal, entries: (URI, Array[Byte])*): (URI, ManifestCms) = {
    val builder = createMftBuilder(keyPair, issuer, entries:_*)

    val manifest = builder.build(keyPair.getPrivate)
    storage.storeManifest(ManifestObject(manifestLocation.toString, manifest))

    (manifestLocation, manifest)
  }

  private def createMftBuilder(keyPair: KeyPair, issuer: X500Principal, entries: (URI, Array[Byte])*): ManifestCmsBuilder = {

    val thisUpdateTime = NOW.minusMinutes(1)
    val nextUpdateTime = NOW.plusYears(1)

    val builder: ManifestCmsBuilder = new ManifestCmsBuilder
    builder.withCertificate(createManifestEECertificate(keyPair, issuer))
      .withManifestNumber(DEFAULT_MANIFEST_NUMBER)
      .withThisUpdateTime(thisUpdateTime)
      .withNextUpdateTime(nextUpdateTime)

    entries.foreach { e =>
      val (u, content) = e
      builder.addFile(extractFileName(u), content)
    }

    builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER)
    builder
  }

  private def createManifestEECertificate(keyPair: KeyPair, issuerDN: X500Principal): X509ResourceCertificate = {
    val builder: X509ResourceCertificateBuilder = new X509ResourceCertificateBuilder
    builder.withCa(false).withSubjectDN(new X500Principal("CN=EECert")).withIssuerDN(issuerDN).withSerial(BigInteger.ONE)
    builder.withPublicKey(keyPair.getPublic)
    builder.withSigningKeyPair(keyPair)
    builder.withInheritedResourceTypes(java.util.EnumSet.allOf(classOf[IpResourceType]))
    builder.withValidityPeriod(VALIDITY_PERIOD)
    builder.withCrlDistributionPoints(ROOT_CRL_LOCATION)
    builder.withKeyUsage(KeyUsage.digitalSignature)
    builder.build
  }

  def createExpiredResourceCertificate(keyPair: KeyPair, locationName: String) = {
    createResourceCertificate(keyPair, ROOT_KEY_PAIR, locationName, ROOT_MANIFEST_LOCATION, CERTIFICATE_NAME, ROOT_CERTIFICATE_NAME,
      new ValidityPeriod(NOW.minusYears(2), NOW.minusYears(1)), isObjectIssuer = true, inheritResources = false)
  }

  def createInheritingResourceCertificate(keyPair: KeyPair, locationName: String, manifestLocation: URI) = {
    createResourceCertificate(keyPair, ROOT_KEY_PAIR, locationName, manifestLocation, CERTIFICATE_NAME, ROOT_CERTIFICATE_NAME,
      new ValidityPeriod(NOW.minusYears(2), NOW.plusYears(1)), isObjectIssuer = true, inheritResources = true)
  }

  def createValidResourceCertificate(keyPair: KeyPair, locationName: String, manifestLocation: URI) = {
    createResourceCertificate(keyPair, ROOT_KEY_PAIR, locationName, manifestLocation, CERTIFICATE_NAME, ROOT_CERTIFICATE_NAME,
      new ValidityPeriod(NOW.minusYears(2), NOW.plusYears(1)), isObjectIssuer = true, inheritResources = false)
  }

  def createLeafResourceCertificate(keyPair: KeyPair, locationName: String) = {
    createResourceCertificate(keyPair, ROOT_KEY_PAIR, locationName, ROOT_MANIFEST_LOCATION, CERTIFICATE_NAME, ROOT_CERTIFICATE_NAME,
      new ValidityPeriod(NOW.minusYears(2), NOW.plusYears(1)), isObjectIssuer = false, inheritResources = false)
  }

  def createChildResourceCertificate(keyPair: KeyPair, parentKeyPair: KeyPair, locationName: String, certificateName: X500Principal, parentName: X500Principal) = {
    createResourceCertificate(keyPair, parentKeyPair, locationName, ROOT_MANIFEST_LOCATION, certificateName, parentName,
      new ValidityPeriod(NOW.minusYears(2), NOW.plusYears(1)), isObjectIssuer = false, inheritResources = false)
  }

  def createOverClaimingResourceCertificate(keyPair: KeyPair, parentKeyPair: KeyPair, locationName: String,
                                            manifestLocation: URI, certificateName: X500Principal, parentName: X500Principal,
                                            validityPeriod: ValidityPeriod, isObjectIssuer: Boolean): (URI, X509ResourceCertificate) = {
    val builder: X509ResourceCertificateBuilder = new X509ResourceCertificateBuilder
    builder.withValidityPeriod(validityPeriod)

    val overClaimingResourceSet = IpResourceSet.parse("127.0.0.0/8")
    builder.withResources(overClaimingResourceSet)
    builder.withIssuerDN(parentName)
    builder.withSubjectDN(certificateName)
    builder.withSerial(ROOT_SERIAL_NUMBER.add(BigInteger.ONE))
    builder.withPublicKey(keyPair.getPublic)
    builder.withAuthorityKeyIdentifier(true)
    builder.withSubjectKeyIdentifier(true)
    builder.withSigningKeyPair(parentKeyPair)
    builder.withCrlDistributionPoints(URI.create("rsync://foo.host/bar/i_dont_care.crl"))

    if (isObjectIssuer) {
      builder.withCa(true)
      builder.withKeyUsage(KeyUsage.digitalSignature + KeyUsage.keyCertSign + KeyUsage.cRLSign)

      builder.withSubjectInformationAccess(
        new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY, REPO_LOCATION),
        new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST, manifestLocation)
      )
    } else {
      builder.withKeyUsage(KeyUsage.digitalSignature)
    }

    val certificate = builder.build

    val certificateLocation = new URI(REPO_LOCATION + locationName)
    storage.storeCertificate(CertificateObject(certificateLocation.toString, certificate))

    certificate.getManifestUri

    (certificateLocation, certificate)
  }

  def createResourceCertificate(keyPair: KeyPair, parentKeyPair: KeyPair, locationName: String, manifestLocation: URI, certificateName: X500Principal, parentName: X500Principal,
                                validityPeriod: ValidityPeriod, isObjectIssuer: Boolean, inheritResources: Boolean): (URI, X509ResourceCertificate) = {
    val builder: X509ResourceCertificateBuilder = new X509ResourceCertificateBuilder
    builder.withValidityPeriod(validityPeriod)
    if (inheritResources) {
      builder.withInheritedResourceTypes(util.EnumSet.allOf(classOf[IpResourceType]))
    } else {
      builder.withResources(ROOT_RESOURCE_SET)
    }
    builder.withIssuerDN(parentName)
    builder.withSubjectDN(certificateName)
    builder.withSerial(ROOT_SERIAL_NUMBER.add(BigInteger.ONE))
    builder.withPublicKey(keyPair.getPublic)
    builder.withAuthorityKeyIdentifier(true)
    builder.withSubjectKeyIdentifier(true)
    builder.withSigningKeyPair(parentKeyPair)
    builder.withCrlDistributionPoints(URI.create("rsync://foo.host/bar/i_dont_care.crl"))

    if (isObjectIssuer) {
      builder.withCa(true)
      builder.withKeyUsage(KeyUsage.digitalSignature + KeyUsage.keyCertSign + KeyUsage.cRLSign)

      builder.withSubjectInformationAccess(
        new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY, REPO_LOCATION),
        new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST, manifestLocation)
      )
    } else {
      builder.withKeyUsage(KeyUsage.digitalSignature)
    }

    val certificate = builder.build

    val certificateLocation = new URI(REPO_LOCATION + locationName)
    storage.storeCertificate(CertificateObject(certificateLocation.toString, certificate))

    certificate.getManifestUri

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

  def createRepoService(storage: Storage, errors: Seq[Fetcher.Error] = Seq()): RepoService = {
    new RepoService(new RepoFetcher(storage, new Fetchers(HttpFetcherStore.inMemory, FetcherConfig("")))) {
      override def visitRepo(repoUri: URI): Seq[Fetcher.Error] = {
        errors
      }
    }
  }

}
