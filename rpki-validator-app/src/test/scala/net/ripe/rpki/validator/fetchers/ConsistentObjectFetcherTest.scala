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
package net.ripe.rpki.validator.fetchers

import net.ripe.rpki.validator.store.DataSources
import net.ripe.rpki.validator.store.RepositoryObjectStore
import net.ripe.rpki.commons.rsync.Rsync
import net.ripe.rpki.validator.util.UriToFileMapper
import java.io.File
import java.net.URI
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject
import net.ripe.rpki.commons.validation._
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import net.ripe.rpki.commons.validation.ValidationString._
import net.ripe.rpki.commons.util.Specification
import net.ripe.rpki.commons.util.Specifications
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCmsTest
import net.ripe.rpki.commons.crypto.crl.X509CrlTest
import net.ripe.rpki.commons.crypto.cms.roa.RoaCmsTest
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateTest
import net.ripe.rpki.validator.models.StoredRepositoryObject
import org.scalatest.BeforeAndAfter
import org.scalatest.mock.MockitoSugar
import org.mockito.Matchers._
import org.mockito.Mockito._
import org.mockito.stubbing.Answer
import org.mockito.invocation.InvocationOnMock
import java.util
import scala.Some
import scala.collection.JavaConverters._
import net.ripe.rpki.validator.support.ValidatorTestCase

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class ConsistentObjectFetcherTest extends ValidatorTestCase with BeforeAndAfter with MockitoSugar {


  val issuingCertificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate
  val baseUri = issuingCertificate.getRepositoryUri
  val baseValidationContext = new CertificateRepositoryObjectValidationContext(baseUri, issuingCertificate)

  def resolveFileName(uri: URI): String = new File(uri.getPath).getName

  val crl = X509CrlTest.createCrl
  val crlUri = X509ResourceCertificateTest.TEST_TA_CRL
  val crlFileName = resolveFileName(crlUri)

  val roa = RoaCmsTest.getRoaCms
  val roaFileName = "roa.roa"
  val roaUri = baseUri.resolve(roaFileName)

  val mftBuilder = ManifestCmsTest.getRootManifestBuilder
  mftBuilder.addFile(crlFileName, crl.getEncoded)
  mftBuilder.addFile(roaFileName, roa.getEncoded)

  val mft = mftBuilder.build(ManifestCmsTest.MANIFEST_KEY_PAIR.getPrivate)
  val mftUri = issuingCertificate.getManifestUri
  val mftFileName = resolveFileName(mftUri)

  test("Should store consistent set") {
    val store = new RepositoryObjectStore(DataSources.InMemoryDataSource)

    val entries = Map(
      mftUri -> mft,
      crlUri -> crl,
      roaUri -> roa)

    val rsyncFetcher = new TestRemoteObjectFetcher(entries)

    val subject = new ConsistentObjectFetcher(remoteObjectFetcher = rsyncFetcher, store = store)

    val validationResult = ValidationResult.withLocation(mftUri)

    subject.getManifest(mftUri, baseValidationContext, validationResult) should equal(mft)

    validationResult.hasFailures should be(false)
    store.getLatestByUrl(mftUri) should equal(Some(StoredRepositoryObject(uri = mftUri, binary = mft.getEncoded)))
    store.getLatestByUrl(crlUri) should equal(Some(StoredRepositoryObject(uri = crlUri, binary = crl.getEncoded)))
    store.getLatestByUrl(roaUri) should equal(Some(StoredRepositoryObject(uri = roaUri, binary = roa.getEncoded)))
  }

  test("Should fall back to old mft if new content is missing") {

    val store = new RepositoryObjectStore(DataSources.InMemoryDataSource)
    store.put(List(StoredRepositoryObject(uri = mftUri, binary = mft.getEncoded),
                   StoredRepositoryObject(uri = crlUri, binary = crl.getEncoded),
                   StoredRepositoryObject(uri = roaUri, binary = roa.getEncoded)))

    val mftBuilder = ManifestCmsTest.getRootManifestBuilder
    mftBuilder.addFile(crlFileName, crl.getEncoded)

    val mft2 = mftBuilder.build(ManifestCmsTest.MANIFEST_KEY_PAIR.getPrivate)

    val entries = Map(mftUri -> mft2)

    val rsyncFetcher = new TestRemoteObjectFetcher(entries)

    val subject = new ConsistentObjectFetcher(remoteObjectFetcher = rsyncFetcher, store = store)
    val validationResult = ValidationResult.withLocation(mftUri)

    subject.getManifest(mftUri, baseValidationContext, validationResult) should equal(mft)

    validationResult.getWarnings should have size 1
    validationResult.getWarnings.asScala.map(_.getKey) contains
      (List(ValidationString.VALIDATOR_REPOSITORY_INCOMPLETE))

    store.getLatestByUrl(mftUri) should equal(Some(StoredRepositoryObject(uri = mftUri, binary = mft.getEncoded)))
  }

  test("Should fall back to old mft if new content has file not matching hash") {

    val store = new RepositoryObjectStore(DataSources.InMemoryDataSource)
    store.put(List(StoredRepositoryObject(uri = mftUri, binary = mft.getEncoded),
      StoredRepositoryObject(uri = crlUri, binary = crl.getEncoded),
      StoredRepositoryObject(uri = roaUri, binary = roa.getEncoded)))

    val mftWrongHashBuilder = ManifestCmsTest.getRootManifestBuilder
    mftWrongHashBuilder.addFile(crlFileName, crl.getEncoded)
    mftWrongHashBuilder.addFile(roaFileName, Array[Byte](0, 2, 3)) // <-- wrong content

    val mftWrongHash = mftWrongHashBuilder.build(ManifestCmsTest.MANIFEST_KEY_PAIR.getPrivate)

    val entries = Map(
      mftUri -> mftWrongHash,
      crlUri -> crl,
      roaUri -> roa)

    val rsyncFetcher = new TestRemoteObjectFetcher(entries)

    val subject = new ConsistentObjectFetcher(remoteObjectFetcher = rsyncFetcher, store = store)
    val validationResult = ValidationResult.withLocation(mftUri)

    subject.getManifest(mftUri, baseValidationContext, validationResult) should equal(mft)

    // Should see warnings
    validationResult.getWarnings should have size 1
    validationResult.getWarnings.asScala.map(_.getKey) contains
      (List(ValidationString.VALIDATOR_REPOSITORY_INCOMPLETE))

    store.getLatestByUrl(mftUri) should equal(Some(StoredRepositoryObject(uri = mftUri, binary = mft.getEncoded)))
  }

  test("Should store new mft and objects despite inconsistencies if cache is empty") {

    val store = new RepositoryObjectStore(DataSources.InMemoryDataSource)
    store.clear()
    store.getLatestByUrl(mftUri) should equal(None)

    val mftWrongHashBuilder = ManifestCmsTest.getRootManifestBuilder
    mftWrongHashBuilder.addFile(crlFileName, crl.getEncoded)
    mftWrongHashBuilder.addFile(roaFileName, Array[Byte](0, 2, 3)) // <-- wrong content

    val mftWrongHash = mftWrongHashBuilder.build(ManifestCmsTest.MANIFEST_KEY_PAIR.getPrivate)

    val entries = Map(
      mftUri -> mftWrongHash,
      crlUri -> crl,
      roaUri -> roa)

    val rsyncFetcher = new TestRemoteObjectFetcher(entries)

    val subject = new ConsistentObjectFetcher(remoteObjectFetcher = rsyncFetcher, store = store)
    val validationResult = ValidationResult.withLocation(mftUri)

    subject.getManifest(mftUri, baseValidationContext, validationResult) should equal(mftWrongHash)
    store.getLatestByUrl(mftUri) should equal(Some(StoredRepositoryObject(uri = mftUri, binary = mftWrongHash.getEncoded)))
  }

  test("Should get objects by hash") {
    val store = new RepositoryObjectStore(DataSources.InMemoryDataSource)
    store.put(List(StoredRepositoryObject(uri = mftUri, binary = mft.getEncoded),
      StoredRepositoryObject(uri = crlUri, binary = crl.getEncoded),
      StoredRepositoryObject(uri = roaUri, binary = roa.getEncoded)))

    val rsyncFetcher = new TestRemoteObjectFetcher(Map.empty)
    val subject = new ConsistentObjectFetcher(remoteObjectFetcher = rsyncFetcher, store = store)

    val nonExistentUri = URI.create("rsync://some.host/doesnotexist.roa")

    val validationResult = ValidationResult.withLocation(nonExistentUri)
    subject.getObject(nonExistentUri, baseValidationContext, mft.getFileContentSpecification(roaFileName), validationResult) should equal(roa)
  }

  test("Should get crl for mft from cache") {
    val store = new RepositoryObjectStore(DataSources.InMemoryDataSource)
    store.clear()

    store.put(List(StoredRepositoryObject(uri = mftUri, binary = mft.getEncoded),
      StoredRepositoryObject(uri = crlUri, binary = crl.getEncoded),
      StoredRepositoryObject(uri = roaUri, binary = roa.getEncoded)))

    val crl2 = X509CrlTest.createCrl
    crl should not equal(crl2)

    val mft2Builder = ManifestCmsTest.getRootManifestBuilder
    mft2Builder.addFile(crlFileName, crl2.getEncoded)
    mft2Builder.addFile(roaFileName, roa.getEncoded)
    val mft2 = mft2Builder.build(ManifestCmsTest.MANIFEST_KEY_PAIR.getPrivate)

    // New set is inconsistent, but new crl found for crlUri
    val entries = Map(
      mftUri -> mft2,
      crlUri -> crl2)

    val rsyncFetcher = new TestRemoteObjectFetcher(entries)
    val subject = new ConsistentObjectFetcher(remoteObjectFetcher = rsyncFetcher, store = store)
    val validationResult = ValidationResult.withLocation(mftUri)

    subject.getManifest(mftUri, baseValidationContext, validationResult) should equal(mft)
    subject.getCrl(crlUri, baseValidationContext, validationResult) should equal(crl)
  }

}

class TestRemoteObjectFetcher(entries: Map[URI, CertificateRepositoryObject]) extends RsyncRpkiRepositoryObjectFetcher(new Rsync, new UriToFileMapper(new File(System.getProperty("java.io.tmpdir")))) {

  override def prefetch(uri: URI, result: ValidationResult) = {}

  override def fetchContent(uri: URI, specification: Specification[Array[Byte]], result: ValidationResult) = {
    result.setLocation(new ValidationLocation(uri))
    entries.get(uri) match {
      case Some(repositoryObject) =>
        if (result.rejectIfFalse(specification.isSatisfiedBy(repositoryObject.getEncoded), VALIDATOR_FILE_CONTENT, uri.toString())) {
          repositoryObject.getEncoded
        } else {
          null
        }
      case _ =>
        result.rejectIfNull(null, VALIDATOR_READ_FILE, uri.toString);
        null
    }
  }
}
