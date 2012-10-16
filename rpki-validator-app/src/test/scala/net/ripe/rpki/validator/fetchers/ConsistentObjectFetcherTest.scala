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

import org.scalatest.FunSuite
import org.scalatest.matchers.ShouldMatchers
import net.ripe.rpki.validator.store.DataSources
import net.ripe.rpki.validator.store.RepositoryObjectStore
import net.ripe.certification.validator.fetchers.RsyncCertificateRepositoryObjectFetcher
import net.ripe.commons.certification.rsync.Rsync
import net.ripe.certification.validator.util.UriToFileMapper
import java.io.File
import java.net.URI
import net.ripe.commons.certification.CertificateRepositoryObject
import net.ripe.commons.certification.validation.ValidationResult
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import net.ripe.commons.certification.crl.X509Crl
import net.ripe.commons.certification.validation.ValidationString._
import net.ripe.commons.certification.util.Specification
import net.ripe.commons.certification.util.Specifications
import net.ripe.commons.certification.cms.manifest.ManifestCms
import net.ripe.commons.certification.cms.manifest.ManifestCmsTest
import net.ripe.commons.certification.crl.X509CrlTest
import net.ripe.commons.certification.cms.roa.RoaCmsTest
import net.ripe.commons.certification.validation.ValidationLocation
import net.ripe.commons.certification.x509cert.X509ResourceCertificateTest
import net.ripe.rpki.validator.models.StoredRepositoryObject
import scala.util.Random
import org.scalatest.BeforeAndAfter
import net.ripe.commons.certification.validation.ValidationString
import org.apache.http.impl.client.DefaultHttpClient
import net.ripe.commons.certification.validation.ValidationStatus

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class ConsistentObjectFetcherTest extends FunSuite with ShouldMatchers with BeforeAndAfter {

  val store = new RepositoryObjectStore(DataSources.InMemoryDataSource)
  before {
    store.clear
  }

  val issuingCertificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate
  val baseUri = issuingCertificate.getRepositoryUri
  val baseValidationContext = new CertificateRepositoryObjectValidationContext(mftUri, issuingCertificate)

  val crl = X509CrlTest.createCrl
  val crlFileName = "crl.crl"
  val crlUri = baseUri.resolve(crlFileName)

  val roa = RoaCmsTest.getRoaCms
  val roaFileName = "roa.roa"
  val roaUri = baseUri.resolve(roaFileName)

  val mftBuilder = ManifestCmsTest.getRootManifestBuilder
  mftBuilder.addFile(crlFileName, crl.getEncoded)
  mftBuilder.addFile(roaFileName, roa.getEncoded)

  val mft = mftBuilder.build(ManifestCmsTest.MANIFEST_KEY_PAIR.getPrivate)
  val mftFileName = "mft.mft"
  val mftUri = baseUri.resolve(mftFileName)

  test("Should store consistent set") {
    val entries = Map(
      mftUri -> mft,
      crlUri -> crl,
      roaUri -> roa)

    val rsyncFetcher = new TestRemoteObjectFetcher(entries)

    val subject = new ConsistentObjectFetcher(remoteObjectFetcher = rsyncFetcher, store = store)

    val validationResult = new ValidationResult

    subject.getManifest(mftUri, baseValidationContext, validationResult)

    validationResult.hasFailures should be(false)
    store.getLatestByUrl(mftUri) should equal(Some(StoredRepositoryObject(uri = mftUri, repositoryObject = mft)))
    store.getLatestByUrl(crlUri) should equal(Some(StoredRepositoryObject(uri = crlUri, repositoryObject = crl)))
    store.getLatestByUrl(roaUri) should equal(Some(StoredRepositoryObject(uri = roaUri, repositoryObject = roa)))
  }

  test("Should not store mft when entry is missing") {
    val entries = Map(
      mftUri -> mft,
      roaUri -> roa)

    val rsyncFetcher = new TestRemoteObjectFetcher(entries)

    val subject = new ConsistentObjectFetcher(remoteObjectFetcher = rsyncFetcher, store = store)
    val validationResult = new ValidationResult

    subject.getManifest(mftUri, baseValidationContext, validationResult)

    validationResult.getWarnings should have size 1
    validationResult.getWarnings.get(0).getKey should equal(ValidationString.VALIDATOR_REPOSITORY_INCOMPLETE)
    store.getLatestByUrl(mftUri) should equal(None)

  }

  test("Should not store when wrong hash is found") {

    val mftWrongHashBuilder = ManifestCmsTest.getRootManifestBuilder
    mftWrongHashBuilder.addFile(crlFileName, crl.getEncoded)
    mftWrongHashBuilder.addFile(roaFileName, Array[Byte](0, 2, 3)) // <-- wrong content

    val mftWrongHash = mftWrongHashBuilder.build(ManifestCmsTest.MANIFEST_KEY_PAIR.getPrivate)
    val mftWrongHashFileName = "inconsistenMft.mft"
    val mftWrongHashUri = baseUri.resolve(mftWrongHashFileName)

    val entries = Map(
      mftWrongHashUri -> mftWrongHash,
      crlUri -> crl,
      roaUri -> roa)

    val rsyncFetcher = new TestRemoteObjectFetcher(entries)

    val subject = new ConsistentObjectFetcher(remoteObjectFetcher = rsyncFetcher, store = store)
    val validationResult = new ValidationResult

    subject.getManifest(mftWrongHashUri, baseValidationContext, validationResult)

    // Should see warnings
    validationResult.getWarnings should have size 1
    validationResult.getWarnings.get(0).getKey should equal(ValidationString.VALIDATOR_REPOSITORY_INCONSISTENT)

    // And metrics
    val metrics = validationResult.getMetrics(new ValidationLocation(mftWrongHashUri))
    metrics should have size 1
    metrics.get(0).getName should equal(ValidationString.VALIDATOR_REPOSITORY_INCONSISTENT)

    // And since it's not in the cache, also errors
    val failures = validationResult.getFailures(new ValidationLocation(mftWrongHashUri))
    failures should have size 1
    failures.get(0).getKey should equal(ValidationString.VALIDATOR_REPOSITORY_OBJECT_NOT_IN_CACHE)
    store.getLatestByUrl(mftWrongHashUri) should equal(None)
  }

  test("Should get certificate repository objects from the store") {

    val rsyncFetcher = new TestRemoteObjectFetcher(Map.empty)
    val subject = new ConsistentObjectFetcher(remoteObjectFetcher = rsyncFetcher, store = store)
    val validationResult = new ValidationResult

    store.put(StoredRepositoryObject(uri = mftUri, repositoryObject = mft))
    store.put(StoredRepositoryObject(uri = roaUri, repositoryObject = roa))
    store.put(StoredRepositoryObject(uri = crlUri, repositoryObject = crl))

    // Should get it from store
    subject.getManifest(mftUri, baseValidationContext, validationResult) should equal(mft)
    subject.getObject(roaUri, null, null, validationResult) should equal(roa)
    subject.getCrl(crlUri, null, validationResult) should equal(crl)

    // But should see warnings about fetching
    validationResult.getResult(new ValidationLocation(mftUri), ValidationString.VALIDATOR_REPOSITORY_INCOMPLETE).getStatus() should be(ValidationStatus.WARNING)
    validationResult.getFailuresForCurrentLocation should have size 0

    // And metrics
    val metrics = validationResult.getMetrics(new ValidationLocation(mftUri))
    metrics should have size 1
    metrics.get(0).getName should equal(ValidationString.VALIDATOR_REPOSITORY_INCOMPLETE)
  }

  test("Should get object by hash if we can") {
    val rsyncFetcher = new TestRemoteObjectFetcher(Map.empty)
    val subject = new ConsistentObjectFetcher(remoteObjectFetcher = rsyncFetcher, store = store)
    val validationResult = new ValidationResult

    store.put(StoredRepositoryObject(uri = mftUri, repositoryObject = mft))
    val nonExistentUri = URI.create("rsync://some.host/doesnotexist.roa")
    store.put(StoredRepositoryObject(uri = nonExistentUri, repositoryObject = roa))
    store.put(StoredRepositoryObject(uri = crlUri, repositoryObject = crl))

    subject.getObject(nonExistentUri, null, mft.getFileContentSpecification(roaFileName), validationResult) should equal(roa)
  }

  test("Should give an error in case we can not get the object from the store") {
    val rsyncFetcher = new TestRemoteObjectFetcher(Map.empty)
    val subject = new ConsistentObjectFetcher(remoteObjectFetcher = rsyncFetcher, store = store)
    val validationResult = new ValidationResult

    subject.getManifest(mftUri, baseValidationContext, validationResult) should equal(null)
    validationResult.getWarnings should have size 1
    validationResult.getWarnings.get(0).getKey should equal(ValidationString.VALIDATOR_REPOSITORY_INCOMPLETE)
    validationResult.getFailures(new ValidationLocation(mftUri)) should have size 1
  }

}

class TestRemoteObjectFetcher(entries: Map[URI, CertificateRepositoryObject]) extends RemoteObjectFetcher(new RsyncCertificateRepositoryObjectFetcher(new Rsync, new UriToFileMapper(new File(System.getProperty("java.io.tmpdir")))), Some(new HttpObjectFetcher(new DefaultHttpClient()))) {

  val ALWAYS_TRUE_SPECIFICATION = Specifications.alwaysTrue[Array[Byte]]

  override def prefetch(uri: URI, result: ValidationResult) = {}

  override def getCrl(uri: URI, context: CertificateRepositoryObjectValidationContext, result: ValidationResult) = {
    getObject(uri, context, ALWAYS_TRUE_SPECIFICATION, result).asInstanceOf[X509Crl]
  }

  override def getManifest(uri: URI, context: CertificateRepositoryObjectValidationContext, result: ValidationResult) = {
    getObject(uri, context, ALWAYS_TRUE_SPECIFICATION, result).asInstanceOf[ManifestCms]
  }

  override def getObject(uri: URI, context: CertificateRepositoryObjectValidationContext, specification: Specification[Array[Byte]], result: ValidationResult) = {
    result.setLocation(new ValidationLocation(uri))
    entries.get(uri) match {
      case Some(repositoryObject) =>
        if (result.rejectIfFalse(specification.isSatisfiedBy(repositoryObject.getEncoded), VALIDATOR_FILE_CONTENT, uri.toString())) {
          repositoryObject
        } else {
          null
        }
      case _ =>
        result.rejectIfNull(null, VALIDATOR_READ_FILE, uri.toString);
        null
    }
  }

}

