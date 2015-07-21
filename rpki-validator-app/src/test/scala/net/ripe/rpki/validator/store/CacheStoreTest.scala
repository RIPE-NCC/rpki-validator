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
package net.ripe.rpki.validator.store

import java.math.BigInteger
import java.net.URI

import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCmsTest
import net.ripe.rpki.commons.crypto.cms.roa.RoaCmsTest
import net.ripe.rpki.commons.crypto.crl.X509CrlTest
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateTest
import net.ripe.rpki.validator.models.validation._
import net.ripe.rpki.validator.support.ValidatorTestCase
import org.joda.time.Instant
import org.scalatest.BeforeAndAfter

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class CacheStoreTest extends ValidatorTestCase with BeforeAndAfter with Hashing {

  private val memoryDataSource = DataSources.InMemoryDataSource

  private val store = new CacheStore(memoryDataSource)

  val testCrl = X509CrlTest.createCrl
  val testManifest = ManifestCmsTest.getRootManifestCms
  val testManifest1 = ManifestCmsTest.getRootManifestBuilder.withManifestNumber(new BigInteger("222")).
    build(ManifestCmsTest.MANIFEST_KEY_PAIR.getPrivate)
  val testRoa = RoaCmsTest.getRoaCms
  val testCertificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate

  before {
    store.clear()
  }

  test("Store a certificate") {
    val certificate = CertificateObject(url = "rsync://bla", decoded = testCertificate)

    store.storeCertificate(certificate)

    val obj = store.getObject(stringify(certificate.hash)).get.asInstanceOf[CertificateObject]
    obj.url should be(certificate.url)
    obj.aki should be(certificate.aki)
    obj.ski should be(certificate.ski)
    obj.encoded should be(certificate.encoded)
    obj.hash should be(certificate.hash)
  }

  test("Store a certificate and get it by URL") {
    val certificate = CertificateObject(url = "rsync://bla", decoded = testCertificate)

    store.storeCertificate(certificate)

    val seq = store.getCertificate("rsync://bla")
    seq should not be empty
    val obj = seq.head
    obj.url should be(certificate.url)
    obj.aki should be(certificate.aki)
    obj.ski should be(certificate.ski)
    obj.encoded should be(certificate.encoded)
    obj.hash should be(certificate.hash)
  }

  test("Store a crl") {
    val crl = CrlObject(url = "rsync://bla", decoded = testCrl)

    store.storeCrl(crl)

    val obj = store.getObject(stringify(crl.hash)).get.asInstanceOf[CrlObject]

    obj.url should be(crl.url)
    obj.aki should be(crl.aki)
    obj.encoded should be(crl.encoded)
    obj.hash should be(crl.hash)
  }


  test("Store a manifest") {
    val manifest = ManifestObject(url = "rsync://bla", decoded = testManifest)

    store.storeManifest(manifest)

    val manifests: Seq[ManifestObject] = store.getManifests(manifest.aki)
    manifests should have length 1

    val head = manifests.head
    head.url should be(manifest.url)
    head.aki should be(manifest.aki)
    head.encoded should be(manifest.encoded)
    head.hash should be(manifest.hash)
  }

  test("Store a roa") {
    val roa = RoaObject(url = "rsync://bla", decoded = testRoa)

    store.storeRoa(roa)

    val obj = store.getObject(stringify(roa.hash)).get.asInstanceOf[RoaObject]

    obj.url should be(roa.url)
    obj.aki should be(roa.aki)
    obj.encoded should be(roa.encoded)
    obj.hash should be(roa.hash)
  }

  test("Do not store the same object twice") {
    val roa = RoaObject(url = "rsync://bla", decoded = testRoa)
    store.storeRoa(roa)
    store.storeRoa(roa)

    store.getObject(stringify(roa.hash)).get
  }

  test("Do not store the same certificate twice") {
    val certificate = CertificateObject(url = "rsync://bla", decoded = testCertificate)

    store.storeCertificate(certificate)
    store.storeCertificate(certificate)

    store.getObject(stringify(certificate.hash)).get
  }

  test("Update validation timestamp") {
    val roa: RoaObject = RoaObject(url = "rsync://bla.roa", decoded = testRoa)
    store.storeRoa(roa)

    val certificate = CertificateObject(url = "rsync://bla.cer", decoded = testCertificate)
    store.storeCertificate(certificate)

    val newTime = Instant.now
    store.updateValidationTimestamp(Seq(roa.hash, certificate.hash), newTime)

    val roaObject = store.getObject(stringify(roa.hash)).get
    roaObject.validationTime should be(Some(newTime))

    val certificateObject = store.getObject(stringify(certificate.hash)).get
    certificateObject.validationTime should be(Some(newTime))
  }

  test("Delete old objects") {

    val roa: RoaObject = RoaObject(url = "rsync://bla.roa", decoded = testRoa)
    store.storeRoa(roa)

    val certificate = CertificateObject(url = "rsync://bla.cer", decoded = testCertificate)
    store.storeCertificate(certificate)

    val timeInThePast = Instant.now.minus(3600 * 1000 * (store.deletionDelay + 1))
    store.updateValidationTimestamp(Seq(roa.hash, certificate.hash), timeInThePast)

    store.clearObjects(Instant.now)

    store.getObject(stringify(roa.hash)).isEmpty should be(true)

    store.getObject(stringify(certificate.hash)).isEmpty should be(true)
  }

  test("Delete objects never validated") {

    val roa: RoaObject = RoaObject(url = "rsync://bla.roa", decoded = testRoa)
    store.storeRoa(roa)

    val certificate = CertificateObject(url = "rsync://bla.cer", decoded = testCertificate)
    store.storeCertificate(certificate)

    val timeInTheFuture = Instant.now.plus(3600 * 1000 * (store.deletionDelay + 1))

    store.clearObjects(timeInTheFuture)

    store.getObject(stringify(roa.hash)).isEmpty should be(true)

    store.getObject(stringify(certificate.hash)).isEmpty should be(true)
  }

  test("Should return both objects and certificates matching the url") {
    val myUrl = "rsync://bla"
    val certificate = CertificateObject(url = myUrl, decoded = testCertificate)
    val roa = RoaObject(url = myUrl, decoded = testRoa)
    val manifest = ManifestObject(url = myUrl, decoded = testManifest)
    val crl = CrlObject(url = myUrl, decoded = testCrl)
    val someOtherCrl = CrlObject(url = "rsync:bla.bla", decoded = testCrl)

    store.storeCrl(crl)
    store.storeManifest(manifest)
    store.storeCertificate(certificate)
    store.storeRoa(roa)
    store.storeCrl(someOtherCrl)

    val objects = store.getObject(myUrl)

//    objects should have size 4

    objects.foreach {
      case c: CertificateObject => c.decoded should be(certificate.decoded)
      case c: RoaObject => c.decoded should be(roa.decoded)
      case c: ManifestObject => c.decoded should be(manifest.decoded)
      case c: CrlObject => c.decoded should be(crl.decoded)
    }
  }

  test("Should return an empty Seq when nothing matches the url") {
    val objects = store.getObject("rsync:bla")
    objects should be(None)
  }

  test("Should delete older object with the same URI") {
    val mft1 = ManifestObject(url = "rsync://bla.mft", decoded = testManifest)
    val mft2 = ManifestObject(url = "rsync://bla.mft", decoded = testManifest1)
    store.storeManifest(mft1)
    store.storeManifest(mft2)

    store.getManifests(mft1.aki) should have size 2

    val uri = new URI("rsync://bla.mft")
    store.cleanOutdated(Map(uri -> Seq((uri, mft1.hash))))

    val manifests = store.getManifests(mft1.aki)
    manifests should have size 1
    manifests.head.hash should be(mft1.hash)

  }

}
