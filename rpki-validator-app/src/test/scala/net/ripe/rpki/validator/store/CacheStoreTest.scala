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

import scala.util.Try

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

    val obj = store.getObjects(stringify(certificate.hash)).map(_.asInstanceOf[CertificateObject])
    obj.head.url should be(certificate.url)
    obj.head.aki should be(certificate.aki)
    obj.head.ski should be(certificate.ski)
    obj.head.encoded should be(certificate.encoded)
    obj.head.hash should be(certificate.hash)
  }

  test("Store a certificate and get it by URL") {
    val certificate = CertificateObject(url = "rsync://bla", decoded = testCertificate)

    store.storeCertificate(certificate)

    val seq = store.getCertificates("rsync://bla")
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

    val obj = store.getObjects(stringify(crl.hash)).map(_.asInstanceOf[CrlObject])

    obj.head.url should be(crl.url)
    obj.head.aki should be(crl.aki)
    obj.head.encoded should be(crl.encoded)
    obj.head.hash should be(crl.hash)
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

  test("DB concurrency") {
    val manifest = ManifestObject(url = "rsync://bla", decoded = testManifest)

    val timeToGo = System.currentTimeMillis() + 100
    val results = (1 to 2*Runtime.getRuntime.availableProcessors()).par.map { t =>
      val sleepTime = timeToGo - System.currentTimeMillis()
      if (sleepTime > 1) Thread.sleep(sleepTime)
      Try(store.storeManifest(manifest))
    }

    results.filter(_.isFailure) should have length 0

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

    val obj = store.getObjects(stringify(roa.hash)).map(_.asInstanceOf[RoaObject])

    obj.head.url should be(roa.url)
    obj.head.aki should be(roa.aki)
    obj.head.encoded should be(roa.encoded)
    obj.head.hash should be(roa.hash)
  }

  test("Do not store the same object twice") {
    val roa = RoaObject(url = "rsync://bla", decoded = testRoa)
    store.storeRoa(roa)
    store.storeRoa(roa)

    store.getObjects(stringify(roa.hash)).size should be(1)
  }

  test("Do not store the same certificate twice") {
    val certificate = CertificateObject(url = "rsync://bla", decoded = testCertificate)

    store.storeCertificate(certificate)
    store.storeCertificate(certificate)

    store.getObjects(stringify(certificate.hash)).size should be(1)
  }

  test("Update validation timestamp") {
    val roa: RoaObject = RoaObject(url = "rsync://bla.roa", decoded = testRoa)
    store.storeRoa(roa)

    val certificate = CertificateObject(url = "rsync://bla.cer", decoded = testCertificate)
    store.storeCertificate(certificate)

    val newTime = Instant.now
    store.updateValidationTimestamp(Seq(roa.hash, certificate.hash), newTime)

    val roaObject = store.getObjects(stringify(roa.hash))
    roaObject.head.validationTime should be(Some(newTime))

    val certificateObject = store.getObjects(stringify(certificate.hash))
    certificateObject.head.validationTime should be(Some(newTime))
  }

  test("Delete old objects") {

    val roa: RoaObject = RoaObject(url = "rsync://bla.roa", decoded = testRoa)
    store.storeRoa(roa)

    val certificate = CertificateObject(url = "rsync://bla.cer", decoded = testCertificate)
    store.storeCertificate(certificate)

    val timeInThePast = Instant.now.minus(store.oldObjectsDeletionDelay.toMillis + 1)
    store.updateValidationTimestamp(Seq(roa.hash, certificate.hash), timeInThePast)

    store.clearObjects(Instant.now)

    store.getObjects(stringify(roa.hash)) should be(empty)

    store.getObjects(stringify(certificate.hash)) should be(empty)
  }

  test("Delete objects never validated") {

    val roa: RoaObject = RoaObject(url = "rsync://bla.roa", decoded = testRoa)
    store.storeRoa(roa)

    val certificate = CertificateObject(url = "rsync://bla.cer", decoded = testCertificate)
    store.storeCertificate(certificate)

    val timeInTheFuture = Instant.now.plus(1000000 + store.bogusObjectsDeletionDelay.toMillis)

    store.clearObjects(timeInTheFuture)

    store.getObjects(stringify(roa.hash)) should be(empty)

    store.getObjects(stringify(certificate.hash)) should be(empty)
  }

  test("Should return both objects and certificates matching the url") {
    val myUrl = "rsync://bla"
    val certificate = CertificateObject(url = myUrl, decoded = testCertificate)
    val roa = RoaObject(url = myUrl, decoded = testRoa)
    val manifest = ManifestObject(url = myUrl, decoded = testManifest)
    val crl = CrlObject(url = myUrl, decoded = testCrl)
    val someOtherCrl = CrlObject(url = "rsync://bla.bla", decoded = testCrl)

    store.storeCrl(crl)
    store.storeManifest(manifest)
    store.storeCertificate(certificate)
    store.storeRoa(roa)
    store.storeCrl(someOtherCrl)

    val objects = store.getObjects(myUrl)

//    objects should have size 4

    objects.foreach {
      case c: CertificateObject => c.decoded should be(certificate.decoded)
      case c: RoaObject => c.decoded should be(roa.decoded)
      case c: ManifestObject => c.decoded should be(manifest.decoded)
      case c: CrlObject => c.decoded should be(crl.decoded)
    }
  }

  test("Should return an empty Seq when nothing matches the url") {
    val objects = store.getObjects("rsync:bla")
    objects should be(Seq())
  }

  test("Should delete older object with the same URI") {
    val mft1 = ManifestObject(url = "rsync://bla.mft", decoded = testManifest)
    val mft2 = ManifestObject(url = "rsync://bla.mft", decoded = testManifest1)
    store.storeManifest(mft1)
    store.storeManifest(mft2)

    store.getManifests(mft1.aki) should have size 2

    val uri = new URI("rsync://bla.mft")
    store.cleanOutdated(Seq((uri, mft1.hash)))

    val manifests = store.getManifests(mft1.aki)
    manifests should have size 1
    manifests.head.hash should be(mft1.hash)

  }

}
