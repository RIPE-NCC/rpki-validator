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

  private val store = new CacheStore(memoryDataSource, TA_NAME)

  val testCrl = X509CrlTest.createCrl
  val testManifest = ManifestCmsTest.getRootManifestCms
  val testRoa = RoaCmsTest.getRoaCms
  val testCertificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate

  before {
    store.clear()
  }

  test("Store a certificate") {
    val certificate = CertificateObject(url = "rsync://bla", decoded = testCertificate)

    store.storeCertificate(certificate)

    val certificates = store.getCertificates(certificate.aki)
    certificates should have length 1

    val head = certificates.head
    head.url should be(certificate.url)
    head.aki should be(certificate.aki)
    head.ski should be(certificate.ski)
    head.encoded should be(certificate.encoded)
    head.hash should be(certificate.hash)
  }

  test("Store a crl") {
    val crl = CrlObject(url = "rsync://bla", decoded = testCrl)

    store.storeCrl(crl)

    val crls: Seq[CrlObject] = store.getCrls(crl.aki)
    crls should have length 1

    val head = crls.head
    head.url should be(crl.url)
    head.aki should be(crl.aki)
    head.encoded should be(crl.encoded)
    head.hash should be(crl.hash)
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

    val roas: Seq[RoaObject] = store.getRoas(roa.aki)
    roas should have length 1

    val head = roas.head
    head.url should be(roa.url)
    head.aki should be(roa.aki)
    head.encoded should be(roa.encoded)
    head.hash should be(roa.hash)
  }

  test("Do not store the same object twice") {
    val roa = RoaObject(url = "rsync://bla", decoded = testRoa)
    store.storeRoa(roa)
    store.storeRoa(roa)

    store.getRoas(roa.aki) should have length 1
  }

  test("Do not store the same certificate twice") {
    val certificate = CertificateObject(url = "rsync://bla", decoded = testCertificate)

    store.storeCertificate(certificate)
    store.storeCertificate(certificate)

    store.getCertificates(certificate.aki) should have length 1
  }

  test("Store twice and fetch a broken object") {
    val broken = BrokenObject(url = "rsync://bla", bytes = Array[Byte](1.toByte, 2.toByte), errorMessage = "Couldn't parse that")

    val now = Instant.now()

    store.storeBroken(broken)
    store.storeBroken(broken)

    store.getBroken should have length 1
    val b = store.getBroken("rsync://bla")
    b.get.url should be(broken.url)
    b.get.hash should be(broken.hash)
    b.get.errorMessage should be(broken.errorMessage)
    b.get.downloadTime.isAfter(now) should be(true)
    b.get.downloadTime.isBefore(now.plus(10000L)) should be(true)
  }

  test("Update validation timestamp") {
    val roa: RoaObject = RoaObject(url = "rsync://bla.roa", decoded = testRoa)
    store.storeRoa(roa)

    val certificate = CertificateObject(url = "rsync://bla.cer", decoded = testCertificate)
    store.storeCertificate(certificate)

    val newTime = Instant.now
    store.updateValidationTimestamp(Seq(roa.url, certificate.url), newTime)

    val roas = store.getRoas(roa.aki)
    roas should have length 1
    roas.head.validationTime should be(Some(newTime))

    val certificates = store.getCertificates(certificate.aki)
    certificates should have length 1
    certificates.head.validationTime should be(Some(newTime))
  }

  test("Should delete objects in batches") {
    val certificate = CertificateObject(url = "rsync://bla.cer", decoded = testCertificate)
    val roa = RoaObject(url = "rsync://bla/bla.roa", decoded = testRoa)
    val manifest = ManifestObject(url = "rsync://bla/bla.mft", decoded = testManifest)
    val crl = CrlObject(url = "rsync://bla/bla.crl", decoded = testCrl)

    store.storeCrl(crl)
    store.storeManifest(manifest)
    store.storeCertificate(certificate)
    store.storeRoa(roa)

    store.delete(Map(
      certificate.url -> stringify(certificate.hash),
      roa.url -> stringify(roa.hash),
      manifest.url -> stringify(manifest.hash)))

    store.getCertificates(certificate.aki) should be(Seq())
    store.getRoas(roa.aki) should be(Seq())
    store.getManifests(manifest.aki) should be(Seq())
    store.getCrls(manifest.aki) should have size 1
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

//    objects should have size 0
  }

}
