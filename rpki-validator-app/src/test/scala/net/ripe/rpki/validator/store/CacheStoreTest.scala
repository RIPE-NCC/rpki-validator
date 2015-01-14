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

import java.net.URI

import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCmsTest
import net.ripe.rpki.commons.crypto.cms.roa.RoaCmsTest
import net.ripe.rpki.validator.models.validation.{RoaObject, ManifestObject, CrlObject, CertificateObject}
import net.ripe.rpki.validator.support.ValidatorTestCase
import org.apache.commons.dbcp.BasicDataSource
import org.joda.time.{DateTime, DateTimeUtils}
import org.scalatest.BeforeAndAfter
import org.springframework.jdbc.core.JdbcTemplate

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class CacheStoreTest extends ValidatorTestCase with BeforeAndAfter {

  private val memoryDataSource = DataSources.InMemoryDataSource

  val store = new CacheStore(memoryDataSource)

  before {
    store.clear()
  }

  test("Store a certificate") {
    val aki = Array[Byte](1.toByte)
    val certificate = CertificateObject(
      url = "rsync://bla",
      aki = aki,
      encoded = Array[Byte](2.toByte, 99.toByte),
      ski = Array[Byte](3.toByte))

    store.storeCertificate(certificate)

    val certificates: Seq[CertificateObject] = store.getCertificates(aki)
    certificates should have length 1

    val head = certificates.head
    head.url should be(certificate.url)
    head.aki should be(certificate.aki)
    head.ski should be(certificate.ski)
    head.encoded should be(certificate.encoded)
    head.hash should be(certificate.hash)
  }

  test("Store a crl") {
    val aki = Array[Byte](1.toByte)
    val crl = CrlObject(
      url = "rsync://bla",
      aki = aki,
      encoded = Array[Byte](2.toByte, 4.toByte))

    store.storeCrl(crl)

    val crls: Seq[CrlObject] = store.getCrls(aki)
    crls should have length 1

    val head = crls.head
    head.url should be(crl.url)
    head.aki should be(crl.aki)
    head.encoded should be(crl.encoded)
    head.hash should be(crl.hash)
  }


  test("Store a manifest") {
    val aki = Array[Byte](1.toByte)
    val manifest = ManifestObject(
      url = "rsync://bla",
      aki = aki,
      encoded = Array[Byte](2.toByte, 4.toByte))

    store.storeManifest(manifest)

    val manifests: Seq[ManifestObject] = store.getManifests(aki)
    manifests should have length 1

    val head = manifests.head
    head.url should be(manifest.url)
    head.aki should be(manifest.aki)
    head.encoded should be(manifest.encoded)
    head.hash should be(manifest.hash)
  }

  test("Store a roa") {
    val aki = Array[Byte](1.toByte)
    val roa = RoaObject(
      url = "rsync://bla",
      aki = aki,
      encoded = Array[Byte](2.toByte, 4.toByte))

    store.storeRoa(roa)

    val roas: Seq[RoaObject] = store.getRoas(aki)
    roas should have length 1

    val head = roas.head
    head.url should be(roa.url)
    head.aki should be(roa.aki)
    head.encoded should be(roa.encoded)
    head.hash should be(roa.hash)
  }


}