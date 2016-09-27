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
package net.ripe.rpki.validator.models.validation

import java.net.URI
import java.util.Collections

import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateTest
import net.ripe.rpki.commons.validation.ValidationStatus
import net.ripe.rpki.validator.models.{InvalidObject, RepoService, ValidObject, ValidatedObject}
import net.ripe.rpki.validator.store.CacheStore
import net.ripe.rpki.validator.support.ValidatorTestCase
import net.ripe.rpki.validator.util.TrustAnchorLocator
import org.joda.time.Instant
import org.mockito.Mockito.when
import org.mockito.{Matchers, Mockito}
import org.scalatest.BeforeAndAfter
import org.scalatest.mock.MockitoSugar

class TrustAnchorValidationProcessTest extends ValidatorTestCase with MockitoSugar with BeforeAndAfter {

  val mockStore = mock[CacheStore]
  val mockRepoService = mock[RepoService]
  val mockTrustAnchorLocator: TrustAnchorLocator = mock[TrustAnchorLocator]

  val maxStaleDays: Int = 1

  val taName: String = "ripe"

  val enableLooseValidation: Boolean = true

  val taCertUri = new URI("rsync://taCert.cert")

  val matchingCert = CertificateObject("rsync://taCert.cert", X509ResourceCertificateTest.createSelfSignedCaResourceCertificate, None)

  val taValidatorProcess = new TrustAnchorValidationProcess(
    mockTrustAnchorLocator,
    mockStore,
    mockRepoService,
    maxStaleDays,
    taName,
    enableLooseValidation) {

    override def keyInfoMatches(certificate: CertificateObject): Boolean = certificate == matchingCert
  }

  before {
    Mockito.reset(mockStore, mockRepoService, mockTrustAnchorLocator)
    when(mockTrustAnchorLocator.getCertificateLocations).thenReturn(Collections.singletonList(taCertUri))
    when(mockRepoService.visitTrustAnchorCertificate(Matchers.eq(taCertUri), Matchers.eq(true), Matchers.any(classOf[Instant]))).thenReturn(Seq())
    when(mockRepoService.visitRepo(Matchers.eq(false), Matchers.any(classOf[Instant]))(Matchers.eq(matchingCert.decoded.getRepositoryUri))).thenReturn(Seq())
  }

  test("Should return validObject for trust anchor certificate without errors") {
    when(mockStore.getCertificates(taCertUri.toString)).thenReturn(Seq(matchingCert))
    when(mockStore.getManifests(matchingCert.aki)).thenReturn(Seq())

    val validation = taValidatorProcess.runProcess(false)

    val validatedObject = validation.toOption.get.find(vo => vo.uri == taCertUri && vo.isInstanceOf[ValidObject])
    validatedObject.isDefined should be(true)
    validatedObject.get.validationStatus should equal(ValidationStatus.PASSED)
  }

  test("Should return inValidObject when no valid ta certificate found") {
    when(mockStore.getCertificates(taCertUri.toString)).thenReturn(Seq())

    val validation = taValidatorProcess.runProcess(false)

    val validatedObject: ValidatedObject = validation.toOption.get.find(vo => vo.uri == taCertUri).get
    validatedObject.isInstanceOf[InvalidObject] should be(true)
    validatedObject.validationStatus should equal(ValidationStatus.ERROR)
  }

  test("Should return inValidObject when more than one matching ta certificate found") {
    when(mockStore.getCertificates(taCertUri.toString)).thenReturn(Seq(matchingCert, matchingCert))

    val validation = taValidatorProcess.runProcess(false)

    val validatedObject: ValidatedObject = validation.toOption.get.find(vo => vo.uri == taCertUri).get
    validatedObject.isInstanceOf[InvalidObject] should be(true)
    validatedObject.validationStatus should equal(ValidationStatus.ERROR)
  }

  test("Should just warn when more than one object is found with the uri of the ta certificate but only one matches the ta certificate") {
    val cert2 = mock[CertificateObject]
    when(mockStore.getCertificates(taCertUri.toString)).thenReturn(Seq(matchingCert, cert2))
    when(mockStore.getManifests(matchingCert.aki)).thenReturn(Seq())

    val validation = taValidatorProcess.runProcess(false)

    val validatedObject = validation.toOption.get.find(vo => vo.uri == taCertUri && vo.isInstanceOf[ValidObject])
    validatedObject.isDefined should be(true)
    validatedObject.get.validationStatus should equal(ValidationStatus.WARNING)
  }
}
