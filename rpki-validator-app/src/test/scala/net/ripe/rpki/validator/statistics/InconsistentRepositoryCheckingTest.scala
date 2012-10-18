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
package net.ripe.rpki.validator.statistics

import org.junit.runner.RunWith
import org.scalatest.junit.JUnitRunner
import org.scalatest.FunSuite
import org.scalatest.matchers.ShouldMatchers
import net.ripe.commons.certification.validation.ValidationResult
import net.ripe.rpki.validator.models.ValidatedObject
import net.ripe.rpki.validator.models.ValidObject
import java.net.URI
import net.ripe.commons.certification.x509cert.X509ResourceCertificateBuilder
import javax.security.auth.x500.X500Principal
import java.math.BigInteger
import net.ripe.commons.certification.ValidityPeriod
import org.joda.time.DateTime
import org.bouncycastle.asn1.x509.KeyUsage
import net.ripe.commons.certification.util.KeyPairFactoryTest
import net.ripe.ipresource.IpResourceSet
import net.ripe.commons.certification.x509cert.X509CertificateInformationAccessDescriptor
import net.ripe.commons.certification.x509cert.RpkiSignedObjectEeCertificateBuilder
import net.ripe.ipresource.InheritedIpResourceSet
import net.ripe.commons.certification.cms.manifest.ManifestCmsBuilder
import net.ripe.commons.certification.crl.X509CrlBuilder
import net.ripe.rpki.validator.models.InvalidObject
import net.ripe.rpki.validator.models.InvalidObject
import net.ripe.commons.certification.validation.ValidationCheck
import net.ripe.commons.certification.validation.ValidationStatus
import net.ripe.commons.certification.validation.ValidationString

object InconsistentRepositoryCheckingTest {

  val TA_CER_URI = URI.create("rsync://host/ta.cer")
  val TA_CER_REPO_URI = URI.create("rsync://host/")
  val TA_MFT_URI = URI.create("rsync://host/ta.mft")
  val TA_CRL_URI = URI.create("rsync://host/ta.crl")
  val TA_MISSING_CER_URI = URI.create("rsync://host/missing.cer")
  val TA_UNKNOWN_CER_URI = URI.create("rsync://host/unknown.cer")

  val TA_CER_SUBJECT = new X500Principal("CN=root-cert")
  val TA_CER_VALIDITY = new ValidityPeriod(new DateTime().minusMinutes(1), new DateTime().plusHours(1))
  val TA_CER_KEY_PAIR = KeyPairFactoryTest.TEST_KEY_PAIR
  val TA_CER_RESOURCES = IpResourceSet.parse("10/8")

  val TA_CER_OBJECT = {
    val builder = new X509ResourceCertificateBuilder()
    builder.withCa(true)
    builder.withKeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
    builder.withSubjectDN(TA_CER_SUBJECT)
    builder.withIssuerDN(TA_CER_SUBJECT)
    builder.withSerial(BigInteger.ONE)
    builder.withValidityPeriod(TA_CER_VALIDITY)
    builder.withPublicKey(TA_CER_KEY_PAIR.getPublic)
    builder.withSigningKeyPair(TA_CER_KEY_PAIR)
    builder.withResources(TA_CER_RESOURCES)

    builder.withSubjectInformationAccess(
      new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY, TA_CER_REPO_URI),
      new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST, TA_MFT_URI))

    builder.build
  }

  val TA_CER_VALIDATED_OBJECT = new ValidObject(uri = TA_CER_URI, checks = Set.empty, repositoryObject = TA_CER_OBJECT)

  val TA_CRL_VALIDITY = TA_CER_VALIDITY

  val TA_CRL_OBJECT = {
    val builder = new X509CrlBuilder()
    builder.withIssuerDN(new X500Principal("CN=issuer"));
    builder.withThisUpdateTime(TA_CRL_VALIDITY.getNotValidBefore);
    builder.withNextUpdateTime(TA_CRL_VALIDITY.getNotValidAfter);
    builder.withNumber(BigInteger.TEN);
    builder.withAuthorityKeyIdentifier(TA_CER_KEY_PAIR.getPublic());
    builder.addEntry(BigInteger.TEN, new DateTime().minusDays(1));
    builder.addEntry(BigInteger.valueOf(42), new DateTime().minusDays(3));
    builder.build(TA_CER_KEY_PAIR.getPrivate)
  }

  val TA_CRL_VALIDATED_OBJECT = new ValidObject(uri = TA_CRL_URI, checks = Set.empty, repositoryObject = TA_CRL_OBJECT)

  val MISSING_CER_VALIDATED_OBJECT = new InvalidObject(uri = TA_MISSING_CER_URI, checks = Set(new ValidationCheck(ValidationStatus.ERROR, ValidationString.VALIDATOR_READ_FILE, TA_MISSING_CER_URI.toString)))

  val TA_MFT_SUBJECT = new X500Principal("CN=root-mft")
  val TA_MFT_VALIDITY = TA_CRL_VALIDITY
  val TA_MFT_KEY_PAIR = KeyPairFactoryTest.SECOND_TEST_KEY_PAIR

  val TA_MFT_EE_CER = {
    val builder = new RpkiSignedObjectEeCertificateBuilder()
    builder.withCorrespondingCmsPublicationPoint(TA_MFT_URI)
    builder.withSubjectDN(TA_MFT_SUBJECT)
    builder.withIssuerDN(TA_CER_SUBJECT)
    builder.withSerial(BigInteger.ONE)
    builder.withValidityPeriod(TA_MFT_VALIDITY)
    builder.withPublicKey(TA_MFT_KEY_PAIR.getPublic)
    builder.withSigningKeyPair(TA_CER_KEY_PAIR)
    builder.withResources(InheritedIpResourceSet.getInstance)
    builder.withCrlUri(TA_CRL_URI)
    builder.withParentResourceCertificatePublicationUri(TA_CER_URI)

    builder.build
  }

  val TA_MFT_OBJECT = {
    val builder = new ManifestCmsBuilder()

    builder.withManifestNumber(BigInteger.ONE)
    builder.withThisUpdateTime(TA_MFT_EE_CER.getValidityPeriod.getNotValidBefore)
    builder.withNextUpdateTime(TA_MFT_EE_CER.getValidityPeriod.getNotValidAfter)
    builder.withCertificate(TA_MFT_EE_CER)

    builder.addFile("ta.cer", TA_CER_OBJECT.getEncoded)
    builder.addFile("ta.crl", TA_CRL_OBJECT.getEncoded)

    builder.build(TA_MFT_KEY_PAIR.getPrivate)
  }

  val TA_MFT_VALIDATED_OBJECT = new ValidObject(uri = TA_MFT_URI, checks = Set.empty, repositoryObject = TA_MFT_OBJECT)

  val INCONSISTENT_TA_MFT_OBJECT = {
    val builder = new ManifestCmsBuilder()

    builder.withManifestNumber(BigInteger.ONE)
    builder.withThisUpdateTime(TA_MFT_EE_CER.getValidityPeriod.getNotValidBefore)
    builder.withNextUpdateTime(TA_MFT_EE_CER.getValidityPeriod.getNotValidAfter)
    builder.withCertificate(TA_MFT_EE_CER)

    builder.addFile("ta.cer", TA_CER_OBJECT.getEncoded)
    builder.addFile("missing.cer", TA_CER_OBJECT.getEncoded)
    builder.addFile("ta.crl", TA_CRL_OBJECT.getEncoded)

    builder.build(TA_MFT_KEY_PAIR.getPrivate)
  }

  val INCONSISTENT_TA_MFT_VALIDATED_OBJECT = new ValidObject(uri = TA_MFT_URI, checks = Set.empty, repositoryObject = INCONSISTENT_TA_MFT_OBJECT)

  val CONSISTENT_OBJECT_SET = List(
    TA_CER_VALIDATED_OBJECT,
    TA_CRL_VALIDATED_OBJECT,
    TA_MFT_VALIDATED_OBJECT).map {
      vo => (vo.uri, vo)
    }.toMap

  val INCONSISTENT_OBJECT_SET = List(
    TA_CER_VALIDATED_OBJECT,
    TA_CRL_VALIDATED_OBJECT,
    INCONSISTENT_TA_MFT_VALIDATED_OBJECT,
    MISSING_CER_VALIDATED_OBJECT).map {
      vo => (vo.uri, vo)
    }.toMap

}

@RunWith(classOf[JUnitRunner])
class InconsistentRepositoryCheckingTest extends FunSuite with ShouldMatchers {


  test("should find valid certificates in objects") {
    val validCerts = InconsistentRepositoryChecker.validCaCertificates(InconsistentRepositoryCheckingTest.INCONSISTENT_OBJECT_SET.values.toSeq)
    validCerts should have size (1)
  }

  test("should get full URIs from manifest option") {
    val uris = InconsistentRepositoryChecker.getManifestEntryUris(InconsistentRepositoryCheckingTest.TA_CER_OBJECT.getRepositoryUri, Some(InconsistentRepositoryCheckingTest.TA_MFT_OBJECT))

    uris should have size (2)
    uris should contain(InconsistentRepositoryCheckingTest.TA_CER_URI)
    uris should contain(InconsistentRepositoryCheckingTest.TA_CRL_URI)
  }

  test("should find validated objects for uri seq") {
    val validatedObjects = InconsistentRepositoryChecker.findObjectsForUris(InconsistentRepositoryCheckingTest.INCONSISTENT_OBJECT_SET, InconsistentRepositoryChecker.getManifestEntryUris(InconsistentRepositoryCheckingTest.TA_CER_OBJECT.getRepositoryUri, Some(InconsistentRepositoryCheckingTest.TA_MFT_OBJECT)))
    validatedObjects should have size (2)
    validatedObjects should contain (InconsistentRepositoryCheckingTest.TA_CER_VALIDATED_OBJECT: ValidatedObject)
    validatedObjects should contain (InconsistentRepositoryCheckingTest.TA_CRL_VALIDATED_OBJECT: ValidatedObject)
  }

  test("should create InvalidObject for uri we have no validation data for") {
    val validatedObjects = InconsistentRepositoryChecker.findObjectsForUris(InconsistentRepositoryCheckingTest.INCONSISTENT_OBJECT_SET, List(InconsistentRepositoryCheckingTest.TA_UNKNOWN_CER_URI))

    validatedObjects should have size (1)

    val invalidObjectForUnknown = validatedObjects(0)

    invalidObjectForUnknown.isInstanceOf[InvalidObject] should be(true)
    invalidObjectForUnknown.checks should have size(0) // This is indicative of a programming error in our validator, but should not result in flagging a repo as inconsistent.

  }

  test("should find no inconsistent CA when all okay") {
    val inconsistentCAs = InconsistentRepositoryChecker.check(InconsistentRepositoryCheckingTest.CONSISTENT_OBJECT_SET)
    inconsistentCAs.filter(_._2 == true) should have size(0)
  }

  test("should find inconsistent CA when mft entry is missing") {
    val inconsistentCAs = InconsistentRepositoryChecker.check(InconsistentRepositoryCheckingTest.INCONSISTENT_OBJECT_SET)
    inconsistentCAs.filter(_._2 == true) should have size(1)
  }

}