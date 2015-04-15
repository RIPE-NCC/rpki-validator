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

import net.ripe.ipresource.{IpResourceSet, IpResourceType}
import net.ripe.rpki.commons.crypto.ValidityPeriod
import net.ripe.rpki.commons.crypto.cms.manifest.{ManifestCms, ManifestCmsBuilder}
import net.ripe.rpki.commons.crypto.crl.{X509Crl, X509CrlBuilder}
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper._
import net.ripe.rpki.commons.crypto.x509cert.{X509CertificateInformationAccessDescriptor, X509ResourceCertificate, X509ResourceCertificateBuilder}
import net.ripe.rpki.validator.store.Storage
import org.bouncycastle.asn1.x509.KeyUsage
import org.joda.time.DateTime

class RpkiTreeBuilder(store: Storage) {

  private val REPO_LOCATION: URI = URI.create("rsync://foo.host/bar/")
  private val RRDP_NOTIFICATION_LOCATION: URI = URI.create("http://foo.host/bar/notification.xml")
  private val ROOT_RESOURCE_SET: IpResourceSet = IpResourceSet.parse("10.0.0.0/8, 192.168.0.0/16, ffce::/16, AS21212")
  private val ROOT_SERIAL_NUMBER: BigInteger = BigInteger.valueOf(900)
  private val NOW: DateTime = DateTime.now()
  private val VALIDITY_PERIOD: ValidityPeriod = new ValidityPeriod(NOW.minusMinutes(1), NOW.plusYears(1))

  private var rootCertName: X500Principal = _
  private var rootKeyPair: KeyPair = _

  private val certs = scala.collection.mutable.HashMap.empty[X500Principal, KeyPair]
  private val crlsByCert = scala.collection.mutable.HashMap.empty[X500Principal, (URI, Seq[BigInteger])]
  private val mftsByCert = scala.collection.mutable.HashMap.empty[X500Principal, (URI, Seq[(URI, Array[Byte])])]

  def addRootCertificate(name: X500Principal, keyPair: KeyPair) = {
    rootCertName = name
    rootKeyPair = keyPair
    certs.put(name, keyPair)
  }

  def addCrl(parentCertificateName: X500Principal, location: URI, revokedSerials: BigInteger*) = {
    crlsByCert.put(parentCertificateName, (location, revokedSerials.toSeq))
  }

  def addMft(parentCertificateName: X500Principal, location: URI, entries: (URI, Array[Byte])*) = {
    mftsByCert.put(parentCertificateName, (location, entries.toSeq))
  }

  def build = {
    // TODO Build and store the whole tree, starting with the rootCert
    val rootCert = buildRootCertificate(rootCertName, rootKeyPair)

    buildTreeFrom(rootCertName)
  }

  def buildTreeFrom(certificateName: X500Principal) = {
    val mft = buildMft(certificateName)
    val crl = buildCrl(certificateName)
    // TODO store them
    // TODO also build other objects and recurse on certs
  }

  private def buildRootCertificate(name: X500Principal, keyPair: KeyPair) = {
    val (crlLocation, _) = crlsByCert.get(name).get
    val (manifestLocation, _) = mftsByCert.get(name).get

    val builder: X509ResourceCertificateBuilder = new X509ResourceCertificateBuilder
    builder.withSubjectDN(name)
    builder.withIssuerDN(name)
    builder.withSerial(ROOT_SERIAL_NUMBER)
    builder.withValidityPeriod(VALIDITY_PERIOD)
    builder.withPublicKey(keyPair.getPublic)
    builder.withCa(true)
    builder.withKeyUsage(KeyUsage.keyCertSign)
    builder.withAuthorityKeyIdentifier(true)
    builder.withSubjectKeyIdentifier(true)
    builder.withResources(ROOT_RESOURCE_SET)
    builder.withAuthorityKeyIdentifier(false)
    builder.withSigningKeyPair(keyPair)
    builder.withCrlDistributionPoints(crlLocation)

    builder.withSubjectInformationAccess(
      new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY, REPO_LOCATION),
      new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_NOTIFY, RRDP_NOTIFICATION_LOCATION),
      new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST, manifestLocation)
    )
    builder.build
  }

  private def buildCrl(certificateName: X500Principal): X509Crl = {
    val keyPair = certs.get(certificateName).get
    val (_, revokedSerials) = crlsByCert.get(certificateName).get

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

  private def buildMft(certificateName: X500Principal): ManifestCms = {
    val keyPair = certs.get(certificateName).get
    val (_, entries) = mftsByCert.get(certificateName).get
    val (crlLocation, _) = crlsByCert.get(certificateName).get

    val thisUpdateTime = NOW.minusMinutes(1)
    val nextUpdateTime = NOW.plusYears(1)

    val builder: ManifestCmsBuilder = new ManifestCmsBuilder
    builder.withCertificate(createManifestEECertificate(keyPair, certificateName, crlLocation))
      .withManifestNumber(BigInteger.valueOf(68))
      .withThisUpdateTime(thisUpdateTime)
      .withNextUpdateTime(nextUpdateTime)

    entries.foreach { e =>
      val (u, content) = e
      builder.addFile(extractFileName(u), content)
    }

    builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER)

    builder.build(keyPair.getPrivate)
  }

  private def createManifestEECertificate(keyPair: KeyPair, issuerDN: X500Principal, crlLocation: URI): X509ResourceCertificate = {
    val builder: X509ResourceCertificateBuilder = new X509ResourceCertificateBuilder
    builder.withCa(false).withSubjectDN(new X500Principal("CN=EECert")).withIssuerDN(issuerDN).withSerial(BigInteger.ONE)
    builder.withPublicKey(keyPair.getPublic)
    builder.withSigningKeyPair(keyPair)
    builder.withInheritedResourceTypes(java.util.EnumSet.allOf(classOf[IpResourceType]))
    builder.withValidityPeriod(VALIDITY_PERIOD)
    builder.withCrlDistributionPoints(crlLocation)
    builder.withKeyUsage(KeyUsage.digitalSignature)
    builder.build
  }

  private def extractFileName(uri: URI): String = {
    uri.toString.split('/').last
  }
}
