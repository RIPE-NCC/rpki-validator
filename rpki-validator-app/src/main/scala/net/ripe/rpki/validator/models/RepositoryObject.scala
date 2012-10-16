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
package net.ripe.rpki.validator
package models

import net.ripe.commons.certification.CertificateRepositoryObject
import java.net.URI
import org.apache.commons.codec.binary.Base64
import net.ripe.commons.certification.cms.manifest.ManifestCms
import akka.util.ByteString
import org.joda.time.DateTime
import net.ripe.commons.certification.util.CertificateRepositoryObjectFactory
import net.ripe.commons.certification.x509cert.X509ResourceCertificate
import net.ripe.commons.certification.cms.roa.RoaCms
import net.ripe.commons.certification.crl.X509Crl
import net.ripe.commons.certification.validation.ValidationResult

object StoredRepositoryObject {

  def apply(uri: URI, repositoryObject: CertificateRepositoryObject): StoredRepositoryObject = {

    val binaryObject = ByteString(repositoryObject.getEncoded)
    val hash = ByteString(ManifestCms.hashContents(repositoryObject.getEncoded))

    val expires = CertificateRepositoryObjectFactory.createCertificateRepositoryObject(repositoryObject.getEncoded, new ValidationResult) match {
      case cert: X509ResourceCertificate => cert.getValidityPeriod().getNotValidAfter
      case mft: ManifestCms => mft.getNotValidAfter
      case roa: RoaCms => roa.getValidityPeriod.getNotValidAfter
      case crl: X509Crl => crl.getNextUpdateTime
    }

    StoredRepositoryObject(hash = hash, uri = uri, binaryObject = binaryObject, expires = expires)
  }
}

case class StoredRepositoryObject(hash: ByteString, uri: URI, binaryObject: ByteString, expires: DateTime)