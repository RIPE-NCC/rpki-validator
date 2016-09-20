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

import java.net.URI

import akka.util.ByteString
import net.ripe.rpki.commons.crypto.UnknownCertificateRepositoryObject
import net.ripe.rpki.commons.crypto.cms.ghostbuster.GhostbustersCms
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms
import net.ripe.rpki.commons.crypto.crl.X509Crl
import net.ripe.rpki.commons.crypto.util.CertificateRepositoryObjectFactory
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import net.ripe.rpki.commons.validation.ValidationResult
import org.joda.time.{DateTime, DateTimeZone}

object StoredRepositoryObject {


  def apply(uri: URI, binary: Array[Byte]): StoredRepositoryObject = {

    val defaultTime: DateTime = new DateTime(DateTimeZone.UTC).plusDays(1)

    val binaryObject = ByteString(binary)
    val hash = ByteString(ManifestCms.hashContents(binary))

    /**
     * See: GRE-412
     *
     * There was a case where a ROA had a notAfter time *before* the notBefore time and we can not parse
     * its ValidityPeriod.
     */
    val expires = try {
      CertificateRepositoryObjectFactory.createCertificateRepositoryObject(binary, ValidationResult.withLocation(uri)) match {
        case cert: X509ResourceCertificate => cert.getValidityPeriod.getNotValidAfter
        case mft: ManifestCms => mft.getNotValidAfter
        case roa: RoaCms => roa.getValidityPeriod.getNotValidAfter
        case crl: X509Crl => crl.getNextUpdateTime
        case _: GhostbustersCms | _: UnknownCertificateRepositoryObject => defaultTime
      }
    } catch {
      case e: RuntimeException => defaultTime
    }

    StoredRepositoryObject(hash = hash, uri = uri, binaryObject = binaryObject, expires = expires)
  }
}

case class StoredRepositoryObject(hash: ByteString, uri: URI, binaryObject: ByteString, expires: DateTime)