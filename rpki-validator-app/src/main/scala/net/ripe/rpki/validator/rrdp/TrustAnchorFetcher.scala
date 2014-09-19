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
package net.ripe.rpki.validator.rrdp

import java.io.File
import java.net.URI

import net.ripe.rpki.commons.crypto.CertificateRepositoryObject
import net.ripe.rpki.commons.crypto.util.CertificateRepositoryObjectFactory
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateUtil
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import net.ripe.rpki.commons.validation.ValidationCheck
import net.ripe.rpki.commons.validation.ValidationResult
import net.ripe.rpki.commons.validation.ValidationStatus
import net.ripe.rpki.commons.validation.ValidationString
import net.ripe.rpki.validator.models.InvalidObject
import net.ripe.rpki.validator.models.ValidObject

import com.google.common.io.Files
import org.apache.commons.io.Charsets
import org.apache.commons.io.IOUtils
import org.apache.http.client.methods.HttpGet
import org.apache.http.impl.client.DefaultHttpClient


/**
 * Will fetch and validate TA certificate, but.. only supports a single HTTP uri at the moment..
 */
case class TrustAnchorFetcher(uri: URI, publicKeyInfo: String, objectRetriever: ObjectRetriever = new HttpRetriever) {

  def fetch() = {

    val result = ValidationResult.withLocation(uri)
    try {
      val repoObject = objectRetriever.retrieveObject(uri, result)

      if (result.hasFailureForCurrentLocation()) {
        InvalidObject(uri, Set(new ValidationCheck(ValidationStatus.ERROR, ValidationString.VALIDATOR_TA_RETRIEVE)))
      }

      repoObject match {
        case cert: X509ResourceCertificate => {
          if (X509CertificateUtil.getEncodedSubjectPublicKeyInfo(cert.getCertificate).equals(publicKeyInfo)) {
            ValidObject(uri, Set(new ValidationCheck(ValidationStatus.PASSED, ValidationString.TRUST_ANCHOR_PUBLIC_KEY_MATCH)), repoObject)
          } else {
            InvalidObject(uri, Set(new ValidationCheck(ValidationStatus.ERROR, ValidationString.TRUST_ANCHOR_PUBLIC_KEY_MATCH)))
          }
        }
        case _ => InvalidObject(uri, Set(new ValidationCheck(ValidationStatus.ERROR, ValidationString.VALIDATOR_TA_RETRIEVE)))
      }

    } catch {
      case e: Exception => InvalidObject(uri, Set(new ValidationCheck(ValidationStatus.ERROR, ValidationString.VALIDATOR_TA_RETRIEVE)))
    }
  }

}

sealed trait ObjectRetriever {
  def retrieveObject(uri: URI, result: ValidationResult): CertificateRepositoryObject
}

class HttpRetriever extends ObjectRetriever {
  def retrieveObject(uri: URI, result: ValidationResult): CertificateRepositoryObject = {
    val get = new HttpGet(uri)
    val httpClient = new DefaultHttpClient
    val is = httpClient.execute(get).getEntity().getContent()
    val encoded = IOUtils.toByteArray(is)

    CertificateRepositoryObjectFactory.createCertificateRepositoryObject(encoded, result)
  }
}

class TestRetriever(testObject: CertificateRepositoryObject) extends ObjectRetriever {
  def retrieveObject(uri: URI, result: ValidationResult): CertificateRepositoryObject = testObject
}



object TrustAnchorFetcher {

  def fromFile(file: File) = fromString(Files.toString(file, Charsets.UTF_8))

  def fromString(contents: String, objectRetriever: ObjectRetriever = new HttpRetriever) = {
    val lines = contents.trim().lines.toList

    val uri = URI.create(lines.head)
    val publicKeyInfo = lines.tail.mkString("").replaceAll("\\s+", "")

    TrustAnchorFetcher(uri, publicKeyInfo, objectRetriever)
  }


}