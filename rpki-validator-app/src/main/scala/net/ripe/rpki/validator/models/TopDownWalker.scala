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

import java.net.URI

import net.ripe.rpki.commons.crypto.CertificateRepositoryObject
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.rpki.commons.crypto.crl.{CrlLocator, X509CrlValidator}
import net.ripe.rpki.commons.crypto.util.CertificateRepositoryObjectFactory
import net.ripe.rpki.commons.validation.{ValidationOptions, ValidationString, ValidationLocation, ValidationResult}
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import net.ripe.rpki.validator.store.RepositoryObjectStore
import org.apache.commons.lang.Validate
import scala.collection.JavaConverters._


class TopDownWalker(certificateContext: CertificateRepositoryObjectValidationContext, store: RepositoryObjectStore, fetcher: CrlLocator, validationOptions: ValidationOptions) {
  Validate.isTrue(certificateContext.getCertificate.isObjectIssuer, "certificate must be an object issuer")


  def execute: ValidationResult = {
    Option(certificateContext.getRepositoryURI) match {
      case Some(repositoryUri) =>
        prefetch(repositoryUri)
        val crlResult: ValidationResult = processCrl(repositoryUri)
        val manifestResult: ValidationResult = processManifest(repositoryUri)
        crlResult.addAll(manifestResult)
      case None => ValidationResult.withLocation("") // do nothing, suppose this could happen if CA has no children
    }
  }

  def prefetch(uri: URI) = ???

  def processCrl(uri: URI): ValidationResult = {
    val keyIdentifier = certificateContext.getSubjectKeyIdentifier
    store.getCrlForKI(keyIdentifier) match {
      case Seq() => validationError(uri, ValidationString.VALIDATOR_OBJECT_PROCESSING_EXCEPTION, uri.toString)
      case crlList =>
//        crlList.sortWith( (crlA, crlB) => crlB.getNumber.compareTo(crlA.getNumber) > 0)
//        val crlLocation: String = crl.getCrlUri.toString
//        val validationResult = ValidationResult.withLocation(crlLocation)
//        val validator: X509CrlValidator = new X509CrlValidator(validationOptions, validationResult, certificateContext.getCertificate)
//        validator.validate(crlLocation, crl)
//        if (!validationResult.hasFailureForCurrentLocation) {
//
//        }
        ValidationResult.withLocation("") // TODO
    }
  }

  def processManifest(uri: URI): ValidationResult = {
    val keyIdentifier = certificateContext.getSubjectKeyIdentifier
    store.getManifestForKI(keyIdentifier) match {
      case Some(manifest) => processManifestEntries(manifest, uri)
      case None => validationError(uri, ValidationString.VALIDATOR_OBJECT_PROCESSING_EXCEPTION, uri.toString)
    }
  }

  def processManifestEntries(manifest: ManifestCms, uri: URI): ValidationResult = {
    manifest.getFiles.entrySet().asScala.map(entry => {
      store.getByHash(entry.getValue) match {
        case None => validationError(uri, ValidationString.VALIDATOR_OBJECT_PROCESSING_EXCEPTION, uri.resolve(entry.getKey).toString)
        case Some(repositoryObject) => validate(repositoryObject, uri)
      }
    }).foldLeft(ValidationResult.withLocation(uri))(
        (collector, result) => collector.addAll(result)
      )
  }

  def validate(repositoryObject: StoredRepositoryObject, uri: URI): ValidationResult = {
    val result = ValidationResult.withLocation(uri)
    val certificateRepositoryObject = CertificateRepositoryObjectFactory.createCertificateRepositoryObject(repositoryObject.binaryObject.toArray[Byte], result)
    certificateRepositoryObject.validate(uri.toString, certificateContext, fetcher, validationOptions, result)
    result
  }

  def validationError(uri: URI, key: String, param: String) = {
    ValidationResult.withLocation(new ValidationLocation(uri)).error(key, param)
  }


}
