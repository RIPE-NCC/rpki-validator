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

import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.rpki.commons.crypto.crl.{CrlLocator, X509Crl, X509CrlValidator}
import net.ripe.rpki.commons.crypto.util.CertificateRepositoryObjectFactory
import net.ripe.rpki.commons.validation.ValidationString.CRL_REQUIRED
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import net.ripe.rpki.commons.validation.{ValidationLocation, ValidationOptions, ValidationResult, ValidationString}
import net.ripe.rpki.validator.store.RepositoryObjectStore
import org.apache.commons.lang.Validate

import scala.collection.JavaConverters._


class TopDownWalker(certificateContext: CertificateRepositoryObjectValidationContext, store: RepositoryObjectStore, fetcher: CrlLocator, validationOptions: ValidationOptions) {
  
  Validate.isTrue(certificateContext.getCertificate.isObjectIssuer, "certificate must be an object issuer")

  lazy val crl: Option[X509Crl] = findCrl

  def crlLocator = new CrlLocator {
    override def getCrl(uri: URI, context: CertificateRepositoryObjectValidationContext, result: ValidationResult): X509Crl = crl.get
  }

  val validationResult: ValidationResult = ValidationResult.withLocation("")


  def execute: ValidationResult = {
    Option(certificateContext.getRepositoryURI) match {
      case Some(repositoryUri) =>
        prefetch(repositoryUri)
        validationResult.setLocation(new ValidationLocation(repositoryUri))

      case None =>  //TODO do nothing, suppose this could happen if CA has no children?
    }

    if (crl.isDefined) {
      findManifest()
    } else {
      validationError(CRL_REQUIRED, "No valid CRL found with SKI=" + certificateContext.getSubjectKeyIdentifier)
    }

    validationResult
  }

  def prefetch(uri: URI) = ???

  def findCrl: Option[X509Crl] = {
    val keyIdentifier = certificateContext.getSubjectKeyIdentifier
    findMostRecentValidCrl(store.getCrlForKI(keyIdentifier))
  }

  def findMostRecentValidCrl(crlList: Seq[X509Crl]): Option[X509Crl] = {
    crlList.sortBy(_.getNumber).reverse.find(crl => {
      val crlLocation = crl.getCrlUri.toString
      val crlValidationResult = ValidationResult.withLocation(crlLocation)
      val validator: X509CrlValidator = new X509CrlValidator(validationOptions, crlValidationResult, certificateContext.getCertificate)
      validator.validate(crlLocation, crl)
      validationResult.addAll(crlValidationResult)
      ! crlValidationResult.hasFailureForCurrentLocation
    })
  }

  def findManifest() {
    val keyIdentifier = certificateContext.getSubjectKeyIdentifier
    findMostRecentValidManifest(store.getManifestsForKI(keyIdentifier)) match {
      case Some(manifest) => processManifestEntries(manifest)
      case None =>
        validationError(ValidationString.VALIDATOR_OBJECT_PROCESSING_EXCEPTION, "No manifests with SKI=" + certificateContext.getSubjectKeyIdentifier) //TODO better error code
    }
  }

  def findMostRecentValidManifest(manifests: Seq[ManifestCms]): Option[ManifestCms] = {
    manifests.sortBy(_.getNumber).reverse.find( manifest => {
      val manifestValidationResult: ValidationResult = ValidationResult.withLocation("")
      manifest.validate(certificateContext.getLocation.toString, certificateContext, crlLocator, validationOptions, manifestValidationResult)
      validationResult.addAll(manifestValidationResult)
      ! manifestValidationResult.hasFailures
    })
  }

  def processManifestEntries(manifest: ManifestCms) {
    // TODO who validates that the manifest has one and only one CRL entry?
    manifest.getFiles.entrySet().asScala.map(entry => {
      // TODO validate that set of objects signed by certificateContext.getSubjectKeyIdentifier matches this set of entries
    })
  }

  def validate(repositoryObject: StoredRepositoryObject, uri: URI): ValidationResult = {
    val result = ValidationResult.withLocation(uri)
    val certificateRepositoryObject = CertificateRepositoryObjectFactory.createCertificateRepositoryObject(repositoryObject.binaryObject.toArray[Byte], result)
    certificateRepositoryObject.validate(uri.toString, certificateContext, fetcher, validationOptions, result)
    result
  }

  def validationError(uri: URI, key: String, param: String) = {
    validationResult.rejectForLocation(new ValidationLocation(uri), key, param)
  }

  def validationError(key: String, param: String) = {
    validationResult.error(key, param)
  }

}
