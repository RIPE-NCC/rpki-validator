package net.ripe.rpki.validator.models

import java.net.URI

import net.ripe.rpki.commons.crypto.CertificateRepositoryObject
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.rpki.commons.crypto.crl.X509CrlValidator
import net.ripe.rpki.commons.crypto.util.CertificateRepositoryObjectFactory
import net.ripe.rpki.commons.validation.{ValidationOptions, ValidationString, ValidationLocation, ValidationResult}
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import net.ripe.rpki.validator.store.RepositoryObjectStore
import org.apache.commons.lang.Validate
import scala.collection.JavaConverters._


class TopDownWalker(certificateContext: CertificateRepositoryObjectValidationContext, store: RepositoryObjectStore, fetcher: Any, validationOptions: ValidationOptions) {
  Validate.isTrue(certificateContext.getCertificate.isObjectIssuer, "certificate must be an object issuer")


  def execute: ValidationResult = {
    Option(certificateContext.getRepositoryURI) match {
      case Some(repositoryUri) =>
        prefetch(repositoryUri)
        val crlResult: ValidationResult = processCrl(repositoryUri)
        val manifestResult: ValidationResult = processManifest(repositoryUri)
        crlResult.addAll(manifestResult)
      case None => new ValidationResult()// do nothing, suppose this could happen if CA has no children
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
    }).foldLeft(new ValidationResult())(
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
    new ValidationResult().rejectForLocation(new ValidationLocation(uri), key, param)
  }


}
