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

import grizzled.slf4j.Logging
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms
import net.ripe.rpki.commons.crypto.crl.{CrlLocator, X509Crl}
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import net.ripe.rpki.commons.validation.ValidationString._
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import net.ripe.rpki.commons.validation.{ValidationCheck, ValidationLocation, ValidationOptions, ValidationResult}
import net.ripe.rpki.validator.models.validation._
import net.ripe.rpki.validator.store.Storage
import org.apache.commons.lang.Validate

import scala.collection.JavaConverters._

class TopDownWalker(certificateContext: CertificateRepositoryObjectValidationContext, store: Storage, fetcher: RepoFetcher, validationOptions: ValidationOptions)(seen: scala.collection.mutable.Set[String])
  extends Logging {

  private object HashUtil extends Hashing

  val certificateSkiHex: String = HashUtil.stringify(certificateContext.getSubjectKeyIdentifier)
  
  Validate.isTrue(seen.add(certificateSkiHex))
  Validate.isTrue(certificateContext.getCertificate.isObjectIssuer, "certificate must be an object issuer")
  
  private val certContextValidationLocation = new ValidationLocation(certificateContext.getLocation)
  private val certContextValidationResult: ValidationResult = ValidationResult.withLocation(certContextValidationLocation)
  private val validatedObjects = Map.newBuilder[URI, ValidatedObject]
  private var crlLocator: CrlLocator = _

  def execute: Map[URI, ValidatedObject] = {
    logger.info(s"Validating ${certificateContext.getLocation}")
    Option(certificateContext.getRepositoryURI) match {
      case Some(repositoryUri) =>
        prefetch(repositoryUri)
        certContextValidationResult.setLocation(new ValidationLocation(repositoryUri))

      case None =>  //TODO do nothing, suppose this could happen if CA has no children?
    }

    findCrl match {
      case None =>
        certContextValidationResult.rejectForLocation(certContextValidationLocation, CRL_REQUIRED, "No valid CRL found with SKI=" + certificateContext.getSubjectKeyIdentifier)
        validatedObjects += certificateContext.getLocation -> InvalidObject(certificateContext.getLocation, certContextValidationResult.getAllValidationChecksForCurrentLocation.asScala.toSet)

      case Some(crl) =>
        crlLocator = new CrlLocator {
          override def getCrl(uri: URI, context: CertificateRepositoryObjectValidationContext, result: ValidationResult): X509Crl =
            crl.decoded
        }

        validatedObjects += createValidObjectForThisCert
        validatedObjects += createValidObject(crl)
        val roas = findAndValidateObjects(store.getRoas)
        val childrenCertificates = findAndValidateObjects(store.getCertificates)

        findManifest match {
          case Some(manifest) =>
            crossCheckWithManifest(manifest, crl, roas, childrenCertificates)
            validatedObjects += createValidObject(manifest)
          case None =>
            certContextValidationResult.warnForLocation(certContextValidationLocation, VALIDATOR_CA_SHOULD_HAVE_MANIFEST, certificateSkiHex)
        }

        validatedObjects ++= roas.map(createValidObject)

        validatedObjects ++= childrenCertificates.flatMap(stepDown)
    }

    validatedObjects.result()
  }

  private def stepDown: (RepositoryObject[X509ResourceCertificate]) => Map[URI, ValidatedObject] = {
    cert => {
      val ski: String = HashUtil.stringify(cert.decoded.getSubjectKeyIdentifier)
      if (seen.contains(ski)) {
        logger.error(s"Found circular reference of certificates: from ${certificateContext.getLocation} [${certificateSkiHex}] to ${cert.url} [$ski]")
        Map()
      } else {
        val newValidationContext = new CertificateRepositoryObjectValidationContext(new URI(cert.url), cert.decoded)
        val nextLevelWalker = new TopDownWalker(newValidationContext, store, fetcher, validationOptions)(seen)
        nextLevelWalker.execute
      }
    }
  }

  private def createValidObjectForThisCert = {
    val validObject = new ValidObject(certificateContext.getLocation, certContextValidationResult.getAllValidationChecksForLocation(certContextValidationLocation).asScala.toSet, certificateContext.getCertificate)
    certificateContext.getLocation -> validObject
  }

  private def createValidObject[T <: CertificateRepositoryObject](repositoryObject: RepositoryObject[T]): (URI, ValidObject) = {
    val crlUri: URI = new URI(repositoryObject.url)
    val validationResultsForLocation: Set[ValidationCheck] = certContextValidationResult.getAllValidationChecksForLocation(new ValidationLocation(crlUri)).asScala.toSet
    crlUri -> new ValidObject(crlUri, validationResultsForLocation, repositoryObject.decoded)
  }

  private def prefetch(uri: URI) = fetcher.fetch(uri)

  private def findCrl: Option[CrlObject] = {
    val keyIdentifier = certificateContext.getSubjectKeyIdentifier
    findMostRecentValidCrl(store.getCrls(keyIdentifier))
  }

  private def findMostRecentValidCrl(crlList: Seq[CrlObject]): Option[CrlObject] = {
    crlList.sortBy(_.decoded.getNumber).reverse.find { crl =>
      val crlValidationResult = ValidationResult.withLocation(crl.url)
      crl.decoded.validate(crl.url, certificateContext, crlLocator, validationOptions, crlValidationResult)
      certContextValidationResult.addAll(crlValidationResult)
      ! crlValidationResult.hasFailures
    }
  }

  private def findManifest: Option[ManifestObject] = {
    val manifests = store.getManifests(certificateContext.getSubjectKeyIdentifier)
    findMostRecentValidManifest(manifests)
  }

  private def findMostRecentValidManifest(manifests: Seq[ManifestObject]): Option[ManifestObject] = {
    manifests.sortBy(_.decoded.getNumber).reverse.find( manifest => {
      val manifestValidationResult: ValidationResult = ValidationResult.withLocation(manifest.url)
      manifest.decoded.validate(certificateContext.getLocation.toString, certificateContext, crlLocator, validationOptions, manifestValidationResult)
      certContextValidationResult.addAll(manifestValidationResult)
      ! manifestValidationResult.hasFailures
    })
  }

  type FileAndHashEntries = Map[String, Array[Byte]]

  private def processManifestEntries(manifest: ManifestObject, crl: CrlObject, roas: Seq[RepositoryObject[_]], childrenCertificates: Seq[RepositoryObject[_]]) {
    val repositoryUri = certificateContext.getRepositoryURI
    val validationLocation = new ValidationLocation(manifest.url)
    val manifestEntries: FileAndHashEntries = manifest.decoded.getFiles.entrySet().asScala.map { entry =>
      repositoryUri.resolve(entry.getKey).toString -> entry.getValue
    }.toMap
    
    val (crlsOnManifest, entriesExceptCrls) = manifestEntries.partition(_._1.toLowerCase.endsWith(".crl"))

    crossCheckCrls(crl, crlsOnManifest, validationLocation)
    crossCheckRepoObjects(validationLocation, entriesExceptCrls, childrenCertificates ++ roas)
  }

  private[models] def crossCheckRepoObjects(validationLocation: ValidationLocation, manifestEntries: FileAndHashEntries, foundObjects: Seq[RepositoryObject[_]]) {
    
    val foundObjectsEntries = foundObjects.map(c => c.url -> c.hash).toMap
    
    val notFoundInRepo = manifestEntries.keySet -- foundObjectsEntries.keySet
    val notOnManifest = foundObjectsEntries.keySet -- manifestEntries.keySet
    val objectsWithMatchingUri = manifestEntries.keySet intersect foundObjectsEntries.keySet

    notFoundInRepo.foreach { location =>
      certContextValidationResult.warnForLocation(validationLocation, VALIDATOR_MANIFEST_FILE_NOT_FOUND_BY_AKI, location, certificateSkiHex)
    }

    notOnManifest.foreach { location =>
      certContextValidationResult.warnForLocation(validationLocation, VALIDATOR_MANIFEST_DOES_NOT_CONTAIN_FILE, location)
    }

    objectsWithMatchingUri.filterNot { location =>
      HashUtil.equals(manifestEntries(location), foundObjectsEntries(location))
    } foreach { location =>
      certContextValidationResult.warnForLocation(validationLocation, VALIDATOR_MANIFEST_DOES_NOT_CONTAIN_FILE,
        s"Hash code of object at $location (${foundObjectsEntries(location)}) does not match the one specified in the manifest (${manifestEntries(location)})")
    }
  }

  def checkManifestUrlOnCertMatchesLocationInRepo(manifest: ManifestObject) = {
    val manifestLocationInCertificate: String = certificateContext.getManifestURI.toString
    val manifestLocationInRepository: String = manifest.url
    if(! manifestLocationInRepository.equalsIgnoreCase(manifestLocationInCertificate)) {
      certContextValidationResult.warnForLocation(new ValidationLocation(manifestLocationInRepository),
        VALIDATOR_MANIFEST_LOCATION_MISMATCH, manifestLocationInCertificate, manifestLocationInRepository)
    }
  }

  def crossCheckCrls(crl: CrlObject, manifestCrlEntries: FileAndHashEntries, validationLocation: ValidationLocation) = {
    if (manifestCrlEntries.size == 0) {
      certContextValidationResult.warnForLocation(validationLocation, VALIDATOR_MANIFEST_DOES_NOT_CONTAIN_FILE, "*.crl")
    } else if (manifestCrlEntries.size > 1) {
      val crlFileNames = manifestCrlEntries.keys.mkString(",")
      certContextValidationResult.warnForLocation(validationLocation, VALIDATOR_MANIFEST_DOES_NOT_CONTAIN_FILE, s"Single CRL expected, found: $crlFileNames")
    } else {
      val locationOnMft = certificateContext.getRepositoryURI.resolve(manifestCrlEntries.keys.head).toString
      val hashOnMft = manifestCrlEntries.values.head
      if (locationOnMft != crl.url) {
        certContextValidationResult.warnForLocation(validationLocation, VALIDATOR_MANIFEST_CRL_URI_MISMATCH, locationOnMft, crl.url.toString)
      } else if (!HashUtil.equals(crl.hash, hashOnMft)) {
        certContextValidationResult.warnForLocation(validationLocation, VALIDATOR_MANIFEST_DOES_NOT_CONTAIN_FILE, s"Hash code of $locationOnMft doesn't match hash code in manifest")
      }
    }
  }

  private def findAndValidateObjects[T <: CertificateRepositoryObject](find: Array[Byte] => Seq[RepositoryObject[T]]) = {
    val location: String = certificateContext.getLocation.toString
    val objects = find(certificateContext.getSubjectKeyIdentifier)
    objects.foreach(_.decoded.validate(location, certificateContext, crlLocator, validationOptions, certContextValidationResult))
    objects
  }

  private def crossCheckWithManifest(manifest: ManifestObject, crl: CrlObject, roas: Seq[RepositoryObject[RoaCms]], childrenCertificates: Seq[RepositoryObject[X509ResourceCertificate]]) {
    checkManifestUrlOnCertMatchesLocationInRepo(manifest)
    processManifestEntries(manifest, crl, roas, childrenCertificates)
  }
}
