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
import org.joda.time.Instant

import scala.collection.JavaConverters._
import scala.collection.mutable

class TopDownWalker(certificateContext: CertificateRepositoryObjectValidationContext, store: Storage, repoService: RepoService, validationOptions: ValidationOptions, validationStartTime: Instant)(seen: scala.collection.mutable.Set[String])
  extends Logging {

  private object HashUtil extends Hashing

  val certificateSkiHex: String = HashUtil.stringify(certificateContext.getSubjectKeyIdentifier)
  
  Validate.isTrue(seen.add(certificateSkiHex))
  Validate.isTrue(certificateContext.getCertificate.isObjectIssuer, "certificate must be an object issuer")
  
  private val certContextValidationLocation = new ValidationLocation(certificateContext.getLocation)
  private val certContextValidationResult: ValidationResult = ValidationResult.withLocation(certContextValidationLocation)
  private var crlLocator: CrlLocator = _
  private var objectsToIgnore = Map[String, String]()

  private[models] def preferredFetchLocation: Option[URI] = Option(certificateContext.getRpkiNotifyURI).orElse(Option(certificateContext.getRepositoryURI))

  def execute: Map[URI, ValidatedObject] = {

    logger.info(s"Validating ${certificateContext.getLocation}")
    val fetchErrors = preferredFetchLocation.map(prefetch)

    val validatedObjects = Map.newBuilder[URI, ValidatedObject]

    val childrenValidatedObjects = findCrl match {
      case None =>
        certContextValidationResult.rejectForLocation(certContextValidationLocation, CRL_REQUIRED, s"No valid CRL found with AKI=$certificateSkiHex")
        validatedObjects += certificateContext.getLocation -> InvalidObject(certificateContext.getLocation, certContextValidationResult.getAllValidationChecksForCurrentLocation.asScala.toSet)
        Seq()

      case Some(crl) =>
        crlLocator = new CrlLocator {
          override def getCrl(uri: URI, context: CertificateRepositoryObjectValidationContext, result: ValidationResult): X509Crl =
            crl.decoded
        }

        validatedObjects += createValidatedObjectEntry(crl)
        val roas = findAndValidateObjects(store.getRoas)
        val childrenCertificates = findAndValidateObjects(store.getCertificates)

        findManifest match {
          case Some(manifest) =>
            checkManifestUrlOnCertMatchesLocationInRepo(manifest)
            crossCheckWithManifest(manifest, crl, roas, childrenCertificates)
            validatedObjects += createValidatedObjectEntry(manifest)
          case None =>
            certContextValidationResult.warnForLocation(certContextValidationLocation, VALIDATOR_CA_SHOULD_HAVE_MANIFEST, certificateSkiHex)
        }

        validatedObjects ++= roas.map(createValidatedObjectEntry)
        validatedObjects ++= childrenCertificates.map(createValidatedObjectEntry)

        val validatedChildrenObjects = childrenCertificates.flatMap(stepDown)
        validatedObjects ++= validatedChildrenObjects

        validatedChildrenObjects.map(x => x._1.toString)
    }

    val validatedObjectMap = validatedObjects.result()

    updateStorage(childrenValidatedObjects, validatedObjectMap)

    validatedObjectMap.filterKeys(key => !objectsToIgnore.contains(key.toString))
  }

  private def updateStorage(childrenValidatedObjects: Seq[String], validatedObjectMap: Map[URI, ValidatedObject]) = {
    // delete ignored objects
    objectsToIgnore.foreach { uri =>
      logger.info("Removing object: " + uri._1)
    }
    store.delete(objectsToIgnore)
    
    // don't update validation timestamps for validatedChildrenObjects --- it will
    // be validated by the stepDown recursively
    val materialValidatedOnThisStep = validatedObjectMap.keySet.map(_.toString).filterNot(childrenValidatedObjects.contains(_))
    materialValidatedOnThisStep.foreach { uri =>
      logger.info("Setting validation time for the object: " + uri)
    }
    store.updateValidationTimestamp(materialValidatedOnThisStep)
  }

  private def stepDown: (RepositoryObject[X509ResourceCertificate]) => Map[URI, ValidatedObject] = {
    cert => {
      val ski: String = HashUtil.stringify(cert.decoded.getSubjectKeyIdentifier)
      if (seen.contains(ski)) {
        logger.error(s"Found circular reference of certificates: from ${certificateContext.getLocation} [$certificateSkiHex] to ${cert.url} [$ski]")
        Map()
      } else {
        val newValidationContext = new CertificateRepositoryObjectValidationContext(new URI(cert.url), cert.decoded)
        val nextLevelWalker = new TopDownWalker(newValidationContext, store, repoService, validationOptions, validationStartTime)(seen)
        nextLevelWalker.execute
      }

    }
  }

  private def createValidatedObjectEntry[T <: CertificateRepositoryObject](repositoryObject: RepositoryObject[T]): (URI, ValidatedObject) = {
    val objectUri: URI = new URI(repositoryObject.url)
    objectUri -> createValidatedObject(repositoryObject, objectUri)
  }

  private def createValidatedObject[T <: CertificateRepositoryObject](repositoryObject: RepositoryObject[T], objectUri: URI): ValidatedObject = {
    val validationResults: Set[ValidationCheck] = certContextValidationResult.getAllValidationChecksForLocation(new ValidationLocation(objectUri)).asScala.toSet
    val valid = validationResults.forall(_.isOk)
    if (valid) {
      ValidObject(objectUri, validationResults, repositoryObject.decoded)
    }
    else {
      InvalidObject(objectUri, validationResults)
    }
  }

  private def prefetch(uri: URI) = repoService.visitRepo(uri)

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
      manifest.decoded.validate(manifest.url, certificateContext, crlLocator, validationOptions, manifestValidationResult)
      certContextValidationResult.addAll(manifestValidationResult)
      ! manifestValidationResult.hasFailures
    })
  }

  private[models] def notPublishedAnymore(value: RepositoryObject[_ >: X509ResourceCertificate with RoaCms <: CertificateRepositoryObject]): Boolean = {
    value.downloadTime.fold(ifEmpty = true) {
      _.isBefore(validationStartTime)
    }
  }

  type FileAndHashEntries = Map[URI, Array[Byte]]

  private[models] def crossCheckRepoObjects(validationLocation: ValidationLocation, manifestEntries: FileAndHashEntries, roas: Seq[RepositoryObject[RoaCms]], childrenCertificates: Seq[RepositoryObject[X509ResourceCertificate]]) {

    val roaEntries = roas.map(r => new URI(r.url) -> r)
    val certEntries = childrenCertificates.map(c => new URI(c.url) -> c)
    val foundObjectsEntries = ( roaEntries ++ certEntries ).toMap

    val notFoundInRepo = manifestEntries.keySet -- foundObjectsEntries.keySet
    val notOnManifest = foundObjectsEntries.keySet -- manifestEntries.keySet
    val objectsWithMatchingUri = manifestEntries.keySet intersect foundObjectsEntries.keySet

    notFoundInRepo.foreach { location =>
      certContextValidationResult.warnForLocation(validationLocation, VALIDATOR_MANIFEST_FILE_NOT_FOUND_BY_AKI, location.toString, certificateSkiHex)
    }

    notOnManifest.foreach { location =>
      val repositoryObject = foundObjectsEntries.get(location).get
      if (repositoryObject.isExpiredOrRevoked) {
        if (notPublishedAnymore(repositoryObject)) {
          objectsToIgnore = objectsToIgnore + (repositoryObject.url -> HashUtil.stringify(repositoryObject.hash))
        } else {
          certContextValidationResult.warnForLocation(new ValidationLocation(location), VALIDATOR_REPOSITORY_EXPIRED_REVOKED_OBJECT, location.toString)
        }
      } else {
        certContextValidationResult.warnForLocation(validationLocation, VALIDATOR_MANIFEST_DOES_NOT_CONTAIN_FILE, location.toString)
      }
    }

    objectsWithMatchingUri.filterNot { location =>
      HashUtil.equals(manifestEntries(location), foundObjectsEntries(location).hash)
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
        certContextValidationResult.warnForLocation(validationLocation, VALIDATOR_MANIFEST_HASH_MISMATCH, locationOnMft, certificateSkiHex)
      }
    }
  }

  private def findAndValidateObjects[T <: CertificateRepositoryObject](find: Array[Byte] => Seq[RepositoryObject[T]]) = {
    val objects = find(certificateContext.getSubjectKeyIdentifier)
    objects.foreach(o => o.decoded.validate(o.url, certificateContext, crlLocator, validationOptions, certContextValidationResult))
    objects
  }

  private def crossCheckWithManifest(manifest: ManifestObject, crl: CrlObject, roas: Seq[RepositoryObject[RoaCms]], childrenCertificates: Seq[RepositoryObject[X509ResourceCertificate]]) {
    val repositoryUri = certificateContext.getRepositoryURI
    val validationLocation = new ValidationLocation(manifest.url)
    val manifestEntries: FileAndHashEntries = manifest.decoded.getFiles.entrySet().asScala.map { entry =>
      repositoryUri.resolve(entry.getKey) -> entry.getValue
    }.toMap

    val (crlsOnManifest, entriesExceptCrls) = manifestEntries.partition(_._1.toString.toLowerCase.endsWith(".crl"))

    crossCheckCrls(crl, crlsOnManifest, validationLocation)
    crossCheckRepoObjects(validationLocation, entriesExceptCrls, roas, childrenCertificates)
  }
}
