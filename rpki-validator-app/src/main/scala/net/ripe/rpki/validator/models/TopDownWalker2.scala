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
import scala.collection.immutable.Iterable

class TopDownWalker2(certificateContext: CertificateRepositoryObjectValidationContext,
                    store: Storage,
                    repoService: RepoService,
                    validationOptions: ValidationOptions,
                    validationStartTime: Instant)(seen: scala.collection.mutable.Set[String])
  extends Logging {

  private object HashUtil extends Hashing

  private val certificateSkiHex: String = HashUtil.stringify(certificateContext.getSubjectKeyIdentifier)
  
  Validate.isTrue(seen.add(certificateSkiHex))
  Validate.isTrue(certificateContext.getCertificate.isObjectIssuer, "certificate must be an object issuer")
  
  private val certContextValidationLocation = new ValidationLocation(certificateContext.getLocation)
  private val certContextValidationResult: ValidationResult = ValidationResult.withLocation(certContextValidationLocation)
  private var objectsToIgnore = Map[String, String]()

  private[models] def preferredFetchLocation: Option[URI] = Option(certificateContext.getRpkiNotifyURI).orElse(Option(certificateContext.getRepositoryURI))

  sealed trait Validation {
    def location: ValidationLocation
    def key: String
    def params: Seq[String]
  }

  case class Reject(location: ValidationLocation, key: String, params: Seq[String]) extends Validation
  case class Warning(location: ValidationLocation, key: String, params: Seq[String]) extends Validation


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
        validatedObjects += createValidatedObjectEntry(crl)
        val roas = findAndValidateObjects(crl, store.getRoas)
        val childrenCertificates = findAndValidateObjects(crl, store.getCertificates)

        findManifest(crl) match {
          case Some(manifest) =>
            checkManifestUrlOnCertMatchesLocationInRepo(manifest)
            crossCheckWithManifest(manifest, crl)
            validatedObjects += createValidatedObjectEntry(manifest)
          case None =>
            certContextValidationResult.warnForLocation(certContextValidationLocation, VALIDATOR_CA_SHOULD_HAVE_MANIFEST, certificateSkiHex)
        }

        validatedObjects ++= roas.map(createValidatedObjectEntry)
        validatedObjects ++= childrenCertificates.map(createValidatedObjectEntry)

        val validatedChildrenObjects = childrenCertificates.flatMap(stepDown)
        validatedObjects ++= validatedChildrenObjects

        validatedChildrenObjects.map(_._1.toString)
    }

    val validatedObjectMap = validatedObjects.result()

    updateAndCleanStorage(childrenValidatedObjects, validatedObjectMap)

    validatedObjectMap.filterKeys(key => !objectsToIgnore.contains(key.toString))
  }

  private def updateAndCleanStorage(childrenValidatedObjects: Seq[String], validatedObjectMap: Map[URI, ValidatedObject]) = {
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

//
//    //
//    val oldOnes: Seq[RepositoryObject[_]] = store.getVeryOldObjects("1 week old")
//    oldOnes.foreach {
//      logger.info("Cleaning up very old object: " + _)
//    }
//    store.delete(oldOnes.map( o => ( o.url -> HashUtil.stringify(o.hash) )))

  }

  private def stepDown(cert: RepositoryObject[X509ResourceCertificate]): Map[URI, ValidatedObject] = {
    val ski: String = HashUtil.stringify(cert.decoded.getSubjectKeyIdentifier)
    if (seen.contains(ski)) {
      logger.error(s"Found circular reference of certificates: from ${certificateContext.getLocation} [$certificateSkiHex] to ${cert.url} [$ski]")
      Map()
    } else {
      val newValidationContext = new CertificateRepositoryObjectValidationContext(new URI(cert.url), cert.decoded)
      val nextLevelWalker = new TopDownWalker2(newValidationContext, store, repoService, validationOptions, validationStartTime)(seen)
      nextLevelWalker.execute
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
      crl.decoded.validate(crl.url, certificateContext, crlLocator(crl), validationOptions, crlValidationResult)
      certContextValidationResult.addAll(crlValidationResult)
      ! crlValidationResult.hasFailures
    }
  }

  private def crlLocator(crl :CrlObject) = new CrlLocator {
    override def getCrl(uri: URI, context: CertificateRepositoryObjectValidationContext, result: ValidationResult): X509Crl =
      crl.decoded
  }

  private def findManifest(crl: CrlObject): Option[ManifestObject] = {
    val manifests = store.getManifests(certificateContext.getSubjectKeyIdentifier)
    findMostRecentValidManifest(manifests, crl)
  }

  private def findMostRecentValidManifest(manifests: Seq[ManifestObject], crl: CrlObject): Option[ManifestObject] = {
    manifests.sortBy(_.decoded.getNumber).reverse.find( manifest => {
      val manifestValidationResult: ValidationResult = ValidationResult.withLocation(manifest.url)
      manifest.decoded.validate(manifest.url, certificateContext, crlLocator(crl), validationOptions, manifestValidationResult)
      certContextValidationResult.addAll(manifestValidationResult)
      ! manifestValidationResult.hasFailures
    })
  }

  type FileAndHashEntries = Map[URI, Array[Byte]]

  case class ClassifiedObjects(roas: Seq[RoaObject], certificates: Seq[CertificateObject], crls: Seq[CrlObject])

  private def classify(objects: Seq[RepositoryObject[_]]) = {
    var (roas, certificates, crls) = (List[RoaObject](), List[CertificateObject](), List[CrlObject]())
    val c = objects.foreach {
      case roa: RoaObject => roas = roa :: roas
      case cer: CertificateObject => certificates = cer :: certificates
      case crl: CrlObject => crls = crl :: crls
    }
    ClassifiedObjects(roas.toSeq, certificates.toSeq, crls.toSeq)
  }


//  private[models] def crossCheckRepoObjects(validationLocation: ValidationLocation, objects : Seq[RepositoryObject[_]]) = {
//
//    val foundObjectsEntries = objects.map(o => new URI(o.url) -> o).toMap
//
//    val notFoundInRepo = manifestEntries.keySet -- foundObjectsEntries.keySet
//    notFoundInRepo.foreach { location =>
//      certContextValidationResult.warnForLocation(validationLocation, VALIDATOR_MANIFEST_FILE_NOT_FOUND_BY_AKI, location.toString, certificateSkiHex)
//    }
//
//    val objectsWithMatchingUri = manifestEntries.keySet intersect foundObjectsEntries.keySet
//    objectsWithMatchingUri.filterNot { location =>
//      HashUtil.equals(manifestEntries(location), foundObjectsEntries(location).hash)
//    } foreach { location =>
//      certContextValidationResult.warnForLocation(validationLocation, VALIDATOR_MANIFEST_DOES_NOT_CONTAIN_FILE,
//        s"Hash code of object at $location (${foundObjectsEntries(location)}) does not match the one specified in the manifest (${manifestEntries(location)})")
//    }
//
//    val notOnManifest = (foundObjectsEntries.keySet -- manifestEntries.keySet).map { foundObjectsEntries.get(_).get }
//    val (expiredOrRevoked, notExpiredOrRevoked) = notOnManifest.partition(_.isExpiredOrRevoked)
//
//    notExpiredOrRevoked.foreach { repositoryObject =>
//      certContextValidationResult.warnForLocation(validationLocation, VALIDATOR_MANIFEST_DOES_NOT_CONTAIN_FILE, repositoryObject.url)
//    }
//
//    expiredOrRevoked.filter(_.validationTime.isEmpty).foreach { repositoryObject =>
//      certContextValidationResult.warnForLocation(new ValidationLocation(repositoryObject.url), VALIDATOR_REPOSITORY_EXPIRED_REVOKED_OBJECT, repositoryObject.url)
//    }
//
//    expiredOrRevoked.filterNot(_.validationTime.isEmpty).foreach { repositoryObject =>
//      objectsToIgnore = objectsToIgnore + (repositoryObject.url -> HashUtil.stringify(repositoryObject.hash))
//    }
//    (Seq(), Seq())
//  }

  def checkManifestUrlOnCertMatchesLocationInRepo(manifest: ManifestObject) = {
    val manifestLocationInCertificate: String = certificateContext.getManifestURI.toString
    val manifestLocationInRepository: String = manifest.url
    if(! manifestLocationInRepository.equalsIgnoreCase(manifestLocationInCertificate)) {
      certContextValidationResult.warnForLocation(new ValidationLocation(manifestLocationInRepository),
        VALIDATOR_MANIFEST_LOCATION_MISMATCH, manifestLocationInCertificate, manifestLocationInRepository)
    }
  }

  def crossCheckCrls(crl: CrlObject, manifestCrlEntries: Seq[CrlObject], validationLocation: ValidationLocation) = {
    if (manifestCrlEntries.size == 0) {
      Warning(validationLocation, VALIDATOR_MANIFEST_DOES_NOT_CONTAIN_FILE, Seq("*.crl"))
    } else if (manifestCrlEntries.size > 1) {
      val crlUris = manifestCrlEntries.map(_.url).mkString(",")
      Warning(validationLocation, VALIDATOR_MANIFEST_DOES_NOT_CONTAIN_FILE, Seq(s"Single CRL expected, found: $crlUris"))
    } else {
      val crlOnMft: CrlObject = manifestCrlEntries.head
      if (crlOnMft.url != crl.url) {
        Warning(validationLocation, VALIDATOR_MANIFEST_CRL_URI_MISMATCH, Seq(crlOnMft.url, crl.url))
      } else if (!HashUtil.equals(crl.hash, crlOnMft.hash)) {
        Warning(validationLocation, VALIDATOR_MANIFEST_HASH_MISMATCH, Seq(crlOnMft.url, certificateSkiHex))
      }
    }
  }

  private def findAndValidateObjects[T <: CertificateRepositoryObject](crl : CrlObject, find: Array[Byte] => Seq[RepositoryObject[T]]) = {
    val objects = find(certificateContext.getSubjectKeyIdentifier)
    objects.foreach(o => o.decoded.validate(o.url, certificateContext, crlLocator(crl), validationOptions, certContextValidationResult))
    objects
  }

  private def crossCheckWithManifest(manifest: ManifestObject, crlByAki: CrlObject) = {
    val repositoryUri = certificateContext.getRepositoryURI
    val validationLocation = new ValidationLocation(manifest.url)
    val manifestEntries: FileAndHashEntries = manifest.decoded.getHashes.entrySet().asScala.map { entry =>
      repositoryUri.resolve(entry.getKey) -> entry.getValue
    }.toMap

    val objects: Iterable[RepositoryObject[_]] = manifestEntries.map { e =>
      val (uri, hash) = e
      val obj = store.getObject(uri, hash)
      if (obj.isEmpty) {
        certContextValidationResult.warnForLocation(validationLocation, VALIDATOR_MANIFEST_FILE_NOT_FOUND_BY_AKI, uri.toString, certificateSkiHex)
      }
      obj
    }.collect { case Some(o) => o }

    val classified @ ClassifiedObjects(roas, childrenCertificates, crlsOnManifest) = classify(objects.toSeq)


    crossCheckCrls(crlByAki, crlsOnManifest, validationLocation)
//    crossCheckRepoObjects(validationLocation, roas ++ childrenCertificates)

    classified
  }
}
