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
import net.ripe.rpki.commons.crypto.crl.{CrlLocator, X509Crl}
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import net.ripe.rpki.commons.validation.ValidationString._
import net.ripe.rpki.commons.validation._
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import net.ripe.rpki.validator.models.validation.RepositoryObject.ROType
import net.ripe.rpki.validator.models.validation._
import net.ripe.rpki.validator.store.Storage
import org.apache.commons.lang.Validate
import org.joda.time.Instant

import scala.collection.JavaConverters._

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

  private[models] def preferredFetchLocation: Option[URI] = Option(certificateContext.getRpkiNotifyURI).orElse(Option(certificateContext.getRepositoryURI))

  case class Check(location: ValidationLocation, impl: ValidationCheck)

  private def error(location: ValidationLocation, key: String, params: String*) =
    Check(location, new ValidationCheck(ValidationStatus.ERROR, key, params: _*))

  private def warning(location: ValidationLocation, key: String, params: String*) =
    Check(location, new ValidationCheck(ValidationStatus.WARNING, key, params: _*))

  private def isError(c: Check) = !c.impl.isOk

  private def location(o: RepositoryObject.ROType) = new ValidationLocation(o.url)

  def execute: Map[URI, ValidatedObject] = {
    val validatedObjects = validateContext
    updateValidationTimes(validatedObjects)
    validatedObjects
  }

  private def validateContext = {
    logger.info(s"Validating ${certificateContext.getLocation}")

    val fetchErrors = preferredFetchLocation.map {
      prefetch(_).map { e => e.uri -> e } toMap
    }.getOrElse(Map())

    val mftList = fetchMftsByAKI
    val validatedObjects = findRecentValidMftWithCrl(mftList) match {
      case Some((manifest, crl, mftObjects, mftCrlChecks)) =>
        val ClassifiedObjects(roas, childrenCertificates, crlList) = classify(mftObjects)

        val checks = checkManifestUrlOnCertMatchesLocationInRepo(manifest).toList ++
          mftCrlChecks ++
          check(roas, crl) ++
          check(childrenCertificates, crl)

        val checkMap = checks.groupBy(_.location)

        val validatedChildren = childrenCertificates.view.map { c =>
          val v = validatedObject(checkMap)(c)
          (c, v, c.decoded.isObjectIssuer && v._2.isValid)
        }

        Seq(roas.map(validatedObject(checkMap)),
          validatedChildren.map(_._2).force,
          crlList.map(validatedObject(checkMap)),
          mftList.map(validatedObject(checkMap)),
          validatedChildren.filter(_._3).map(_._1).force.flatMap(stepDown)
        ).map(_.toMap).fold(Map[URI, ValidatedObject]()) { (objects, m) => merge(objects, m) }

      case None =>
        Map(certificateContext.getLocation -> InvalidObject(certificateContext.getLocation,
          Set(new ValidationCheck(ValidationStatus.WARNING, VALIDATOR_CA_SHOULD_HAVE_MANIFEST, certificateSkiHex))))
    }

    fetchErrors ++ validatedObjects
  }

  private def updateValidationTimes(validatedObjectMap: Map[URI, ValidatedObject]) = {
    val validatedObjects = validatedObjectMap.keySet.map(_.toString)
    validatedObjects.foreach { uri =>
      logger.info("Setting validation time for the object: " + uri)
    }
    store.updateValidationTimestamp(validatedObjects)
  }

  private def merge(m1: Map[URI, ValidatedObject], m2: Map[URI, ValidatedObject]): Map[URI, ValidatedObject] = {
    m1.map { e1 =>
      val (u1, v1) = e1
      m2.get(u1) match {
        case None => e1
        case Some(v2) => (u1, merge(v1, v2))
      }
    } ++ m2.filterKeys(!m1.contains(_))
  }

  private def merge(vo1: ValidatedObject, vo2: ValidatedObject): ValidatedObject = {
    (vo1, vo2) match {
      case (InvalidObject(u1, checks1), InvalidObject(u2, checks2)) => InvalidObject(u1, checks1 ++ checks2)
      case (InvalidObject(u1, checks1), ValidObject(u2, checks2, _)) => InvalidObject(u1, checks1 ++ checks2)
      case (ValidObject(u1, checks1, _), InvalidObject(u2, checks2)) => InvalidObject(u1, checks1 ++ checks2)
      case (ValidObject(u1, checks1, obj1), ValidObject(u2, checks2, obj2)) => ValidObject(u1, checks1 ++ checks2, obj1)
    }
  }

  def validatedObject(checkMap: Map[ValidationLocation, List[Check]])(r: RepositoryObject.ROType): (URI, ValidatedObject) = {
    val uri = new URI(r.url)
    val validationChecks = checkMap.get(new ValidationLocation(uri)).map(_.map(_.impl).toSet)
    val hasErrors = validationChecks.exists(c => !c.forall(_.isOk))
    if (hasErrors) {
      uri -> InvalidObject(uri, validationChecks.get)
    } else {
      uri -> ValidObject(uri, validationChecks.getOrElse(Set()), r.decoded)
    }
  }

  def check(objects: Seq[RepositoryObject.ROType], crl: CrlObject): List[Check] = {
    objects.map { o =>
      val location = new ValidationLocation(o.url)
      val result = ValidationResult.withLocation(location)
      o.decoded.validate(o.url, certificateContext, crlLocator(crl), validationOptions, result)
      toChecks(location, result)
    }.flatten.toList
  }

  private def toChecks(location: ValidationLocation, result: ValidationResult): List[Check] = {
    result.getWarnings(location).asScala.map(r => warning(location, r.getKey, r.getParams: _*)).toList ++
      result.getFailures(location).asScala.map(r => error(location, r.getKey, r.getParams: _*)).toList
  }

  private def stepDown(cert: RepositoryObject[X509ResourceCertificate]): Map[URI, ValidatedObject] = {
    val ski: String = HashUtil.stringify(cert.decoded.getSubjectKeyIdentifier)
    if (seen.contains(ski)) {
      logger.error(s"Found circular reference of certificates: from ${certificateContext.getLocation} [$certificateSkiHex] to ${cert.url} [$ski]")
      // TODO add Check with error
      Map()
    } else {
      val newValidationContext = new CertificateRepositoryObjectValidationContext(new URI(cert.url), cert.decoded)
      val nextLevelWalker = new TopDownWalker2(newValidationContext, store, repoService, validationOptions, validationStartTime)(seen)
      nextLevelWalker.validateContext
    }
  }

  private def prefetch(uri: URI) = {
    repoService.visitRepo(uri).map { error =>
      InvalidObject(error.url, Set(new ValidationCheck(ValidationStatus.FETCH_ERROR, error.message)))
    }
  }

  private def validateObject(obj: RepositoryObject.ROType)(validate: ValidationResult => Unit) = {
    val validationResult = ValidationResult.withLocation(location(obj))
    validate(validationResult)
    validationResult
  }

  private def _validateCrl(crl: CrlObject): ValidationResult =
    validateObject(crl) { validationResult =>
      crl.decoded.validate(crl.url, certificateContext, crlLocator(crl), validationOptions, validationResult)
    }

  private def fetchMftsByAKI: Seq[ManifestObject] = store.getManifests(certificateContext.getSubjectKeyIdentifier)

  private def crlLocator(crl: CrlObject) = new CrlLocator {
    override def getCrl(uri: URI, context: CertificateRepositoryObjectValidationContext, result: ValidationResult): X509Crl =
      crl.decoded
  }


  private def getCrlChecks(mft: ManifestObject, crl: Option[CrlObject]) = crl.fold {
    List(error(location(mft), CRL_REQUIRED))
  } { c =>
    toChecks(location(c), _validateCrl(c))
  }

  private def getMftChecks(mft: ManifestObject, crl: Option[CrlObject]) = crl.fold {
    List[Check]()
  } { c =>
    val checks = toChecks(location(c), _validateMft(c, mft))
    if (!HashUtil.equals(c.aki, mft.aki))
      error(location(c), CRL_AKI_MISMATCH) :: checks
    else
      checks
  }

  private def findRecentValidMftWithCrl(mftList: Seq[ManifestObject]): Option[(ManifestObject, CrlObject, Seq[RepositoryObject.ROType], Seq[Check])] = {
    // sort manifests chronologically so that
    // the latest one goes first
    val recentFirstManifests = mftList.sortBy(_.decoded.getNumber.negate)

    // use "view" here to make it lazy and
    // avoid checking every existing manifest
    val validatedManifests = recentFirstManifests.view.map { mft =>
      // get CRLs on the manifest
      val (mftObjects, warnings, _) = getManifestObjects(mft)
      val crlsOnManifest = mftObjects.collect { case c: CrlObject => c }

      val (crl, crlWarnings) = crossCheckCrls(crlsOnManifest, location(mft))

      val crlChecks = getCrlChecks(mft, crl)
      val mftChecks = getMftChecks(mft, crl)
      (mft, crl, mftObjects, warnings ++ crlChecks ++ mftChecks ++ crlWarnings.toList)
    }

    // Add warnings for the cases when we have to move
    // from one manifest to an older one. That's a
    // problem by itself.
    var allChecks = Seq[Check]()
    val mft = validatedManifests.iterator.find { x =>
      val (mft, crl, _, checks) = x
      allChecks ++= checks

      // TODO Verify this: is it a correct strategy to
      // TODO check for error presence
      val errorsExist = checks.exists(isError)
      if (errorsExist) {
        allChecks :+ warning(location(mft), VALIDATOR_MANIFEST_IS_INVALID)
      }
      !errorsExist && crl.isDefined
    }

    // replace the particular manifest checks with all the checks
    // we've found while searching for the proper manifest
    for { m <- mft; c <- m._2 }
      yield (m._1, c, m._3, allChecks)
  }

  private def _validateMft(crl: CrlObject, mft: ManifestObject): ValidationResult =
    validateObject(mft) { validationResult =>
      mft.decoded.validate(mft.url, certificateContext, crlLocator(crl), validationOptions, validationResult)
    }

  case class ClassifiedObjects(roas: Seq[RoaObject], certificates: Seq[CertificateObject], crls: Seq[CrlObject])

  private def classify(objects: Seq[RepositoryObject.ROType]) = {
    var (roas, certificates, crls) = (List[RoaObject](), List[CertificateObject](), List[CrlObject]())
    val c = objects.foreach {
      case roa: RoaObject => roas = roa :: roas
      case cer: CertificateObject => certificates = cer :: certificates
      case crl: CrlObject => crls = crl :: crls
      case _ =>
    }
    ClassifiedObjects(roas.toSeq, certificates.toSeq, crls.toSeq)
  }

  def checkManifestUrlOnCertMatchesLocationInRepo(manifest: ManifestObject): Option[Check] = {
    val manifestLocationInCertificate = certificateContext.getManifestURI.toString
    val manifestLocationInRepository = manifest.url
    if (!manifestLocationInRepository.equalsIgnoreCase(manifestLocationInCertificate)) {
      Some(warning(new ValidationLocation(manifestLocationInRepository),
        VALIDATOR_MANIFEST_LOCATION_MISMATCH, manifestLocationInCertificate, manifestLocationInRepository))
    } else
      None
  }

  private def crossCheckCrls(manifestCrlEntries: Seq[CrlObject], validationLocation: ValidationLocation): (Option[CrlObject], Option[Check]) = {
    if (manifestCrlEntries.isEmpty) {
      (None, Some(warning(validationLocation, VALIDATOR_MANIFEST_DOES_NOT_CONTAIN_FILE, "*.obj")))
    } else if (manifestCrlEntries.size > 1) {
      val crlUris = manifestCrlEntries.map(_.url).mkString(",")
      (None, Some(warning(validationLocation, VALIDATOR_MANIFEST_DOES_NOT_CONTAIN_FILE, s"Single CRL expected, found: $crlUris")))
    } else
        (Some(manifestCrlEntries.head), None)
  }


  def getManifestObjects(manifest: ManifestObject): (Seq[ROType], Seq[Check], Map[URI, Array[Byte]]) = {
    val repositoryUri = certificateContext.getRepositoryURI
    val validationLocation = location(manifest)

    val warnings = scala.collection.mutable.Buffer[Check]()
    val foundObjects = scala.collection.mutable.Buffer[ROType]()

    val entries = manifest.decoded.getHashes.entrySet().asScala.map { e =>
        (repositoryUri.resolve(e.getKey), e.getValue)
    }.toMap

    entries.foreach { e =>
      val (uri, hash) = e
      val obj = store.getObject(HashUtil.stringify(hash))

      if (obj.isEmpty)
        warnings += warning(validationLocation, VALIDATOR_REPOSITORY_OBJECT_NOT_IN_CACHE, uri.toString, certificateSkiHex)
      else
        obj.foreach { o =>
          if (o.url == uri.toString) {
            foundObjects += o
          } else {
            warnings += warning(validationLocation, VALIDATOR_MANIFEST_URI_MISMATCH, uri.toString, certificateSkiHex)
          }
        }
    }
    (foundObjects.toSeq, warnings.toSeq, entries)
  }
}
