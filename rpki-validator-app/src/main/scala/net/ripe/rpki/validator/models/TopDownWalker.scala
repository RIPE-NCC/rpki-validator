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
import java.util

import com.google.common.collect.Lists
import grizzled.slf4j.Logging
import net.ripe.ipresource.{IpResourceSet, IpResourceType}
import net.ripe.rpki.commons.crypto.crl.{CrlLocator, X509Crl}
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import net.ripe.rpki.commons.validation.ValidationString._
import net.ripe.rpki.commons.validation._
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import net.ripe.rpki.validator.lib.Structures._
import net.ripe.rpki.validator.models.validation.RepositoryObject.ROType
import net.ripe.rpki.validator.models.validation._
import net.ripe.rpki.validator.store.Storage
import org.apache.commons.lang.Validate
import org.joda.time.Instant

import scala.collection.JavaConverters._
import scala.language.reflectiveCalls

class TopDownWalker(certificateContext: CertificateRepositoryObjectValidationContext,
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

  def execute: Seq[ValidatedObject] = fBlock(validateContext) { vo =>
    updateValidationTimes(vo.map(vo => vo.uri -> vo).toMap)
  }

  private def validateContext: Seq[ValidatedObject] = {
    logger.debug(s"Validating ${certificateContext.getLocation}")

    val fetchErrors = preferredFetchLocation.map(prefetch).getOrElse(Seq())

    val mftList = fetchMftsByAKI
    val validatedObjects = findRecentValidMftWithCrl(mftList) match {
      case Some(mftSearchResult) =>
        validateManifestChildren(mftSearchResult)

      case None =>
        Seq(ValidatedObject.invalid(None, certificateContext.getSubjectChain, certificateContext.getLocation, None,
          Set(new ValidationCheck(ValidationStatus.WARNING, VALIDATOR_CA_SHOULD_HAVE_MANIFEST, certificateSkiHex))))
    }

    fetchErrors ++ validatedObjects
  }

  def validateManifestChildren(manifestSearchResult: ManifestSearchResult): Seq[ValidatedObject] = {
    val ManifestSearchResult(manifest, crl, mftObjects, mftChecks, skippedObjects) = manifestSearchResult

    val ClassifiedObjects(roas, childrenCertificates, crlList) = classify(mftObjects)

    val checks = checkManifestUrlOnCertMatchesLocationInRepo(manifest).toList ++
      mftChecks ++
      check(roas, crl) ++
      check(childrenCertificates, crl)

    val checkMap = checks.groupBy(_.location)

    val validatedCerts = childrenCertificates.map { c =>
      val v = validatedObject(checkMap)(c)
      new { val cert = c; val validatedObject = v; val valid = c.decoded.isObjectIssuer && v.isValid; }
    }

    val everythingValidated = roas.map(validatedObject(checkMap)) ++
      validatedCerts.map(_.validatedObject) ++
      crlList.map(validatedObject(checkMap)) ++
      Seq(manifest).map(validatedObject(checkMap)) ++
      skippedObjects ++
      validatedCerts.filter(_.valid).map(_.cert).par.flatMap(stepDown(manifest))

    everythingValidated
  }

  private def updateValidationTimes(validatedObjectMap: Map[URI, ValidatedObject]) = {
    val hashes = validatedObjectMap.values.filter(_.hash.isDefined).map(o => (o.uri, o.hash.get))
    val uriMap: Map[URI, Iterable[(URI, Array[Byte])]] = hashes.groupBy(_._1)

    val hashesOnly = hashes.map(_._2)
    hashesOnly.foreach { hash =>
      logger.debug("Setting validation time for the object: " + HashUtil.stringify(hash))
    }
    store.updateValidationTimestamp(hashesOnly, Instant.now())
    store.cleanOutdated(uriMap)
  }

  private def validatedObject(checkMap: Map[ValidationLocation, List[Check]])(r: RepositoryObject.ROType): ValidatedObject = {
    val uri = new URI(r.url)
    val validationChecks = checkMap.get(new ValidationLocation(uri)).map(_.map(_.impl).toSet)
    val hasErrors = validationChecks.exists(c => !c.forall(_.isOk))
    if (hasErrors) {
      ValidatedObject.invalid(Some(r), certificateContext.getSubjectChain, uri, Some(r.hash), validationChecks.get)
    } else {
      ValidatedObject.valid(Some(r), certificateContext.getSubjectChain, uri, Some(r.hash), validationChecks.getOrElse(Set()), r.decoded)
    }
  }

  private def check(objects: Seq[RepositoryObject.ROType], crl: CrlObject): List[Check] = {
    objects.flatMap { o =>
      val loc = location(o)
      val result = ValidationResult.withLocation(loc)
      o.decoded.validate(o.url, certificateContext, crlLocator(crl), validationOptions, result)
      toChecks(loc, result)
    }.toList
  }

  private def toChecks(location: ValidationLocation, result: ValidationResult): List[Check] = {
    result.getWarnings(location).asScala.map(r => warning(location, r.getKey, r.getParams: _*)).toList ++
      result.getFailures(location).asScala.map(r => error(location, r.getKey, r.getParams: _*)).toList
  }

  private def getResourcesOfType(types: util.EnumSet[IpResourceType], set: IpResourceSet): IpResourceSet = {
    val resources = set.asScala.filter(ipResource => types.contains(ipResource.getType))
    import scala.collection.JavaConversions._
    new IpResourceSet(resources)
  }

  private def stepDown(parentManifest: ManifestObject)(cert: RepositoryObject[X509ResourceCertificate]): Seq[ValidatedObject] = {
    val childCert = cert.decoded
    val ski = HashUtil.stringify(childCert.getSubjectKeyIdentifier)
    if (seen.contains(ski)) {
      val mftUri = new URI(parentManifest.url)
      if (childCert.isRoot) {
        val check = new ValidationCheck(ValidationStatus.WARNING, VALIDATOR_ROOT_CERTIFICATE_INCLUDED_IN_MANIFEST)
        Seq(ValidatedObject.valid(Some(cert), certificateContext.getSubjectChain, mftUri, Some(parentManifest.hash), Set(check), childCert))
      } else {
        logger.error(s"Found circular reference of certificates: from ${certificateContext.getLocation} [$certificateSkiHex] to ${cert.url} [$ski]")
        val check = new ValidationCheck(ValidationStatus.ERROR, VALIDATOR_CIRCULAR_REFERENCE, certificateContext.getLocation.toString, cert.url.toString)
        Seq(ValidatedObject.invalid(Some(cert), certificateContext.getSubjectChain, mftUri, Some(parentManifest.hash), Set(check)))
      }
    } else {
      val childResources = if (childCert.isResourceSetInherited) getResourcesOfType(childCert.getInheritedResourceTypes, certificateContext.getResources) else childCert.getResources
      val childSubjectChain = Lists.newArrayList(certificateContext.getSubjectChain)
      childSubjectChain.add(childCert.getSubject.getName)
      val newValidationContext = new CertificateRepositoryObjectValidationContext(new URI(cert.url), childCert, childResources, childSubjectChain)
      val nextLevelWalker = new TopDownWalker(newValidationContext, store, repoService, validationOptions, validationStartTime)(seen)
      nextLevelWalker.validateContext
    }
  }

  private def prefetch(uri: URI) = {
    repoService.visitRepo(uri).map { error =>
      ValidatedObject.invalid(None, certificateContext.getSubjectChain, error.url, None, Set(new ValidationCheck(ValidationStatus.FETCH_ERROR, VALIDATOR_REPO_EXECUTION, error.message)))
    }
  }

  private def validateObject(obj: RepositoryObject.ROType)(validate: ValidationResult => Unit) =
    fBlock(ValidationResult.withLocation(location(obj))) { validationResult =>
      validate(validationResult)
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

  private def getCrlChecks(mft: ManifestObject, crl: Either[Check, CrlObject]) = crl match {
    case Right(c) => toChecks(location(c), _validateCrl(c))
    case _ => List[Check]()
  }

  private def getMftChecks(mft: ManifestObject, crl: Either[Check, CrlObject]) = crl match {
    case Right(c) =>
      val checks = toChecks(location(c), validateMft(c, mft))
      if (!HashUtil.equals(c.aki, mft.aki))
        error(location(c), CRL_AKI_MISMATCH) :: checks
      else
        checks
    case _ =>
      List[Check]()
  }

  case class ManifestSearchResult(manifest: ManifestObject,
                                  crl: CrlObject,
                                  manifestObjects: Seq[RepositoryObject.ROType],
                                  checksForManifest: Seq[Check],
                                  skippedObjects: Seq[InvalidObject])

  def findRecentValidMftWithCrl(mftList: Seq[ManifestObject]): Option[ManifestSearchResult] = {
    // sort manifests chronologically so that
    // the latest one goes first
    val recentFirstManifests = mftList.sortBy(_.decoded.getNumber.negate())

    // use "view" here to make it lazy and
    // avoid checking every existing manifest
    val validatedManifestData = recentFirstManifests.view.map { mft =>
      // get CRLs on the manifest
      val (mftObjects, errors, _) = getManifestObjects(mft)
      val crlsOnManifest = mftObjects.collect { case c: CrlObject => c }

      val crlOrError = getCrl(crlsOnManifest, location(mft))

      val crlChecks = getCrlChecks(mft, crlOrError)
      val mftChecks = getMftChecks(mft, crlOrError)
      (mft, crlOrError.right.toOption, mftObjects, errors ++ crlOrError.left.toSeq, crlChecks ++ mftChecks)
    }

    // Add warnings and retain the errors for the cases when we have to move from one invalid manifest to an older one.
    var checksForSkippedMfts = Seq[InvalidObject]()
    var checksForValidMft = Seq[Check]()
    val mostRecentValidMft = validatedManifestData.iterator.find { x =>
      val (mft, crl, _, nonFatalChecks, fatalChecks) = x
      val errorsExist = fatalChecks.exists(isError)

      val isMftValid = !errorsExist && crl.isDefined
      if (!isMftValid) {
        val skippedChecks: Seq[Check] = Seq(warning(location(mft), VALIDATOR_MANIFEST_IS_INVALID)) ++ nonFatalChecks ++ fatalChecks

        val mftChecks = skippedChecks.filter(c => c.location.getName.equals(mft.url))
        val crlChecks = skippedChecks.filter(c => crl.isDefined && c.location.getName.equals(crl.get.url))
        val mftUri = new URI(mft.url)

        var skippedInvalidObjects: Seq[InvalidObject] = Seq(ValidatedObject.invalid(Some(mft), certificateContext.getSubjectChain, mftUri, Some(mft.hash), mftChecks.map(c => c.impl).toSet))
        if (crlChecks.nonEmpty) {
          val invalidObject = ValidatedObject.invalid(Some(mft), certificateContext.getSubjectChain, new URI(crl.get.url), Some(crl.get.hash), crlChecks.map(c => c.impl).toSet)
          skippedInvalidObjects ++= Seq(invalidObject)
        }
        checksForSkippedMfts ++= skippedInvalidObjects
      } else {
        checksForValidMft = nonFatalChecks
      }
      isMftValid
    }

    // replace the particular manifest checks with all the checks
    // we've found while searching for the proper manifest
    for { (mft, oCrl, mftObjects, _, _) <- mostRecentValidMft; crl <- oCrl }
      yield ManifestSearchResult(mft, crl, mftObjects, checksForValidMft, checksForSkippedMfts)
  }

  private def validateMft(crl: CrlObject, mft: ManifestObject): ValidationResult =
    validateObject(mft) { validationResult =>
      mft.decoded.validate(mft.url, certificateContext, crlLocator(crl), validationOptions, validationResult)
    }

  case class ClassifiedObjects(roas: Seq[RoaObject], certificates: Seq[CertificateObject], crls: Seq[CrlObject])

  private def classify(objects: Seq[RepositoryObject.ROType]) = {
    var (roas, certificates, crls) = (List[RoaObject](), List[CertificateObject](), List[CrlObject]())
    objects.foreach {
      case roa: RoaObject => roas = roa :: roas
      case cer: CertificateObject => certificates = cer :: certificates
      case crl: CrlObject => crls = crl :: crls
      case _ =>
    }
    ClassifiedObjects(roas.toSeq, certificates.toSeq, crls.toSeq)
  }

  private def checkManifestUrlOnCertMatchesLocationInRepo(manifest: ManifestObject): Option[Check] = {
    val manifestLocationInCertificate = certificateContext.getManifestURI.toString
    val manifestLocationInRepository = manifest.url
    if (!manifestLocationInRepository.equalsIgnoreCase(manifestLocationInCertificate)) {
      Some(warning(new ValidationLocation(manifestLocationInRepository),
        VALIDATOR_MANIFEST_LOCATION_MISMATCH, manifestLocationInCertificate, manifestLocationInRepository))
    } else {
      None
    }
  }

  private def getCrl(manifestCrlEntries: Seq[CrlObject], validationLocation: ValidationLocation): Either[Check, CrlObject] = {
    if (manifestCrlEntries.isEmpty) {
      Left(error(validationLocation, VALIDATOR_MANIFEST_DOES_NOT_CONTAIN_FILE, "*.crl"))
    } else if (manifestCrlEntries.size > 1) {
      val crlUris = manifestCrlEntries.map(_.url).mkString(",")
      Left(error(validationLocation, VALIDATOR_MANIFEST_DOES_NOT_CONTAIN_FILE, s"Single CRL expected, found: $crlUris"))
    } else {
      Right(manifestCrlEntries.head)
    }
  }

  def getManifestObjects(manifest: ManifestObject): (Seq[ROType], Seq[Check], Map[URI, Array[Byte]]) = {
    val repositoryUri = certificateContext.getRepositoryURI
    val validationLocation = location(manifest)

    val errors = scala.collection.mutable.Buffer[Check]()
    val foundObjects = scala.collection.mutable.Buffer[ROType]()

    val entries = manifest.decoded.getHashes.entrySet().asScala.map { e =>
        (repositoryUri.resolve(e.getKey), e.getValue)
    }.toMap

    entries.foreach { e =>
      val (uri, hash) = e
      val hashStr: String = HashUtil.stringify(hash)
      val objs = store.getObjects(hashStr)

      if (objs.isEmpty)
        errors += error(validationLocation, VALIDATOR_REPOSITORY_OBJECT_NOT_IN_CACHE, uri.toString, hashStr)
      else
        objs.foreach { o =>
          foundObjects += o
          if (o.url != uri.toString) {
            errors += warning(validationLocation, VALIDATOR_MANIFEST_URI_MISMATCH, uri.toString, hashStr, o.url)
          }
        }
    }
    (foundObjects.toSeq, errors.toSeq, entries)
  }
}
