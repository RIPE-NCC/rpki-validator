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

import java.util

import lib.Java
import net.ripe.rpki.validator.models.validation._
import scala.collection.JavaConverters._
import java.net.URI
import net.ripe.rpki.validator.util._
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms
import net.ripe.rpki.commons.validation._
import org.joda.time.DateTime

sealed trait ValidatedObject {
  val uri: URI
  val subjectChain: String
  val hash: Option[Array[Byte]]
  val checks: Set[ValidationCheck]
  val isValid: Boolean

  def validationStatus: ValidationStatus = {
    val statuses = checks.map(_.getStatus)
    if (statuses.contains(ValidationStatus.FETCH_ERROR)) ValidationStatus.FETCH_ERROR
    else if (statuses.contains(ValidationStatus.ERROR)) ValidationStatus.ERROR
    else if (statuses.contains(ValidationStatus.WARNING)) ValidationStatus.WARNING
    else ValidationStatus.PASSED
  }

  def hasCheckKey(key: String): Boolean = checks.exists(_.getKey == key)
}

case class InvalidObject(subjectChain: String, uri: URI, hash: Option[Array[Byte]], checks: Set[ValidationCheck]) extends ValidatedObject {
  override val isValid = false
}

case class ValidObject(subjectChain: String, uri: URI, hash: Option[Array[Byte]], checks: Set[ValidationCheck], repositoryObject: CertificateRepositoryObject) extends ValidatedObject {
  override val isValid = true
}

object ValidatedObject {
  val separator = " / "

  def flattenSubjectChain(subjectChain: util.List[String]): String = subjectChain.asScala.reduce(_ + separator + _)

  def objectName(obj: Option[(String, RepositoryObject.ROType)]): String = obj match {
    case Some((name: String, r: RoaObject)) => name
    case Some((_, m: ManifestObject)) => "manifest"
    case Some((_, c: CrlObject)) => "crl"
    case Some((_, c: CertificateObject)) => "certificate"
    case None => ""
    case _ => "Unknown object"
  }

  def invalid(obj: Option[(String, RepositoryObject.ROType)], subjectChain: util.List[String], uri: URI, hash: Option[Array[Byte]], checks: Set[ValidationCheck]) =
    InvalidObject(flattenSubjectChain(subjectChain) + separator + objectName(obj), uri, hash, checks)

  def valid(obj: Option[(String, RepositoryObject.ROType)], subjectChain: util.List[String], uri: URI, hash: Option[Array[Byte]], checks: Set[ValidationCheck],
            repositoryObject: CertificateRepositoryObject) =
    ValidObject(flattenSubjectChain(subjectChain) + separator + objectName(obj), uri, hash, checks, repositoryObject)
}

case class ObjectCountDrop(previousNumber: Int, firstObserved: DateTime = new DateTime())

object TrustAnchorValidations {

  val DropThresholdMaxErrors = 1
  val DropThresholdMinObjectCountFactor: Double = 0.9

  def crossedDropThreshold(previousNumber: Int, newValidatedObjects: Seq[ValidatedObject]): Boolean = {
    previousNumber * DropThresholdMinObjectCountFactor >= newValidatedObjects.size &&
      ValidatedObjects.statusCounts(newValidatedObjects).getOrElse(ValidationStatus.ERROR, 0) >= DropThresholdMaxErrors
  }
}

case class TrustAnchorValidations(validatedObjects: Seq[ValidatedObject] = Seq.empty, objectCountDropObserved: Option[ObjectCountDrop] = None) {

  import TrustAnchorValidations._

  def processNewValidatedObjects(newValidatedObjects: Seq[ValidatedObject]) = {

    def checkForObjectCountDrop(newValidatedObjects: Seq[ValidatedObject]): Option[ObjectCountDrop] = {
      val previousNumber = validatedObjects.size
      if (crossedDropThreshold(previousNumber, newValidatedObjects)) {
        Some(ObjectCountDrop(previousNumber))
      } else
        None
    }

    def checkForObjectDropRecovery(newValidatedObjects: Seq[ValidatedObject], existingDrop: ObjectCountDrop): Option[ObjectCountDrop] = {
      if (crossedDropThreshold(existingDrop.previousNumber, newValidatedObjects)) {
        Some(existingDrop)
      } else
        None
    }

    if (validatedObjects.isEmpty) {
      TrustAnchorValidations(newValidatedObjects)
    } else {
      objectCountDropObserved match {
        case None => TrustAnchorValidations(newValidatedObjects, checkForObjectCountDrop(newValidatedObjects))
        case Some(drop) => TrustAnchorValidations(newValidatedObjects, checkForObjectDropRecovery(newValidatedObjects, drop))
      }
    }
  }
}

class ValidatedObjects(val all: Map[TrustAnchorLocator, TrustAnchorValidations]) {

  def validationStatusCountByTal: Map[TrustAnchorLocator, Map[ValidationStatus, Int]] = for ((locator, taValidations) <- all) yield {
    locator -> ValidatedObjects.statusCounts(taValidations.validatedObjects)
  }

  def getValidatedRtrPrefixes = {
    for {
      (locator, taValidations) <- all
      oLocator = Option(locator)
      ValidObject(_, _, _, _, roa: RoaCms) <- taValidations.validatedObjects
      roaPrefix <- roa.getPrefixes.asScala
    } yield {
      RtrPrefix(roa.getAsn, roaPrefix.getPrefix, Java.toOption(roaPrefix.getMaximumLength), oLocator)
    }
  }

  def update(locator: TrustAnchorLocator, newValidatedObjects: Seq[ValidatedObject]) = {

    val taValidations: TrustAnchorValidations = all.get(locator) match {
      case Some(existingTaValidations) => existingTaValidations.processNewValidatedObjects(newValidatedObjects)
      case None => TrustAnchorValidations(validatedObjects = newValidatedObjects)
    }

    new ValidatedObjects(all.updated(locator, taValidations))
  }

  def removeTrustAnchor(locator: TrustAnchorLocator) = {
    new ValidatedObjects(all.filterKeys(key => !key.equals(locator)))
  }

}

object ValidatedObjects {

  def apply(trustAnchors: TrustAnchors): ValidatedObjects = {
    new ValidatedObjects(trustAnchors.all.map(ta => ta.locator -> TrustAnchorValidations(validatedObjects = Seq.empty[ValidatedObject]))(collection.breakOut))
  }

  def statusCounts(validatedObjects: Seq[ValidatedObject]): Map[ValidationStatus, Int] = {
    validatedObjects.groupBy(_.validationStatus).map(p => p._1 -> p._2.size)
  }
}
