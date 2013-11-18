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

import lib.Java
import scala.collection.JavaConverters._
import java.net.URI
import grizzled.slf4j.Logger
import net.ripe.rpki.validator.util._
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms
import net.ripe.rpki.commons.validation._

sealed trait ValidatedObject {
  val uri: URI
  val checks: Set[ValidationCheck]
  val isValid: Boolean

  def validationStatus: ValidationStatus = {
    val statuses = checks.map(_.getStatus)
    if (statuses.contains(ValidationStatus.ERROR)) ValidationStatus.ERROR
    else if (statuses.contains(ValidationStatus.WARNING)) ValidationStatus.WARNING
    else ValidationStatus.PASSED
  }
}
case class InvalidObject(uri: URI, checks: Set[ValidationCheck]) extends ValidatedObject {
  override val isValid = false
}
case class ValidObject(uri: URI, checks: Set[ValidationCheck], repositoryObject: CertificateRepositoryObject) extends ValidatedObject {
  override val isValid = true
}

class ValidatedObjects(val all: Map[TrustAnchorLocator, Seq[ValidatedObject]]) {

  def validationStatusCountByTal: Map[TrustAnchorLocator, Map[ValidationStatus, Int]] = for ((locator, validatedObjects) <- all) yield {
    locator -> ValidatedObjects.statusCounts(validatedObjects)
  }

  def getValidatedRtrPrefixes = {
    for {
      (locator, validatedObjects) <- all
      ValidObject(_, _, roa: RoaCms) <- validatedObjects
      roaPrefix <- roa.getPrefixes.asScala
    } yield {
      RtrPrefix(roa.getAsn, roaPrefix.getPrefix, Java.toOption(roaPrefix.getMaximumLength), Option(locator))
    }
  }

  def update(locator: TrustAnchorLocator, validatedObjects: Seq[ValidatedObject]) = {

    val currentObjects: Seq[ValidatedObject] = all.get(locator) match {
      case Some(oldValidatedObjects) => oldValidatedObjects
      case None => Seq.empty
    }

    val validatedObjectsWithTaHealth = ValidatedObjects.getValidatedObjectsWithRepositoryHealth(locator.getCertificateLocation, currentObjects , validatedObjects)
    new ValidatedObjects(all.updated(locator, validatedObjectsWithTaHealth))
  }

  def removeTrustAnchor(locator: TrustAnchorLocator) = {
    new ValidatedObjects(all.filterKeys(key => !key.equals(locator)))
  }

}

object ValidatedObjects {
  private val logger = Logger[this.type]

  def apply(trustAnchors: TrustAnchors): ValidatedObjects = {
    new ValidatedObjects(trustAnchors.all.map(ta => ta.locator -> Seq.empty[ValidatedObject])(collection.breakOut))
  }

  def getValidatedObjectsWithRepositoryHealth(taUri: URI, currentValidatedObjects: Seq[ValidatedObject], newValidatedObjects: Seq[ValidatedObject]): Seq[ValidatedObject] = {
    if (currentValidatedObjects.size * 0.9 >= newValidatedObjects.size
         && ValidatedObjects.statusCounts(newValidatedObjects).isDefinedAt(ValidationStatus.ERROR) ) {

      newValidatedObjects :+ InvalidObject(
          taUri,
          Set(new ValidationCheck(ValidationStatus.ERROR, ValidationString.VALIDATOR_REPOSITORY_OBJECT_DROP, currentValidatedObjects.size.toString, newValidatedObjects.size.toString)))
    } else {
      newValidatedObjects
    }
  }

  def statusCounts(validatedObjects: Seq[ValidatedObject]): Map[ValidationStatus, Int] = {
    validatedObjects.groupBy(_.validationStatus).map(p => p._1 -> p._2.size)
  }
}
