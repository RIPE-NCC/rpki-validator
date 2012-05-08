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
package statistics

import net.ripe.commons.certification.validation.ValidationResult
import java.net.URI
import models.ValidatedObject
import net.ripe.rpki.validator.models.ValidObject
import net.ripe.commons.certification.x509cert.X509ResourceCertificate
import net.ripe.rpki.validator.models.ValidObject
import net.ripe.commons.certification.cms.manifest.ManifestCms
import scala.collection.JavaConverters._
import net.ripe.rpki.validator.models.InvalidObject
import net.ripe.commons.certification.validation.ValidationCheck
import net.ripe.commons.certification.validation.ValidationStatus
import net.ripe.commons.certification.validation.ValidationString

object InconsistentRepositoryChecker {

  def check(objectMap: Map[URI, ValidatedObject]): Map[URI, Boolean] = {

    val objects = objectMap.values.toSeq

    validCaCertificates(objects).map { cert =>
      val inconsistencyKeys = List(ValidationString.VALIDATOR_READ_FILE, ValidationString.VALIDATOR_FILE_CONTENT)

      val mft = findValidManifest(objects, cert.getManifestUri)
      val validatedObjects = findObjectsForUris(objectMap, getManifestEntryUris(cert.getRepositoryUri, mft))
      val checks = validatedObjects.flatMap {
        vo => vo.checks
      }
      val problems = checks.exists { check =>
        check.getStatus == ValidationStatus.ERROR && inconsistencyKeys.contains(check.getKey)
      }

      (cert.getManifestUri, problems)
    }.toMap
  }

  def validCaCertificates(objects: Seq[ValidatedObject]) = objects.collect {
    case ValidObject(_, _, cert: X509ResourceCertificate) if cert.isCa => cert
  }

  def findValidManifest(objects: Seq[ValidatedObject], manifestUri: URI) = objects.collect {
    case ValidObject(uri, _, mft: ManifestCms) if uri == manifestUri => mft
  }.headOption

  def getManifestEntryUris(certificateRepositoryUri: URI, manifestOption: Option[ManifestCms]): Seq[URI] = {
    manifestOption match {
      case None => Seq.empty
      case Some(mft) => {
        mft.getFileNames.asScala map {
          filename: String => certificateRepositoryUri.resolve(filename)
        }
      }.toSeq
    }
  }

  def findObjectsForUris(objectMap: Map[URI, ValidatedObject], uris: Seq[URI]): Seq[ValidatedObject] = {
    uris.map {
      uri => objectMap.getOrElse(uri, new InvalidObject(uri, Set.empty))
    }
  }
}

