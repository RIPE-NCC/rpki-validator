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
package fetchers

import models._
import net.ripe.certification.validator.util.TrustAnchorLocator
import net.ripe.certification.validator.fetchers.NotifyingCertificateRepositoryObjectFetcher
import net.ripe.commons.certification.validation.ValidationResult
import net.ripe.commons.certification.CertificateRepositoryObject
import net.ripe.commons.certification.validation.ValidationLocation
import net.ripe.commons.certification.cms.roa.RoaCms

import java.net.URI
import scala.collection.JavaConverters._

class ValidatedObjectCollector(trustAnchor: TrustAnchorLocator, objects: collection.mutable.Builder[(URI, ValidatedObject), _]) extends NotifyingCertificateRepositoryObjectFetcher.ListenerAdapter {

  override def afterFetchFailure(uri: URI, result: ValidationResult) {
    objects += uri -> new InvalidObject(uri, result.getAllValidationChecksForLocation(new ValidationLocation(uri)).asScala.toSet)
  }

  override def afterFetchSuccess(uri: URI, obj: CertificateRepositoryObject, result: ValidationResult) {
    obj match {
      case roa: RoaCms =>
        objects += uri -> new ValidRoa(uri, result.getAllValidationChecksForLocation(new ValidationLocation(uri)).asScala.toSet, roa)
      case _ =>
        objects += uri -> new ValidObject(uri, result.getAllValidationChecksForLocation(new ValidationLocation(uri)).asScala.toSet, obj)
    }
  }

}