/**
 * The BSD License
 *
 * Copyright (c) 2010, 2011 RIPE NCC
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
package config

import scala.collection.JavaConverters._
import scala.collection.mutable
import mutable.HashSet
import net.ripe.certification.validator.util.TrustAnchorLocator
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import org.joda.time.DateTime
import models._

case class MemoryImage(filters: Filters, whitelist: Whitelist, trustAnchors: TrustAnchors, roas: Roas, version: Int = 0) {
  val lastUpdateTime: DateTime = new DateTime

  def updateTrustAnchor(tal: TrustAnchorLocator, certificate: CertificateRepositoryObjectValidationContext) =
    copy(trustAnchors = trustAnchors.update(tal, certificate))

  def updateRoas(tal: TrustAnchorLocator, validatedRoas: Seq[ValidatedRoa]) =
    copy(version = version + 1, roas = roas.update(tal, validatedRoas))

  def addWhitelistEntry(entry: RtrPrefix) = copy(version = version + 1, whitelist = whitelist.addEntry(entry))

  def removeWhitelistEntry(entry: RtrPrefix) = copy(version = version + 1, whitelist = whitelist.removeEntry(entry))

  def getDistinctRtrPrefixes(): Set[RtrPrefix] = {
    //val result: mutable.Set[RtrPrefix] = new HashSet[RtrPrefix]()

    val result = for {
      validatedRoas <- roas.all.values if validatedRoas.isDefined
      validatedRoa <- validatedRoas.get
      roa = validatedRoa.roa
      roaPrefix <- roa.getPrefixes().asScala
    } yield {
      new RtrPrefix(roa.getAsn, roaPrefix.getPrefix,
        if (roaPrefix.getMaximumLength == null) None else Some(roaPrefix.getMaximumLength))
    }

    Set.empty[RtrPrefix] ++ result
  }


//  {
//    val pairs = for {
//      (_, validatedRoas) <- getCurrentRoas.apply().all.toSeq if validatedRoas.isDefined
//      validatedRoa <- validatedRoas.get.sortBy(_.roa.getAsn().getValue())
//      roa = validatedRoa.roa
//      prefix <- roa.getPrefixes().asScala
//    } yield {
//      (prefix, roa.getAsn)
//    }
//    pairs.distinct
//  }

  def addFilter(filter: IgnoreFilter) = copy(version = version + 1, filters = filters.addFilter(filter))

  def removeFilter(filter: IgnoreFilter) = copy(version = version + 1, filters = filters.removeFilter(filter))
}
