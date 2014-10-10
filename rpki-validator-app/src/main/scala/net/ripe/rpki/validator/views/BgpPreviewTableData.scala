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
package views

import lib.NumberResources._
import bgp.preview.BgpValidatedAnnouncement
import net.ripe.ipresource.IpRange
import net.ripe.ipresource.Asn
import scala.xml.Xhtml
import net.ripe.rpki.validator.models.RouteValidity._
import net.ripe.rpki.validator.models.RouteValidity.RouteValidity

abstract class BgpPreviewTableData(validatedAnnouncements: IndexedSeq[BgpValidatedAnnouncement]) extends DataTableJsonView[BgpValidatedAnnouncement] {

  private object RouteValidityOrdering extends Ordering[RouteValidity] {
    override def compare(x: RouteValidity, y: RouteValidity) = x.toString compareTo y.toString
  }

  private def validityClass(validity: RouteValidity) = {
    validity match {
      case Unknown => "label"
      case InvalidAsn => "label warning"
      case InvalidLength => "label warning"
      case Valid => "label notice"
    }
  }

  override def getValuesForRecord(announcement: BgpValidatedAnnouncement) = {
    def reason =
      <table>
        <thead>
          <tr><th>ASN</th><th>Prefix</th><th>Length</th><th>Result</th></tr>
        </thead>
        <tbody>{
          for (prefix <- announcement.valids) yield {
            <tr><td>{ prefix.asn.getValue }</td><td>{ prefix.prefix }</td><td>{ prefix.effectiveMaxPrefixLength }</td><td>VALID</td></tr>
          }
        }{
          for (prefix <- announcement.invalidsAsn) yield {
            <tr><td>{ prefix.asn.getValue }</td><td>{ prefix.prefix }</td><td>{ prefix.effectiveMaxPrefixLength }</td><td>INVALID ASN</td></tr>
          }
        }{
          for (prefix <- announcement.invalidsLength) yield {
            <tr><td>{ prefix.asn.getValue }</td><td>{ prefix.prefix }</td><td>{ prefix.effectiveMaxPrefixLength }</td><td>INVALID LENGTH</td></tr>
          }
        }</tbody>
      </table>
    val validity = if (announcement.validity == Unknown) {
      <span class={ validityClass(announcement.validity) }>{ announcement.validity }</span>
    } else {
      <span class={ validityClass(announcement.validity) } rel="popover" data-content={ Xhtml.toXhtml(reason) } data-original-title="Details">{ announcement.validity }</span>
    }
    List(
      announcement.asn.getValue.toString,
      announcement.prefix.toString,
      Xhtml.toXhtml(validity))
  }

  override def filter(searchCriterium: Any): BgpValidatedAnnouncement => Boolean = {
    searchCriterium match {
      case range: IpRange => _.prefix.overlaps(range)
      case asn: Asn => _.asn == asn
      case searchString: String => announcement =>
          searchString.isEmpty ||
            announcement.asn.toString.contains(searchString) ||
            announcement.prefix.toString.contains(searchString) ||
            announcement.validity.toString.equalsIgnoreCase(searchString) ||
            searchString.equalsIgnoreCase("invalid") && (announcement.validity.equals(InvalidAsn) || announcement.validity.equals(InvalidLength))
    }
  }

  override def ordering(sortColumn: Int) = {
    sortColumn match {
      case 0 => AsnOrdering.on(_.asn)
      case 1 => IpRangeOrdering.on(_.prefix)
      case 2 => RouteValidityOrdering.on(_.validity)
      case _ => sys.error("unknown sort column " + sortColumn)
    }
  }

  override def getAllRecords() = validatedAnnouncements
}
