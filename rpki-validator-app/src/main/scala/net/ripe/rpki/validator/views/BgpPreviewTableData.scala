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
package views

import lib.NumberResources._
import bgp.preview.ValidatedAnnouncement
import net.ripe.ipresource.IpRange
import net.ripe.ipresource.Asn
import net.ripe.commons.certification.validation.roa.RouteValidityState
import scala.xml.NodeSeq

abstract class BgpPreviewTableData(validatedAnnouncements: IndexedSeq[ValidatedAnnouncement]) extends DataTableJsonView[ValidatedAnnouncement] {

  private object RouteValidityStateOrdering extends Ordering[RouteValidityState] {
    override def compare(x: RouteValidityState, y: RouteValidityState) = x.toString compareTo y.toString
  }
  private def validityClass(validity: RouteValidityState) = validity match {
    case RouteValidityState.UNKNOWN => "label"
    case RouteValidityState.INVALID => "label warning"
    case RouteValidityState.VALID => "label notice"
  }
  
  override def getValuesForRecord(record: ValidatedAnnouncement) = {
    record match {
      case announcement: ValidatedAnnouncement =>
        def reason =
          <table>
            <thead>
              <tr><th>ASN</th><th>Prefix</th><th>Length</th><th>Result</th></tr>
            </thead>
            <tbody>{
              for (prefix <- announcement.validates) yield {
                <tr><td>{ prefix.asn.getValue() }</td><td>{ prefix.prefix }</td><td>{ prefix.effectiveMaxPrefixLength }</td><td>VALID</td></tr>
              }
            }{
              for (prefix <- announcement.invalidates) yield {
                <tr><td>{ prefix.asn.getValue() }</td><td>{ prefix.prefix }</td><td>{ prefix.effectiveMaxPrefixLength }</td><td>INVALID</td></tr>
              }
            }</tbody>
          </table>
        val validity = if (announcement.validity == RouteValidityState.UNKNOWN) {
          <span class={ validityClass(announcement.validity) }>{ announcement.validity }</span>
        } else {
          <span class={ validityClass(announcement.validity) } rel="popover" data-content={ reason.toString } data-original-title="Details">{ announcement.validity }</span>
        }
        List(
          announcement.asn.getValue().toString(),
          announcement.prefix.toString(),
          validity.toString())
    }
  }

  override def filter(searchCriterium: Any): ValidatedAnnouncement => Boolean = searchCriterium match {
    case range: IpRange => (record => record.prefix.overlaps(range))
    case asn: Asn => (record => record.asn == asn)
    case searchString: String => 
      (record => 
        searchString.isEmpty ||
        record.asn.toString.contains(searchString) ||
        record.prefix.toString.contains(searchString) ||
        record.validity.toString.equals(searchString))
  }
  
  override def ordering(sortColumn: Int) = {
    sortColumn match {
      case 0 => AsnOrdering.on(_.asn)
      case 1 => IpRangeOrdering.on(_.prefix)
      case 2 => RouteValidityStateOrdering.on(_.validity)
      case _ => sys.error("unknown sort column " + sortColumn)
    }
  }

  override def getAllRecords() = validatedAnnouncements
}
