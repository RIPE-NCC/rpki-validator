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
package controllers

import net.liftweb.json._
import net.ripe.commons.certification.validation.roa.RouteValidityState
import lib.NumberResources._
import bgp.preview.ValidatedAnnouncement
import views.BgpPreviewView
import net.ripe.ipresource.IpRange
import net.ripe.ipresource.Asn

trait BgpPreviewController extends ApplicationController {

  protected def validatedAnnouncements: IndexedSeq[ValidatedAnnouncement]

  private def baseUrl = views.Tabs.BgpPreviewTab.url

  get(baseUrl) {
    new BgpPreviewView()
  }

  get("/bgp-preview-data") {
    val iDisplayStart = params("iDisplayStart").toInt
    val iDisplayLength = params("iDisplayLength").toInt
    val sSearch = params("sSearch").toUpperCase()
    val allRecords = validatedAnnouncements

    val filteredRecords = filterRecords(allRecords, sSearch)

    val sortedRecords = params("iSortCol_0") match {
      case "0" => filteredRecords.sortBy(_.asn)
      case "1" => filteredRecords.sortBy(_.prefix)
      case "2" => filteredRecords.sortBy(_.validity)
      case _ => filteredRecords
    }
    val orderedRecords = params("sSortDir_0") match {
      case "desc" => sortedRecords.reverse
      case _ => sortedRecords
    }
    val displayRecords = orderedRecords.drop(iDisplayStart).take(iDisplayLength)

    compact(render(JObject(List(
      JField("sEcho", JInt(params("sEcho").toInt)),
      JField("iTotalRecords", JInt(allRecords.size)),
      JField("iTotalDisplayRecords", JInt(filteredRecords.size)),
      JField("aaData", JArray(displayRecords.map { announcement =>
        JArray(List(JString(announcement.asn.getValue().toString()), JString(announcement.prefix.toString()), JString(announcement.validity.toString())))
      }.toList))))))
  }

  def filterRecords(inputRecords: IndexedSeq[ValidatedAnnouncement], sSearch: String): IndexedSeq[ValidatedAnnouncement] = {

    parseAsPrefix(sSearch) match {
      case range: IpRange => filterByIpRange(inputRecords, range)
      case asn: Asn => filterByAsn(inputRecords, asn)
      case _ => filterByString(inputRecords, sSearch)
    }

  }

  def filterByIpRange(inputRecords: IndexedSeq[ValidatedAnnouncement], range: IpRange) = {
    inputRecords.filter {
      announcement => announcement.prefix.overlaps(range)
    }
  }
  
  def filterByAsn(inputRecords: IndexedSeq[ValidatedAnnouncement], asn: Asn) = {
      inputRecords.filter {
          announcement => announcement.asn.equals(asn)
      }
  }

  def filterByString(inputRecords: IndexedSeq[ValidatedAnnouncement], sSearch: String) = {
    inputRecords.filter {
      announcement =>
        {
          sSearch.isEmpty || announcement.asn.toString.contains(sSearch) || announcement.prefix.toString.contains(sSearch) || announcement.validity.toString.equals(sSearch)
        }
    }
  }

  def parseAsPrefix(input: String): Any = {
    try {
      IpRange.parse(input)
    } catch {
      case _ => try {
        if(input.toLowerCase().startsWith("as")) {
            Asn.parse(input)
        } else {
          None
        }
      } catch {
        case _ => None
      }
    }
  }

}
