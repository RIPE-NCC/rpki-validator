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

import lib.DataTablesBacking
import lib.NumberResources._
import bgp.preview.ValidatedAnnouncement
import net.ripe.ipresource.IpRange
import net.ripe.ipresource.Asn

abstract class BgpPreviewTableData(validatedAnnouncements: IndexedSeq[ValidatedAnnouncement]) extends DataTablesBacking[ValidatedAnnouncement] {

  override def getValuesForRecord(record: ValidatedAnnouncement) = {
    record match {
      case announcement: ValidatedAnnouncement => List(announcement.asn.getValue().toString(), announcement.prefix.toString(), announcement.validity.toString())
    }
  }

  override def filterRecords(inputRecords: IndexedSeq[ValidatedAnnouncement], searchCriterium: Any): IndexedSeq[ValidatedAnnouncement] = {
    searchCriterium match {
      case range: IpRange => filterByIpRange(inputRecords, range)
      case asn: Asn => filterByAsn(inputRecords, asn)
      case searchString: String => filterByString(inputRecords, searchString)
    }
  }

  override def sortRecords(inputRecords: IndexedSeq[ValidatedAnnouncement], sortColumn: Int) = {
    sortColumn match {
      case 0 => inputRecords.sortBy(_.asn)
      case 1 => inputRecords.sortBy(_.prefix)
      case 2 => inputRecords.sortBy(_.validity)
      case _ => inputRecords
    }
  }

  override def getAllRecords() = validatedAnnouncements

  private def filterByIpRange(inputRecords: IndexedSeq[ValidatedAnnouncement], range: IpRange) = {
    inputRecords.filter {
      announcement => announcement.prefix.overlaps(range)
    }
  }

  private def filterByAsn(inputRecords: IndexedSeq[ValidatedAnnouncement], asn: Asn) = {
    inputRecords.filter {
      announcement => announcement.asn.equals(asn)
    }
  }

  private def filterByString(inputRecords: IndexedSeq[ValidatedAnnouncement], sSearch: String) = {
    inputRecords.filter {
      announcement =>
        {
          sSearch.isEmpty || announcement.asn.toString.contains(sSearch) || announcement.prefix.toString.contains(sSearch) || announcement.validity.toString.equals(sSearch)
        }
    }
  }
  
}