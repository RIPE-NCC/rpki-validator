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

import net.liftweb.json._
import lib.Validation._

trait DataTableJsonView[R <: Any] {

  protected def getParam(name: String): String
  protected def getAllRecords(): IndexedSeq[R]
  protected def filter(searchCriterium: Any): R => Boolean
  protected def ordering(sortColumn: Int): Ordering[R]
  protected def getValuesForRecord(record: R): List[String]

  private val iDisplayStart = getParam("iDisplayStart").toInt
  private val iDisplayLength = getParam("iDisplayLength").toInt
  private val sSearch = getParam("sSearch").trim().toUpperCase

  private val sortCol = getParam("iSortCol_0").toInt
  private val sortOrder = getParam("sSortDir_0")

  private def searchCriterium = parseIpRange(sSearch).toOption orElse parseAsn(sSearch).toOption getOrElse sSearch

  def renderJson: String = {
    val allRecords = getAllRecords()
    val filteredRecords = filterRecords(allRecords, searchCriterium)
    val sortedRecords = sortRecords(filteredRecords, sortCol)
    val displayRecords = paginate(sortedRecords)

    compactRender(JObject(List(
      JField("sEcho", JInt(getParam("sEcho").toInt)),
      JField("iTotalRecords", JInt(allRecords.size)),
      JField("iTotalDisplayRecords", JInt(filteredRecords.size)),
      JField("aaData", makeJArray(displayRecords)))))
  }

  private def paginate(records: IndexedSeq[R]) =
    records.slice(iDisplayStart, iDisplayStart + iDisplayLength)

  private def makeJArray(records: IndexedSeq[R]): JArray =
    JArray(records.par.map { record =>
      JArray(makeJStringListForRecord(record))
    }.toList)

  private def makeJStringListForRecord(record: R): List[JValue] =
    getValuesForRecord(record).map(JString(_))

  private[views] def filterRecords(allRecords: IndexedSeq[R], searchCriterium: Any) = {
    allRecords.par.filter(filter(searchCriterium)).toIndexedSeq
  }

  private[views] def sortRecords(filteredRecords: IndexedSeq[R], sortColumn: Int) = {
    filteredRecords.sorted(order(ordering(sortColumn)))
  }

  private def order(ordering: Ordering[R]) = sortOrder match {
    case "desc" => ordering.reverse
    case _      => ordering
  }
}
