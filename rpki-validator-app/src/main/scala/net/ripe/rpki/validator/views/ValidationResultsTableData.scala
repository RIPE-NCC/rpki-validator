package net.ripe.rpki.validator.views

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

import java.net.URI
import grizzled.slf4j.Logging
import net.ripe.rpki.commons.validation.{ ValidationStatus, ValidationMessage, ValidationCheck }

abstract class ValidationResultsTableData(records: IndexedSeq[ValidatedObjectResult]) extends DataTableJsonView[ValidatedObjectResult] with Logging {

  override def getAllRecords() = records

  override def filter(searchCriterium: Any): ValidatedObjectResult => Boolean = {
    val searchString = searchCriterium.toString

    record => searchString.isEmpty ||
      record.trustAnchorName.toUpperCase.contains(searchString) ||
      record.subjectChain.toString.toUpperCase.contains(searchString) ||
      record.validationStatus.toString.toUpperCase.contains(searchString) ||
      record.messages.contains(searchString)
  }

  override def ordering(sortColumn: Int) = {
    sortColumn match {
      case 0 => implicitly[Ordering[String]].on(_.subjectChain)
      case 1 => implicitly[Ordering[ValidationStatus]].on(_.validationStatus)
      case 2 => implicitly[Ordering[String]].on(_.messages)
      case _ => sys.error("unknown sort column: " + sortColumn)
    }
  }

  override def getValuesForRecord(record: ValidatedObjectResult) = {
    List(
      <span rel="twipsy" data-original-title={record.subjectChain}>
        <b>Certificate chain:</b> {record.subjectChain}
        <br/>
        <b>URI:</b>&nbsp;{record.uri.toString}
      </span>.toString(),
      record.validationStatus.toString,
      record.messages
    )
  }

}

abstract class FetchResultsTableData(records: IndexedSeq[ValidatedObjectResult]) extends ValidationResultsTableData(records){
  override def getValuesForRecord(record: ValidatedObjectResult) = {
    List(
      <span rel="twipsy" data-original-title={record.subjectChain}>
        <b>Certificate chain:</b> {record.subjectChain}
        <br/>
        <b>URI:</b>&nbsp;{record.uri.toString}
      </span>.toString(),
      record.messages
    )
  }


  override def ordering(sortColumn: Int) = {
    sortColumn match {
      case 0 => implicitly[Ordering[String]].on(_.subjectChain)
      case 1 => implicitly[Ordering[String]].on(_.messages)
      case _ => sys.error("unknown sort column: " + sortColumn)
    }
  }

}

case class ValidatedObjectResult(trustAnchorName: String, subjectChain: String, uri: URI, validationStatus: ValidationStatus, checks: Set[ValidationCheck]) {
  lazy val messages = checks.map(ValidationMessage.getMessage).mkString("<br/>\n")
}
