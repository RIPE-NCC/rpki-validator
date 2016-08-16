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

import grizzled.slf4j.Logging
import net.ripe.rpki.commons.validation.{ValidationCheck, ValidationMessage, ValidationStatus}

abstract class ValidationDetailsTableData (records: IndexedSeq[ValidatedObjectDetail]) extends DataTableJsonView[ValidatedObjectDetail] with Logging {
  
  override def getAllRecords() = records

  override def filter(searchCriterium: Any): ValidatedObjectDetail => Boolean = {
    searchCriterium match {
      case searchString: String =>
        record => searchString.isEmpty ||
          record.subjectChain.toString.toUpperCase.contains(searchString) ||
          record.isValid.toString.toUpperCase.contains(searchString) ||
          record.check.getStatus.toString.toUpperCase.contains(searchString) ||
          record.message.toUpperCase.contains(searchString) ||
          record.check.getKey.toUpperCase.contains(searchString)

      case _ => _ => true
    }
  }

  override def ordering(sortColumn: Int) = {
    sortColumn match {
      case 0 => implicitly[Ordering[String]].on(_.subjectChain)
      case 1 => implicitly[Ordering[Boolean]].on(_.isValid)
      case 2 => implicitly[Ordering[String]].on(_.check.getKey)
      case 3 => implicitly[Ordering[String]].on(_.message)
      case 4 => implicitly[Ordering[Boolean]].on(_.check.isOk)
      case _ => sys.error("unknown sort column: " + sortColumn)
    }
  }

  override def getValuesForRecord(record: ValidatedObjectDetail) = {
    List(record.subjectChain.toString, record.isValid.toString, record.check.getKey, record.message, record.check.getStatus.toString)
  }
  
}

object AllChecksPassed extends ValidationCheck(ValidationStatus.PASSED, "")

case class ValidatedObjectDetail(subjectChain: String, isValid: Boolean, check: ValidationCheck) {
  lazy val message = if (check == AllChecksPassed) "All checks passed" else ValidationMessage.getMessage(check)
}
