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
package controllers

import models._
import grizzled.slf4j.Logging
import views._
import net.ripe.rpki.commons.validation.{ValidationString, ValidationCheck, ValidationStatus}

trait ValidatedObjectsController extends ApplicationController with Logging {
  protected def validatedObjects: ValidatedObjects

  get("/roas") {
    new RoasView(validatedObjects, params.getOrElse("q", ""))
  }

  get("/roas-data") {
    new RoaTableData(validatedObjects) {
      override def getParam(name: String) = params(name)
    }
  }

  get("/validation-details") {
    new ValidationDetailsView()
  }

  get("/validation-details-data") {
    new ValidationDetailsTableData(getValidationDetails) {
      override def getParam(name: String) = params(name)
    }
  }

  get("/validation-details.csv") {

    contentType = "text/csv"
    response.addHeader("Content-Disposition", "attachment; filename=validation-details-data.csv")
    response.addHeader("Pragma", "public")
    response.addHeader("Cache-Control", "no-cache")

    val Header = "URI, Object Validity, Check, Check Validity\n"
    val writer = response.getWriter
    writer.print(Header)

    val records = getValidationDetails

    records.foreach { r =>
      writer.print(s""""${r.subjectChain}",${r.isValid},${r.check.getKey},${r.check.isOk}\n""")
    }
  }

  def getValidationResults = {
    val records = for {
      (trustAnchorLocator, taValidation) <- validatedObjects.all.par
      validatedObject <- taValidation.validatedObjects.filterNot(_.validationStatus == ValidationStatus.PASSED)
    } yield {
      ValidatedObjectResult(trustAnchorLocator.getCaName,
        validatedObject.subjectChain,
        validatedObject.uri,
        validatedObject.validationStatus,
        validatedObject.checks.filterNot(_.getStatus == ValidationStatus.PASSED))
    }
    records.seq.toIndexedSeq
  }


  def getValidationDetails = {
    val records = for {
      taValidation <- validatedObjects.all.values.par
      validatedObject <- taValidation.validatedObjects
      check <- if (validatedObject.checks.isEmpty) Seq(AllChecksPassed) else validatedObject.checks
    } yield {
      ValidatedObjectDetail(validatedObject.subjectChain, validatedObject.isValid, check)
    }
    records.seq.toIndexedSeq
  }
}
