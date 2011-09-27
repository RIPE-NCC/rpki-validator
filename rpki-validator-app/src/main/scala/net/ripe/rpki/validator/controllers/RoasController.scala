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

import scala.collection.JavaConverters._
import org.joda.time.DateTimeZone
import org.joda.time.format.DateTimeFormat
import models.Roas
import views.RoasView

trait RoasController extends ApplicationController {
  def roas: Roas

  get("/roas") {
    new RoasView(roas)
  }
  get("/roas.csv") {
    val dateFormatter = DateTimeFormat.forPattern("YYYY-MM-dd HH:mm:ss").withZone(DateTimeZone.UTC)
    val Header = "URI,ASN,IP Prefix,Max Length,Not Before (UTC),Not After (UTC)\n"
    val RowFormat = "\"%s\",%s,%s,%s,%s,%s\n"

    contentType = "text/csv"
    response.addHeader("Content-Disposition", "attachment; filename=roas.csv")
    response.addHeader("Pragma", "public")
    response.addHeader("Cache-Control", "no-cache")

    val writer = response.getWriter()
    writer.print(Header)
    for {
      (_, validatedRoas) <- roas.all if validatedRoas.isDefined
      validatedRoa <- validatedRoas.get.sortBy(_.roa.getAsn().getValue())
      roa = validatedRoa.roa
      prefix <- roa.getPrefixes().asScala
    } {
      writer.print(RowFormat.format(
        validatedRoa.uri,
        roa.getAsn(),
        prefix.getPrefix(),
        Option(prefix.getMaximumLength()).getOrElse(""),
        dateFormatter.print(roa.getNotValidBefore()),
        dateFormatter.print(roa.getNotValidAfter())))
    }
    
    ()
  }
}
