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

import net.liftweb.json._
import net.ripe.ipresource.{IpAddress, IpRange, IpResourceType}
import net.ripe.rpki.commons.validation.roa.AllowedRoute
import net.ripe.rpki.validator.models.RtrPrefix
import net.ripe.rpki.validator.views.ExportView
import org.joda.time.DateTime
import org.joda.time.format.ISODateTimeFormat

trait ExportController extends ApplicationController {

  protected def getRtrPrefixes: Seq[RtrPrefix]

  get("/export") {
    new ExportView()
  }

  get("/export.csv") {
    val Header = "ASN,IP Prefix,Max Length,Trust Anchor\n"
    contentType = "text/csv"
    response.addHeader("Pragma", "public")
    response.addHeader("Cache-Control", "no-cache")

    val writer = response.getWriter
    writer.write(Header)
    getRtrPrefixes.foreach {
      rtr => writer.write(s"${rtr.asn},${rtr.prefix},${rtr.maxPrefixLength.getOrElse(rtr.prefix.getPrefixLength)},${rtr.getCaName}\n")
    }
  }

  get("/export.json") {
    import net.liftweb.json.JsonDSL._

    contentType = "text/json"
    response.addHeader("Pragma", "public")
    response.addHeader("Cache-Control", "no-cache")

    val roas = getRtrPrefixes.map(rtr =>
      ("asn" -> rtr.asn.toString) ~
        ("prefix" -> rtr.prefix.toString) ~
        ("maxLength" -> rtr.maxPrefixLength.getOrElse(rtr.prefix.getPrefixLength)) ~
        ("ta" -> rtr.getCaName)
    )
    response.getWriter.write(compactRender("roas" -> roas))
  }

  get("/export.rpsl") {

    contentType = "text/plain"
    response.addHeader("Pragma", "public")
    response.addHeader("Cache-Control", "no-cache")

    val writer = response.getWriter
    getRtrPrefixes.foreach { rtr =>

      val caName = if(rtr.trustAnchorLocator.isEmpty) "UNKNOWN" else rtr.trustAnchorLocator.get.getCaName.replace(' ', '-').toUpperCase
      val dateTime = ISODateTimeFormat.dateTimeNoMillis().withZoneUTC().print(DateTime.now)

      val maximumLengthForExport = getMaximumLengthForExport(rtr.prefix.getPrefixLength, rtr.maxPrefixLength)
      val allowedRoute = new AllowedRoute(rtr.asn, rtr.prefix, maximumLengthForExport)

      forAllRanges(allowedRoute.getPrefix, allowedRoute.getMaximumLength) { range: IpRange =>
        val version = if(IpResourceType.IPv6 == range.getType) "6" else ""

        writer.write(s"""
                   |route$version: $range
                   |origin: ${allowedRoute.getAsn}
                   |descr: exported from ripe ncc validator
                   |mnt-by: NA
                   |created: $dateTime
                   |last-modified: $dateTime
                   |source: ROA-$caName
                   |""".stripMargin)

      }
    }
  }

  private val prefixDelta = 8

  private def getMaximumLengthForExport(prefixLength: Int, maxPrefixLength: Option[Int]) = {
    Math.min(maxPrefixLength.getOrElse(prefixLength), prefixLength + prefixDelta)
  }

  private def forAllRanges(prefix: IpRange, maxPrefixLength: Int)(printRange: IpRange => Unit) {
    import scala.collection.JavaConversions._
    val ips = prefix.splitToPrefixes().map(_.getStart)

    ips.foreach { ip =>
      walkAllRanges(ip.lowerBoundForPrefix(prefix.getPrefixLength), prefix.getPrefixLength, maxPrefixLength, printRange)
    }
  }

  private def walkAllRanges(ip: IpAddress, prefixLength: Int, maxPrefixLength:Int, printRange: IpRange => Unit) {
    val lower = ip.lowerBoundForPrefix(prefixLength)
    val upper = ip.upperBoundForPrefix(prefixLength)

    printRange(IpRange.range(lower, upper))

    if(prefixLength < maxPrefixLength) {
      walkAllRanges(lower, prefixLength + 1, maxPrefixLength, printRange)
      walkAllRanges(upper, prefixLength + 1, maxPrefixLength, printRange)
    }
  }

}
