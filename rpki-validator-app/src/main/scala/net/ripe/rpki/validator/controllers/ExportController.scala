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

import net.ripe.ipresource._
import net.ripe.rpki.commons.validation.roa.AllowedRoute
import org.joda.time.DateTime
import org.joda.time.format.ISODateTimeFormat
import views.ExportView
import models.RtrPrefix
import net.liftweb.json._

trait ExportController extends ApplicationController {

  protected def getRtrPrefixes: Set[RtrPrefix]

  get("/export") {
    new ExportView()
  }

  get("/export.csv") {
    val Header = "ASN,IP Prefix,Max Length\n"
    val RowFormat = "%s,%s,%s\n"

    contentType = "text/csv"
    response.addHeader("Pragma", "public")
    response.addHeader("Cache-Control", "no-cache")

    val roas = getRtrPrefixes.map(rtr => {
      RowFormat.format(rtr.asn, rtr.prefix, rtr.maxPrefixLength.getOrElse(rtr.prefix.getPrefixLength))
    })
    response.getWriter.write(Header + roas.mkString)
  }

  get("/export.json") {
    import net.liftweb.json.JsonDSL._

    contentType = "text/json"
    response.addHeader("Pragma", "public")
    response.addHeader("Cache-Control", "no-cache")

    val roas = getRtrPrefixes.map(rtr =>
      ("asn" -> rtr.asn.toString) ~
        ("prefix" -> rtr.prefix.toString) ~
        ("maxLength" -> rtr.maxPrefixLength.getOrElse(rtr.prefix.getPrefixLength))
    )
    response.getWriter.write(compact(render(("roas" -> roas))))
  }

  get("/export.rpsl") {

    contentType = "text/plain"
    response.addHeader("Pragma", "public")
    response.addHeader("Cache-Control", "no-cache")

    val routes = new StringBuilder
    getRtrPrefixes.map { rtr =>

      val caName = if(rtr.trustAnchorLocator.isEmpty) "unknown" else rtr.trustAnchorLocator.get.getCaName
      val dateTime = ISODateTimeFormat.dateTimeNoMillis().withZoneUTC().print(DateTime.now)

      val allowedRoute = new AllowedRoute(rtr.asn, rtr.prefix, rtr.maxPrefixLength.getOrElse(rtr.prefix.getPrefixLength))
      val possibleRoutes = getAllRoutesFor(allowedRoute.getPrefix, allowedRoute.getMaximumLength)

      possibleRoutes.foreach { range =>
        val version = if(IpResourceType.IPv6 == range.getType) "6" else ""

        routes ++= s"""
                   |route$version: $range
                   |origin: ${allowedRoute.getAsn}
                   |descr: exported from ripe ncc validator
                   |mnt-by: N/A
                   |created: $dateTime
                   |last-modified: $dateTime
                   |source: $caName
                   |"""
      }

    }
    response.getWriter.write(routes.stripMargin)
  }


  def getAllRoutesFor(prefix: IpRange, maxPrefixLength: Int) = {
    import scala.collection.JavaConversions._
    val ips = prefix.splitToPrefixes().map(_.getStart)

    ips.flatMap { ip =>
      getAllRangesFor(ip.lowerBoundForPrefix(prefix.getPrefixLength), prefix.getPrefixLength, maxPrefixLength)
    }
  }


  def getAllRangesFor(ip: IpAddress, prefixLength: Int, maxPrefixLength:Int): Seq[IpRange] = {
    val lower = ip.lowerBoundForPrefix(prefixLength)
    val upper = ip.upperBoundForPrefix(prefixLength)

    val route = IpRange.range(lower, upper)

    if(prefixLength < maxPrefixLength) {
      Seq.concat(
        Seq(route),
        getAllRangesFor(lower, prefixLength + 1, maxPrefixLength),
        getAllRangesFor(upper, prefixLength + 1, maxPrefixLength)
      )
    } else {
      Seq(route)
    }
  }

}
