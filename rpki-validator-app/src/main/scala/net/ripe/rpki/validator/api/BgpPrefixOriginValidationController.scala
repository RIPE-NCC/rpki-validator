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
package net.ripe.rpki.validator.api

import net.ripe.rpki.validator.models.RtrPrefix
import scalaz.Validation
import org.scalatra.{ScalatraBase, Ok, BadRequest}
import net.liftweb.json._
import net.ripe.rpki.validator.lib.Validation._
import net.ripe.rpki.validator.bgp.preview.{BgpAnnouncement, BgpAnnouncementValidator}
import net.ripe.rpki.validator.models.RouteValidity._


trait BgpPrefixOriginValidationController extends ScalatraBase {
  import net.liftweb.json.JsonDSL._

  protected def getVrpObjects: Seq[RtrPrefix]

  get("/v1/validity/:asn/:prefix/:length") {
    contentType = "text/json;charset=UTF-8"
    response.addHeader("Cache-Control", "no-cache,no-store")

    val asn = parseAsn(params("asn")).orHalt
    val prefix = parseIpPrefix(s"${params("prefix")}/${params("length")}").orHalt

    val announcement = BgpAnnouncementValidator.validate(BgpAnnouncement(asn, prefix), getVrpObjects)

    Ok(body = pretty(render(
      "validated_route" ->
        ("route" ->
          ("origin_asn" -> announcement.asn.toString) ~ ("prefix" -> announcement.prefix.toString)) ~
        ("validity" ->
          convert(announcement.validity) ~
          ("VRPs" ->
            ("matched" -> convert(announcement.valids)) ~
            ("unmatched_as" -> convert(announcement.invalidsAsn)) ~
            ("unmatched_length" -> convert(announcement.invalidsLength)))))
    ))
  }

  private def convert(value: RouteValidity) = {
    value match {
      case Valid => ("state" -> "Valid") ~ ("description" -> "At least one VRP Matches the Route Prefix")
      case InvalidAsn => ("state" -> "Invalid") ~ ("reason" -> "as") ~ ("description" -> "At least one VRP Covers the Route Prefix, but no VRP ASN matches the route origin ASN")
      case InvalidLength => ("state" -> "Invalid") ~ ("reason" -> "length") ~ ("description" -> "At least one VRP Covers the Route Prefix, but the Route Prefix length is greater than the maximum length allowed by VRP(s) matching this route origin ASN")
      case Unknown => ("state" -> "NotFound") ~ ("description" -> "No VRP Covers the Route Prefix")
    }
  }

  private def convert(vrpObjects: Seq[RtrPrefix]) = vrpObjects.map(vrp =>
    ("asn" -> vrp.asn.toString) ~ ("prefix" -> vrp.prefix.toString) ~ ("max_length" -> vrp.maxPrefixLength.getOrElse(vrp.prefix.getPrefixLength))
  )

  private implicit class ValidationOps[A](validation: Validation[String, A]) {
    def orHalt = validation.fold(error => {
      halt(BadRequest(
        body = response.getWriter.write(pretty(render("message" -> error)))
      ))
    })
  }
}