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

import net.ripe.ipresource.{Asn, IpRange}
import net.ripe.rpki.validator.bgp.preview.BgpAnnouncement
import net.ripe.rpki.validator.models.RtrPrefix
import net.ripe.rpki.validator.support.ValidatorTestCase
import org.junit.runner.RunWith
import org.scalatest.BeforeAndAfter
import org.scalatest.junit.JUnitRunner
import org.scalatra.ScalatraFilter
import org.scalatra.test.scalatest.ScalatraFunSuite

@RunWith(classOf[JUnitRunner])
class BgpPrefixOriginValidationControllerTest extends ValidatorTestCase with ScalatraFunSuite with BeforeAndAfter {

  import scala.language.implicitConversions
  implicit def LongToAsn(asn: Long): Asn = new Asn(asn)
  implicit def StringToAsn(asn: String): Asn = Asn.parse(asn)
  implicit def StringToIpRange(prefix: String): IpRange = IpRange.parse(prefix)
  implicit def TupleToBgpAnnouncement(x: (Int, String)): BgpAnnouncement = BgpAnnouncement(x._1, x._2)
  implicit def TupleToRtrPrefix(x: (Int, String)): RtrPrefix = RtrPrefix(x._1, x._2)
  implicit def TupleToRtrPrefix(x: (Int, String, Int)): RtrPrefix = RtrPrefix(x._1, x._2, Some(x._3))

  private val controller = new ScalatraFilter with BgpPrefixOriginValidationController {
    protected def getVrpObjects: Set[RtrPrefix] = testVrpObjects
  }
  addFilter(controller, "/*")

  private var testVrpObjects: Set[RtrPrefix] = _
  before {
    testVrpObjects = Set.empty
  }

  private val basePath = "/v1/validity"

  test("should reply with 404 for unsupported urls") {
    get(s"$basePath") {
      status should be(404)
    }
    get(s"$basePath/") {
      status should be(404)
    }
    get(s"$basePath/AS65001") {
      status should be(404)
    }
    get(s"$basePath/AS65001/") {
      status should be(404)
    }
    get(s"$basePath/AS65001/10.0.0.0") {
      status should be(404)
    }
    get(s"$basePath/AS65001/10.0.0.0/8/") {
      status should be(404)
    }
    get(s"$basePath/AS65001/10.0.0.0-10.0.0.0") {
      status should be(404)
    }
  }

  test("should return BadRequest in case of malformed AS number") {
    get(s"$basePath/AS65536.0/10.0.0.0/8") {
      status should be(400)
      header("Set-Cookie") should be(null)
      header("Content-Type").toLowerCase() should startWith("text/json")
      header("Content-Type").toLowerCase() should endWith("charset=utf-8")
      body should be("""{
                       |  "message":"'AS65536.0' is not a valid ASN"
                       |}""".stripMargin)
    }
  }

  test("should return BadRequest in case of malformed IP resource") {
    get(s"$basePath/AS65535.0/10.0.0.0/33") {
      status should be(400)
      header("Set-Cookie") should be(null)
      header("Content-Type").toLowerCase() should startWith("text/json")
      header("Content-Type").toLowerCase() should endWith("charset=utf-8")
      body should be("""{
                       |  "message":"'10.0.0.0/33' is not a valid IPv4 or IPv6 prefix"
                       |}""".stripMargin)
    }
    get(s"$basePath/AS65535.0/::/129") {
      status should be(400)
      header("Set-Cookie") should be(null)
      header("Content-Type").toLowerCase() should startWith("text/json")
      header("Content-Type").toLowerCase() should endWith("charset=utf-8")
      body should be("""{
                       |  "message":"'::/129' is not a valid IPv4 or IPv6 prefix"
                       |}""".stripMargin)
    }
  }

  test("validity state should be NotFound if no VRP covers the Route Prefix") {

    testVrpObjects = Set.empty

    get(s"$basePath/AS65001/10.0.0.0/8") {
      status should be(200)
      header("Set-Cookie") should be(null)
      header("Content-Type").toLowerCase() should startWith("text/json")
      header("Content-Type").toLowerCase() should endWith("charset=utf-8")
      body should be("""{
                       |  "validated_route":{
                       |    "route":{
                       |      "origin_asn":"AS65001",
                       |      "prefix":"10.0.0.0/8"
                       |    },
                       |    "validity":{
                       |      "state":"NotFound",
                       |      "description":"No VRP Covers the Route Prefix",
                       |      "VRPs":{
                       |        "matched":[],
                       |        "unmatched_as":[],
                       |        "unmatched_length":[]
                       |      }
                       |    }
                       |  }
                       |}""".stripMargin)
    }
  }

  test("validity state should be Valid if at least one VRP matches the Route Prefix") {

    testVrpObjects = Set((65001, "10.0.0.0/8", 8),(65002, "10.0.0.0/8"),(65003, "10.0.0.0/8"),(65001, "10.0.0.0/8", 20))

    get(s"$basePath/AS65001/10.0.0.0/20") {
      status should be(200)
      header("Set-Cookie") should be(null)
      header("Content-Type").toLowerCase() should startWith("text/json")
      header("Content-Type").toLowerCase() should endWith("charset=utf-8")
      body should be("""{
                       |  "validated_route":{
                       |    "route":{
                       |      "origin_asn":"AS65001",
                       |      "prefix":"10.0.0.0/20"
                       |    },
                       |    "validity":{
                       |      "state":"Valid",
                       |      "description":"At least one VRP Matches the Route Prefix",
                       |      "VRPs":{
                       |        "matched":[{
                       |          "asn":"AS65001",
                       |          "prefix":"10.0.0.0/8",
                       |          "max_length":20
                       |        }],
                       |        "unmatched_as":[{
                       |          "asn":"AS65002",
                       |          "prefix":"10.0.0.0/8",
                       |          "max_length":8
                       |        },{
                       |          "asn":"AS65003",
                       |          "prefix":"10.0.0.0/8",
                       |          "max_length":8
                       |        }],
                       |        "unmatched_length":[{
                       |          "asn":"AS65001",
                       |          "prefix":"10.0.0.0/8",
                       |          "max_length":8
                       |        }]
                       |      }
                       |    }
                       |  }
                       |}""".stripMargin)
    }
  }

  test("validity state should be Invalid (AS) if at least one VRP Covers the Route Prefix, but the Route Origin ASN is not equal to VRP ASN.") {

    testVrpObjects = Set((65002, "10.0.0.0/8"))

    get(s"$basePath/AS65001/10.0.0.0/8") {
      status should be(200)
      header("Set-Cookie") should be(null)
      header("Content-Type").toLowerCase() should startWith("text/json")
      header("Content-Type").toLowerCase() should endWith("charset=utf-8")
      body should be("""{
                       |  "validated_route":{
                       |    "route":{
                       |      "origin_asn":"AS65001",
                       |      "prefix":"10.0.0.0/8"
                       |    },
                       |    "validity":{
                       |      "state":"Invalid",
                       |      "reason":"as",
                       |      "description":"At least one VRP Covers the Route Prefix, but no VRP ASN matches the route origin ASN",
                       |      "VRPs":{
                       |        "matched":[],
                       |        "unmatched_as":[{
                       |          "asn":"AS65002",
                       |          "prefix":"10.0.0.0/8",
                       |          "max_length":8
                       |        }],
                       |        "unmatched_length":[]
                       |      }
                       |    }
                       |  }
                       |}""".stripMargin)
    }
  }

  test("validity state should be Invalid (Length) if at least one VRP Covers the Route Prefix, but the Route prefix length is greater than the VRP maximum length") {

    testVrpObjects = Set((65001, "10.0.0.0/8", 20))

    get(s"$basePath/AS65001/10.0.0.0/24") {
      status should be(200)
      header("Set-Cookie") should be(null)
      header("Content-Type").toLowerCase() should startWith("text/json")
      header("Content-Type").toLowerCase() should endWith("charset=utf-8")
      body should be("""{
                       |  "validated_route":{
                       |    "route":{
                       |      "origin_asn":"AS65001",
                       |      "prefix":"10.0.0.0/24"
                       |    },
                       |    "validity":{
                       |      "state":"Invalid",
                       |      "reason":"length",
                       |      "description":"At least one VRP Covers the Route Prefix, but the Route Prefix length is greater than the maximum length allowed by VRP(s) matching this route origin ASN",
                       |      "VRPs":{
                       |        "matched":[],
                       |        "unmatched_as":[],
                       |        "unmatched_length":[{
                       |          "asn":"AS65001",
                       |          "prefix":"10.0.0.0/8",
                       |          "max_length":20
                       |        }]
                       |      }
                       |    }
                       |  }
                       |}""".stripMargin)
    }
  }
}
