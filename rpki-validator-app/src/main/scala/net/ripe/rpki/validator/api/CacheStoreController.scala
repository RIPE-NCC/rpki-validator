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

import grizzled.slf4j.Logging
import net.liftweb.json._
import net.ripe.rpki.validator.models.validation.{RepositoryObject, _}
import org.scalatra.{Ok, ScalatraBase}

import scala.collection.JavaConversions._


trait CacheStoreController extends ScalatraBase with Hashing with Logging {
  import net.liftweb.json.JsonDSL._

  protected def getCachedObjects: Seq[RepositoryObject.ROType]

  get("/v1/store/view") {
    contentType = "text/json;charset=utf-8"
    response.addHeader("Cache-Control", "no-cache,no-store")

    logger.info("Getting cached objects")
    val cachedObjects = getCachedObjects

    def common(o: RepositoryObject.ROType) = {
      val js = ("url" -> o.url.toString) ~
        ("hash" -> stringify(o.hash)) ~
        ("aki" -> stringify(o.aki))

      o.validationTime.map(t => js ~ ("validation_time" -> t.toString)).getOrElse(js)
    }

    logger.info("Started creating JSON")
    val js = cachedObjects.par.map {
      case c: CertificateObject =>
        ("type" -> "cer") ~ common(c)

      case r: RoaObject =>
        ("type" -> "roa") ~ common(r)

      case m: ManifestObject =>
        ("type" -> "mft") ~ common(m) ~ ("files" -> m.decoded.getHashes.map { e =>
          e._1 -> stringify(e._2)
        })

      case c: CrlObject =>
        ("type" -> "crl") ~ common(c)

      case g: GhostbustersObject =>
        ("type" -> "gbr") ~ common(g)
    }.seq

    logger.info("Finished creating JSON")

    val result = Ok(body = pretty(render(js)))

    logger.info("Finished rendering JSON")
    result
  }


}