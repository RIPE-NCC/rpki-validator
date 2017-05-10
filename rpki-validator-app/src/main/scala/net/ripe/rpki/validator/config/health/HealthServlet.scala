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
/**
  * The BSD License
  *
  * Copyright (c) 2010-2012 RIPE NCC
  * All rights reserved.
  *
  * Redistribution and use in source and binary forms, with or without
  * modification, are permitted provided that the following conditions are met:
  *   - Redistributions of source code must retain the above copyright notice,
  * this list of conditions and the following disclaimer.
  *   - Redistributions in binary form must reproduce the above copyright notice,
  * this list of conditions and the following disclaimer in the documentation
  * and/or other materials provided with the distribution.
  *   - Neither the name of the RIPE NCC nor the names of its contributors may be
  * used to endorse or promote products derived from this software without
  * specific prior written permission.
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
package net.ripe.rpki.validator.config.health

import javax.servlet.http.{HttpServlet, HttpServletRequest, HttpServletResponse}

import net.ripe.rpki.commons.rsync.Rsync
import net.ripe.rpki.commons.validation.ValidationStatus
import net.ripe.rpki.validator.config.ApplicationOptions
import net.ripe.rpki.validator.models.{TrustAnchors, ValidatedObjects}
import org.joda.time.{DateTime, Instant}

import scala.collection.immutable

object Code extends Enumeration {
  type Code = Value
  val OK = Value("OK")
  val WARNING = Value("WARNING")
  val ERROR = Value("ERROR")
}

case class Status(code: Code.Code, message: Option[String])

object Status {
  def ok = Status(Code.OK, None)

  def ok(message: String) = Status(Code.OK, Some(message))

  def warning(message: String) = Status(Code.WARNING, Some(message))

  def error(message: String) = Status(Code.ERROR, Some(message))
}


abstract class HealthServlet extends HttpServlet {

  import net.liftweb.json.Extraction._
  import net.liftweb.json._

  implicit val formats = net.liftweb.json.DefaultFormats

  protected def getValidatedObjects: ValidatedObjects

  protected def getTrustAnchors: TrustAnchors

  override def doGet(req: HttpServletRequest, resp: HttpServletResponse): Unit = {
    val statuses =
      Health.getTasStatus(getValidatedObjects) ++ Map(
        "rsync" ->
          Health.rsyncHealthCheck(),
        "last-validation" ->
          Health.getValidationTimeStatus(getTrustAnchors.all.filter(_.enabled).map(_.lastUpdated)),
        "memory" ->
          Health.jvmMemoryCheck
      )

    def setProperResponse(problem: Code.Code, status: Int) = {
      val brokenMessages = statuses.collect {
        case (name, Status(code, Some(message))) if code == problem => s"$name : $message"
        case (name, Status(code, None)) if code == problem => s"$name is broken"
      }
      if (brokenMessages.nonEmpty)
        resp.setHeader("X-NCC-ERROR", brokenMessages.mkString(", "))
      resp.setStatus(status)
    }

    if (statuses.exists(_._2.code == Code.ERROR))
      setProperResponse(Code.ERROR, 500)
    else if (statuses.exists(_._2.code == Code.WARNING))
      setProperResponse(Code.WARNING, 299)

    val formatted = statuses.mapValues(s => Map("code" -> s.code.toString, "message" -> s.message))
    resp.getWriter.write(compactRender(decompose(formatted)))
  }


}
