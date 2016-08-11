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
package net.ripe.rpki.validator.config.health

import javax.servlet.http.{HttpServlet, HttpServletRequest, HttpServletResponse}

class HealthServlet extends HttpServlet {

  import net.liftweb.json.Extraction._
  import net.liftweb.json._

  implicit val formats = net.liftweb.json.DefaultFormats

  override def doGet(req: HttpServletRequest, resp: HttpServletResponse) = {

    val statuses = HealthChecks.registry.map { e => (e._1, e._2.check()) }

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

    resp.getWriter.write(compactRender(decompose(statuses)))
  }
}
