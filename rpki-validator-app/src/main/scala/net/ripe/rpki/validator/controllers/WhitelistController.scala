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

import net.ripe.ipresource.Asn
import net.ripe.ipresource.IpRange
import org.scalatra.ScalatraKernel
import org.scalatra.MethodOverride
import scalaz._
import Scalaz._

import lib.Validation._
import models._
import views.WhitelistView

trait WhitelistController extends ScalatraKernel with MethodOverride {
  def whitelist: Whitelist
  def addWhitelistEntry(entry: WhitelistEntry): Unit
  def removeWhitelistEntry(entry: WhitelistEntry): Unit
  def entryExists(entry: WhitelistEntry): Boolean = whitelist.entries.contains(entry)

  get("/whitelist") {
    new WhitelistView(whitelist)
  }

  post("/whitelist") {
    submittedEntry match {
      case Success(entry) =>
        if (entryExists(entry))
          new WhitelistView(whitelist, params, Seq(ErrorMessage("entry already exists in the whitelist")))
        else {
          addWhitelistEntry(entry)
          redirect("/whitelist")
        }
      case Failure(errors) =>
        new WhitelistView(whitelist, params, errors.head :: errors.tail)
    }
  }

  delete("/whitelist") {
    submittedEntry match {
      case Success(entry) =>
        if (entryExists(entry)) {
          removeWhitelistEntry(entry)
          redirect("/whitelist")
        } else {
          new WhitelistView(whitelist, params, Seq(ErrorMessage("entry no longer exists in the whitelist")))
        }
      case Failure(errors) => // go away hacker!
        new WhitelistView(whitelist, params, errors.head :: errors.tail)
    }
  }

  private def submittedEntry: ValidationNEL[ErrorMessage, WhitelistEntry] = {
    val asn = validateParameter("asn", required(parseAsn))
    val prefix = validateParameter("prefix", required(parseIpPrefix))
    val maxPrefixLength = validateParameter("maxPrefixLength", optional(parseInt))

    (asn |@| prefix |@| maxPrefixLength).apply(WhitelistEntry.validate).flatMap(identity)
  }

  private def validateParameter[A](name: String, f: Option[String] => Validation[String, A]): ValidationNEL[ErrorMessage, A] =
    f(params.get(name).filterNot(_.isEmpty)).fail.map(message => ErrorMessage(message, Some(name))).validation.liftFailNel

}
