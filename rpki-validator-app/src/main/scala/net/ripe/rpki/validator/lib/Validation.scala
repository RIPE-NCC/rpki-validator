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
package net.ripe.rpki.validator.lib

import scalaz._
import Scalaz._
import net.ripe.ipresource.Asn
import net.ripe.ipresource.IpRange

object Validation {

  /**
   * Automatically convert a NonEmptyList to a normal List.
   */
  implicit def NonEmptyListToSeq[A](nel: NonEmptyList[A]): List[A] = nel.head :: nel.tail

  case class ErrorMessage(message: String, fieldName: Option[String] = None)

  def liftFailErrorMessage[A](validation: Validation[String, A], fieldName: Option[String] = None): ValidationNEL[ErrorMessage, A] =
    validation.fail.map(failure => ErrorMessage(failure, fieldName)).liftNel

  /**
   * Makes a validator handle optional input values by generating an error message.
   */
  def required[A, E, B](validator: A => Validation[E, B], error: E = "required"): Option[A] => Validation[E, B] = {
    case None => error.fail
    case Some(value) => validator(value)
  }

  /**
   * Makes a validator handle optional values by passing through [[scala.None]] when no value is provided.
   */
  def optional[A, E, B](validator: A => Validation[E, B]): Option[A] => Validation[E, Option[B]] = {
    case None => none.success
    case Some(value) => validator(value).map(some)
  }

  /**
   * Makes a validator handle optional values by passing through a default when no value is provided. Usage:
   *
   * {{
   *   default(parseInt, -1)(Some("3")) => 3
   *   default(parseInt, -1)(None)      => -1
   * }}
   */
  def default[A, E, B](validator: A => Validation[E, B], default: B): Option[A] => Validation[E, B] = {
    case None => default.success
    case Some(value) => validator(value)
  }

  def collapseWhitespace(s: String): Validation[Nothing, String] = s.replaceAll("\\s+", " ").trim.success

  private def quote(s: String) = "'" + s + "'"

  def parseAsn(s: String): Validation[String, Asn] = try {
    Asn.parse(s).success
  } catch {
    case _ => (quote(s) + " is not a valid ASN").fail
  }

  def parseIpPrefix(s: String): Validation[String, IpRange] = try {
    val resource = IpRange.parse(s)
    if (resource.isLegalPrefix)
      resource.success
    else
      (quote(s) + " is not a valid IPv4 or IPv6 prefix").fail
  } catch {
    case _ => (quote(s) + " is not a valid IPv4 or IPv6 prefix").fail
  }

  def parseInt(s: String): Validation[String, Int] = try {
    s.toInt.success
  } catch {
    case _: NumberFormatException => (quote(s) + " is not a number").fail
  }

  def containedIn(range: Range): Int => Validation[String, Int] = value => {
    if (range.contains(value)) value.success else "must be between %d and %d, was %d".format(range.start, range.end, value).fail
  }
}
