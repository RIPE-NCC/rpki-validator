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
package net.ripe.rpki.validator.bgp.preview

import net.ripe.ipresource.Asn
import net.ripe.ipresource.IpRange
import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader

import grizzled.slf4j.Logging
import net.ripe.rpki.validator.lib.DateAndTime
import org.joda.time.DateTime

import scala.util.control.NonFatal

case class BgpRisEntry(origin: Asn, prefix: IpRange, visibility: Int)
case class BgpRisDump(url: String, lastModified: Option[DateTime] = None, entries: Seq[BgpRisEntry] = Nil)

object BgpRisDump extends Logging {
  def toAnnouncedRoutes(entries: Seq[BgpRisEntry]) = {
    val (r, t) = DateAndTime.timed {
      entries.par.
        filter(e => e.visibility >= BgpAnnouncementValidator.VISIBILITY_THRESHOLD).
        map(e => BgpAnnouncement(e.origin, e.prefix)).distinct.seq
    }
    info(s"toAnnouncedRoutes time ${t/1000.0} seconds")
    r
  }

  def parse(is: InputStream): Either[Exception, IndexedSeq[BgpRisEntry]] = {
    val identityMap = new ObjectIdentityMap
    val reader = new BufferedReader(new InputStreamReader(is))
    try {
      Right(Iterator.continually(reader.readLine()).takeWhile(_ != null).flatMap(parseLine).map(makeResourcesUnique(identityMap, _)).toIndexedSeq)
    } catch {
      case e: Exception =>
        Left(e)
    }
  }

  private def makeResourcesUnique(identityMap: ObjectIdentityMap, entry: BgpRisEntry) = {
    import identityMap._
    val asn = makeUnique(entry.origin)
    val prefix = (makeUnique(entry.prefix.getStart) upTo makeUnique(entry.prefix.getEnd)).asInstanceOf[IpRange]
    entry.copy(origin = asn, prefix = prefix)
  }

  private val BgpEntryRegex = """^\s*([0-9]+)\s+([0-9a-fA-F.:/]+)\s+([0-9]+)\s*$""".r
  private[preview] def parseLine(content: String): Option[BgpRisEntry] = {
    content match {
      case BgpEntryRegex(asn, ipprefix, visibility) =>
        try {
          Some(BgpRisEntry(origin = Asn.parse(asn), prefix = IpRange.parse(ipprefix), visibility = Integer.parseInt(visibility)))
        } catch {
          case NonFatal(e) =>
            error("Skipping unparseble line: " + content)
            debug("Detailed error: ", e)
            None
        }
      case _ => None
    }
  }

  private[this] class ObjectIdentityMap {
    private val identityMap = collection.mutable.Map.empty[AnyRef, AnyRef]

    def makeUnique[A <: AnyRef](a: A): A = identityMap.getOrElseUpdate(a, a).asInstanceOf[A]
  }
}
