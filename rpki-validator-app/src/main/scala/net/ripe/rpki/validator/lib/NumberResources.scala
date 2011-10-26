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

import scala.collection.mutable.Builder
import scalaz.FingerTree
import scalaz.Finger
import scalaz.Monoid
import scalaz.Node
import scalaz.Reducer
import net.ripe.ipresource._
import net.ripe.rpki.validator.models.RtrPrefix

object NumberResources {
  implicit object AsnOrdering extends Ordering[Asn] {
    override def compare(x: Asn, y: Asn) = x compareTo y
  }
  implicit object IpRangeOrdering extends Ordering[IpRange] {
    override def compare(x: IpRange, y: IpRange) = x compareTo y
  }

  val MinimumNumberResource: UniqueIpResource = Asn.parse("AS0")
  val MaximumNumberResource: UniqueIpResource = Ipv6Address.parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")

  case class NumberResourceInterval(start: UniqueIpResource, end: UniqueIpResource) {
    def contains(that: NumberResourceInterval) = this.start.compareTo(that.start) <= 0 && this.end.compareTo(that.end) >= 0
  }

  implicit object NumberResourceIntervalOrdering extends Ordering[NumberResourceInterval] {
    /**
     * Sort on start ascending and end descending.
     */
    override def compare(x: NumberResourceInterval, y: NumberResourceInterval): Int = {
      var rc = x.start compareTo y.start
      if (rc != 0) return rc

      return y.end.compareTo(x.end)
    }
  }

  implicit object NumberResourceIntervalMonoid extends Monoid[NumberResourceInterval] {
    override val zero = NumberResourceInterval(MaximumNumberResource, MinimumNumberResource)
    override def append(s1: NumberResourceInterval, s2: => NumberResourceInterval) = {
      val other = s2
      NumberResourceInterval(s1.start min other.start, s1.end max other.end)
    }
  }

  class NumberResourceIntervalTree[A] private (tree: FingerTree[NumberResourceInterval, A])(implicit measurer: Reducer[A, NumberResourceInterval]) {
    def isEmpty = tree.isEmpty

    def filterContaining(range: NumberResourceInterval): IndexedSeq[A] = {
      def loop[A](tree: FingerTree[NumberResourceInterval, A])(collect: A => Unit)(implicit measurer: Reducer[A, NumberResourceInterval]) {
        def collectIfMatches(value: A) = if (measurer.unit(value) contains range) collect(value)

        def collectFinger(finger: Finger[NumberResourceInterval, A]) = if (finger.measure contains range) finger.foreach(collectIfMatches)

        tree.fold(
          empty = _ => (),
          single = (_, value) => collectIfMatches(value),
          deep = (measure, prefix, interior, suffix) => if (measure contains range) {
            collectFinger(prefix)
            loop(interior)(_.foreach(collectIfMatches))(FingerTree.NodeMeasure)
            collectFinger(suffix)
          })
      }

      val builder = IndexedSeq.newBuilder[A]
      loop(tree)(builder += _)
      builder.result()
    }
  }

  object NumberResourceIntervalTree {
    def apply[A](elems: A*)(implicit measurer: Reducer[A, NumberResourceInterval]): NumberResourceIntervalTree[A] = {
      new NumberResourceIntervalTree(elems.sortBy(measurer.unit).foldLeft(FingerTree.empty)(_ :+ _))
    }

    def empty[A](implicit measurer: Reducer[A, NumberResourceInterval]): NumberResourceIntervalTree[A] = {
      new NumberResourceIntervalTree(FingerTree.empty)
    }
  }

}
