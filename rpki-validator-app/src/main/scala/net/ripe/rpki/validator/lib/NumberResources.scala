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
import scalaz.Node
import scalaz.Monoid
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
    override def append(s1: NumberResourceInterval, s2: => NumberResourceInterval) =
      NumberResourceInterval(s1.start min s2.start, s1.end max s2.end)
  }

  class NumberResourceIntervalTree[A](tree: FingerTree[NumberResourceInterval, A]) {
    def isEmpty = tree.isEmpty

    def filterContaining(range: NumberResourceInterval)(implicit reducer: Reducer[A, NumberResourceInterval]): IndexedSeq[A] = {
      implicit def NodeReducer[A] = new Reducer[Node[NumberResourceInterval, A], NumberResourceInterval] {
        override def unit(node: Node[NumberResourceInterval, A]) = node.measure
      }

      def loop[A](tree: FingerTree[NumberResourceInterval, A])(collect: A => Unit)(implicit reducer: Reducer[A, NumberResourceInterval]) {
        def collectIfMatches(value: A) = if (reducer.unit(value) contains range) collect(value)
        tree.fold(
          empty = _ => (),
          single = (_, value) => collectIfMatches(value),
          deep = (r, prefix, interior, suffix) => if (r contains range) {
            if (prefix.measure contains range) {
              prefix.foreach(collectIfMatches)
            }
            loop(interior)(_.foreach(collectIfMatches))
            if (suffix.measure contains range) {
              suffix.foreach(collectIfMatches)
            }
          })
      }

      val builder = IndexedSeq.newBuilder[A]
      loop(tree)(builder += _)
      builder.result()
    }
  }

  object NumberResourceIntervalTree {
    def apply[A](a: A*)(implicit reducer: Reducer[A, NumberResourceInterval]) = {
      val values = a.sortBy(reducer.unit(_))
      new NumberResourceIntervalTree(values.foldLeft(FingerTree.empty[NumberResourceInterval, A])(_ :+ _))
    }

    def empty[A](implicit reducer: Reducer[A, NumberResourceInterval]) =
      new NumberResourceIntervalTree(FingerTree.empty[NumberResourceInterval, A])
  }

}
