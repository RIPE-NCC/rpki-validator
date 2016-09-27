/**
  * %%Ignore-License
  * scala-stm - (c) 2009-2010, Stanford University, PPL
  * Copied from scala.concurrent.stm.examples
  * https://github.com/nbronson/scala-stm/blob/master/src/test/scala/scala/concurrent/stm/examples/IndexedMap.scala
  */
package net.ripe.rpki.validator.store

import scala.concurrent.stm._

class IndexedMap[A, B] {

  private class Index[C](view: (A, B) => Iterable[C]) extends (C => Map[A, B]) {
    val mapping = TMap.empty[C, Map[A, B]]

    def apply(derived: C) = mapping.single.getOrElse(derived, Map.empty[A, B])

    def +=(kv: (A, B))(implicit txn: InTxn) {
      for (c <- view(kv._1, kv._2))
        mapping(c) = apply(c) + kv
    }

    def -=(kv: (A, B))(implicit txn: InTxn) {
      for (c <- view(kv._1, kv._2)) {
        val after = mapping(c) - kv._1
        if (after.isEmpty)
          mapping -= c
        else
          mapping(c) = after
      }
    }
  }

  private val contents = TMap.empty[A, B]
  private val indices = Ref(List.empty[Index[_]])

  def addIndex[C](view: (A, B) => Iterable[C]): (C => Map[A, B]) = atomic { implicit txn =>
    val index = new Index(view)
    indices() = index :: indices()
    contents foreach { index += _ }
    index
  }

  def get(key: A): Option[B] = contents.single.get(key)

  def getAll: Iterable[B] = contents.single.values

  def put(key: A, value: B): Option[B] = atomic { implicit txn =>
    val prev = contents.put(key, value)
    for (p <- prev; i <- indices())
      i -= (key -> p)
    for (i <- indices())
      i += (key -> value)
    prev
  }

  def clean(): Unit = atomic { implicit txn =>
    indices.single.set(List.empty[Index[_]])
    contents.clear()
  }

  def remove(key: A): Option[B] = atomic { implicit txn =>
    val prev = contents.remove(key)
    for (p <- prev; i <- indices())
      i -= (key -> p)
    prev
  }
}
