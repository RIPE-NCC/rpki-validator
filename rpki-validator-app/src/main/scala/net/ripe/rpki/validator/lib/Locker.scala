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
package net.ripe.rpki.validator.lib


import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock

import grizzled.slf4j.Logging

import scala.collection.mutable

/**
 * Execute a function while acquiring a lock by a key.
 */
class Locker extends Logging {

  private class AccessibleLock extends ReentrantLock {
    def getOwningThread = getOwner
  }

  private val locks = mutable.Map[Object, AccessibleLock]()
  private val globalLock = new AccessibleLock()

  private def getStackTrace(thread: Thread) =
    thread.getStackTrace.dropWhile(_.getClassName.startsWith(classOf[Locker].getName))
      .map(s => s.getFileName + ":" + s.getLineNumber + "\t\t\t" + s.getClassName).mkString("\n\t","\n\t","\n")

  def locked[T](key: Object)(f: => T): T = {
    val lock = _locked(globalLock) {
      locks.getOrElseUpdate(key, new AccessibleLock())
    }
    try {
      _locked(lock) {
        f
      }
    } finally {
      _locked(globalLock) {
        locks.remove(key)
      }
    }
  }

  @inline
  private def _locked[T, X](lock: AccessibleLock)(g: => T): T = {
    if (! lock.tryLock(61, TimeUnit.SECONDS)) {
      val key: Object = locks.find(l => l._2 == lock).get._1
      val lockOwner = lock.getOwningThread
      if (lockOwner != null) {
        logger.info(s"waiting in ${Thread.currentThread()} on ${key} from ${getStackTrace(Thread.currentThread())}")
        logger.info(s"Locked by $lockOwner: ${getStackTrace(lockOwner)}")
      }
      lock.lock()
    }
    try {
      g
    } finally {
      lock.unlock()
    }
  }
}
