package net.ripe.rpki.validator.lib

import net.ripe.rpki.validator.support.ValidatorTestCase

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent._
import scala.concurrent.duration._

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class LockerTest extends ValidatorTestCase {

  private def checkLocker(key1: String, key2: String, shouldBlock: Boolean = true) {
    var neverExecutedSimultaneously = true
    val locker = new Locker
    val sleepPeriod = 20
    for (n <- 1 to 100) yield {
      var v1isInProgress = false
      var v2isInProgress = false
      val v1 = future {
        locker.locked(key1) {
          v1isInProgress = true
          Thread.sleep(sleepPeriod)
          val incorrect = if (v2isInProgress) true else false
          v1isInProgress = false
          incorrect
        }
      }

      val v2 = future {
        locker.locked(key2) {
          v2isInProgress = true
          Thread.sleep(sleepPeriod)
          val incorrect = if (v1isInProgress) true else false
          v2isInProgress = false
          incorrect
        }
      }
      val wasIncorrect1: Boolean = Await.result(v1, 500.milliseconds)
      val wasIncorrect2: Boolean = Await.result(v2, 500.milliseconds)
      if (shouldBlock) {
        wasIncorrect1 should be(false)
        wasIncorrect2 should be(false)
      } else {
        if (wasIncorrect1 || wasIncorrect2)
          neverExecutedSimultaneously = false
      }
    }

    if (!shouldBlock) {
      // it would be very surprising if they never messed up
      neverExecutedSimultaneously should be(false)
    }
  }

  test("should lock with the same keys") {
    checkLocker("x", "x")
  }

  test("should not lock with different keys") {
    checkLocker("x", "y", shouldBlock = false)
  }

}
