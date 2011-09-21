package net.ripe.rpki.validator
package lib

import org.joda.time.Period

import support.TestCase

class DateAndTimeTest extends TestCase {
  import DateAndTime._

  test("keep first significant field") {
    val period = new Period().withWeeks(3).withDays(6)
    keepMostSignificantPeriodFields(1, period) should equal(new Period().withWeeks(3))
  }

  test("keep three significant fields") {
    val period = new Period().withWeeks(3).withDays(6).withHours(23).withMinutes(40).withMillis(300)
    keepMostSignificantPeriodFields(3, period) should equal(new Period().withWeeks(3).withDays(6).withHours(23))
  }

  test("stay within field bounds") {
    val period = new Period().withMillis(300)
    keepMostSignificantPeriodFields(3, period) should equal(new Period().withMillis(300))
  }
}
