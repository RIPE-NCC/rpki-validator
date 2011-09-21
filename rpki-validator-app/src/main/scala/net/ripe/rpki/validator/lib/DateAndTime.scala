package net.ripe.rpki.validator.lib

import org.joda.time._

object DateAndTime {
  def keepMostSignificantPeriodFields(n: Int, period: Period): ReadablePeriod = {
    for (i <- period.getFieldTypes().indices.dropRight(n - 1)) {
      if (period.getValue(i) != 0) {
        val result = new MutablePeriod()
        for (j <- i until (i + n)) {
          result.setValue(j, period.getValue(j))
        }
        return result.toPeriod()
      }
    }
    return period
  }
}
