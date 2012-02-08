package net.ripe.rpki.validator.config

import org.scalatest.FunSuite
import org.scalatest.matchers.ShouldMatchers

class ReleaseInfoTest extends FunSuite with ShouldMatchers {

  test("should return version number") {
    ReleaseInfo.version should include regex ("""\d\.\d""")
  }

  test("should return empty string for unknown keys") {
    ReleaseInfo("nosuchkey") should equal ("")
  }
}
