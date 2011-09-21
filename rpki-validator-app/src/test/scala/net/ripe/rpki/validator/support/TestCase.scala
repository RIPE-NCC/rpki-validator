package net.ripe.rpki.validator.support

import org.junit.runner.RunWith
import org.scalatest.junit.JUnitRunner
import org.scalatest.FunSuite
import org.scalatest.matchers.ShouldMatchers

@RunWith(classOf[JUnitRunner])
abstract class TestCase extends FunSuite with ShouldMatchers
