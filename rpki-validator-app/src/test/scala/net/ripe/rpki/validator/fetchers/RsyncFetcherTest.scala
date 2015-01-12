package net.ripe.rpki.validator.fetchers

import java.net.URI

import net.ripe.rpki.validator.support.ValidatorTestCase
import org.scalatest.BeforeAndAfter
import org.scalatest.mock.MockitoSugar

//@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class RsyncFetcherTest extends ValidatorTestCase with BeforeAndAfter with MockitoSugar {

  test("Should download repository") {
    val fetcher = new RsyncFetcher
    val objects = fetcher.fetchRepo(new URI("rsync://rpki.ripe.net/repository/"))
//    println(objects)
  }

}