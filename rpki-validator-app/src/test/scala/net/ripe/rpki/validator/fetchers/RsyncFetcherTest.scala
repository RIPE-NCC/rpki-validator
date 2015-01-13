package net.ripe.rpki.validator.fetchers

import java.net.URI

import net.ripe.rpki.validator.support.ValidatorTestCase
import org.scalatest.BeforeAndAfter
import org.scalatest.mock.MockitoSugar

//@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class RsyncFetcherTest extends ValidatorTestCase with BeforeAndAfter with MockitoSugar {

  test("Should download repository") {
    val fetcher = new RsyncFetcher

    System.gc()
    Thread.sleep(2000)
    val heapSize = Runtime.getRuntime.totalMemory()
    val objects = fetcher.fetchRepo(new URI("rsync://rpki.ripe.net/repository/"))
    System.gc()
    Thread.sleep(2000)
    val heapSize2 = Runtime.getRuntime.totalMemory()
    println(objects.right.map(_.size))
    println(s"heapSize = $heapSize, heapSize2 = $heapSize2, diff = ${heapSize2 - heapSize}")
  }

}