package net.ripe.rpki.validator.store

import java.net.URI

import net.ripe.rpki.validator.support.ValidatorTestCase
import org.scalatest.BeforeAndAfter

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class RepoServiceStoreTest extends ValidatorTestCase with BeforeAndAfter {

  test("Should not take slashes into account") {
    val t0 = RepoServiceStore.getLastFetchTime(new URI("rsync://host/a"))
    val t1 = t0.plus(10000L)
    val t2 = t0.plus(50000L)

    RepoServiceStore.updateLastFetchTime(new URI("rsync://host/a/"), t1)
    RepoServiceStore.getLastFetchTime(new URI("rsync://host/a")) should be(t1)
    RepoServiceStore.getLastFetchTime(new URI("rsync://host/a/")) should be(t1)
    RepoServiceStore.getLastFetchTime(new URI("rsync://host/a/b")) should be(t1)

    RepoServiceStore.updateLastFetchTime(new URI("rsync://host/a/b"), t2)
    RepoServiceStore.getLastFetchTime(new URI("rsync://host/a/b")) should be(t2)
    RepoServiceStore.getLastFetchTime(new URI("rsync://host/a")) should be(t1)
    RepoServiceStore.getLastFetchTime(new URI("rsync://host/a/")) should be(t1)

    val t3 = RepoServiceStore.getLastFetchTime(new URI("rsync://host1/b/")).plus(20000L)
    RepoServiceStore.updateLastFetchTime(new URI("rsync://host1/b"), t3)
    RepoServiceStore.getLastFetchTime(new URI("rsync://host1/b/")) should be(t3)
    RepoServiceStore.getLastFetchTime(new URI("rsync://host1/b/x")) should be(t3)
    RepoServiceStore.getLastFetchTime(new URI("rsync://host1/b/x/")) should be(t3)
    RepoServiceStore.getLastFetchTime(new URI("rsync://host1/b/x/y")) should be(t3)
  }


}
