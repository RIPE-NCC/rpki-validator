package net.ripe.rpki.validator.config

import org.junit.runner.RunWith
import org.scalatest.FunSuite
import org.scalatest.junit.JUnitRunner
import java.net.Socket
import java.net.InetAddress
import org.scalatest.BeforeAndAfterAll
import org.scalatest.matchers.ShouldMatchers
import org.scalatest.matchers.ShouldMatchers._

@RunWith(classOf[JUnitRunner])
class RTRServerTest extends FunSuite with BeforeAndAfterAll with ShouldMatchers {

  override def beforeAll() = {
	  RTRServer.startServer
  }
  
  test("should connect") {
    val socket = new Socket("127.0.0.1", 8282)
    socket.isConnected() should equal(true)
  }
  
  
  
  
  
}