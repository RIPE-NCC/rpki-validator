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
package net.ripe.rpki.validator.store

import java.io.File
import javax.sql.DataSource

import com.googlecode.flyway.core.Flyway
import net.ripe.rpki.validator.config.ApplicationOptions
import org.springframework.jdbc.datasource.DriverManagerDataSource

object DataSources {

  System.setProperty("derby.system.home", ApplicationOptions.workDirLocation.getCanonicalPath)

  private object DSSingletons extends SimpleSingletons[String, DataSource]({ dataDirBasePath =>
    val result = new DriverManagerDataSource
    result.setUrl("jdbc:derby:" + dataDirBasePath + File.separator + "rpki-object-cache;create=true")
    result.setDriverClassName("org.apache.derby.jdbc.EmbeddedDriver")
    migrate(result)
    result
  })

  /**
   * Store data on disk.
   */
  def DurableDataSource(dataDirBasePath: File) = DSSingletons(dataDirBasePath.getAbsolutePath)

  /**
   * For unit testing
   */
  def InMemoryDataSource = {
    val result = new DriverManagerDataSource
    result.setUrl("jdbc:derby:memory:rpki-object-cache;create=true")
    result.setDriverClassName("org.apache.derby.jdbc.EmbeddedDriver")
    migrate(result)
    result
  }

  private def migrate(dataSource: DataSource) {
    // configure Flyway's logging with Slf4j
    com.googlecode.flyway.core.util.logging.LogFactory.setLogCreator(
      new com.googlecode.flyway.core.util.logging.LogCreator {
        override def createLogger(clazz: Class[_]): com.googlecode.flyway.core.util.logging.Log =
          new com.googlecode.flyway.core.util.logging.Log {
            val slf4jLogger = org.slf4j.LoggerFactory.getLogger(clazz)

            override def warn(message: String): Unit = slf4jLogger.warn(message)
            override def error(message: String): Unit = slf4jLogger.error(message)
            override def error(message: String, e: Exception): Unit = slf4jLogger.error(message, e)
            override def debug(message: String): Unit = slf4jLogger.debug(message)
            override def info(message: String): Unit = slf4jLogger.info(message)
          }
      }
    )

    val flyway = new Flyway
    flyway.setDataSource(dataSource)
    flyway.setLocations("/db/objectstore/migration")
    flyway.migrate
  }
}
