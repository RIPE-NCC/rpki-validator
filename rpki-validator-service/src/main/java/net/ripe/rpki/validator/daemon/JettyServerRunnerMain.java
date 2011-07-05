/**
 * The BSD License
 *
 * Copyright (c) 2010, 2011 RIPE NCC
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
package net.ripe.rpki.validator.daemon;

import net.ripe.rpki.validator.daemon.util.FileResourceUtil;
import net.ripe.rpki.validator.daemon.util.RpkiConfigUtil;
import org.apache.log4j.PropertyConfigurator;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.xml.XmlConfiguration;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class JettyServerRunnerMain {
    private static final String DEFAULT_JETTY_CONFIG = "rpki_validator_service_embedded_jetty-config.xml";

    private Server server;
    private String configFilename;
    private Integer overridingPort;

    JettyServerRunnerMain() {
        this(DEFAULT_JETTY_CONFIG, null);
    }

    JettyServerRunnerMain(String configFilename, Integer overridingPort) {
        this.configFilename = configFilename;
        this.overridingPort = overridingPort;
    }

    public static void main(String[] args) throws Exception {  // NOPMD
        new JettyServerRunnerMain()
                .start()
                .join();
    }

    JettyServerRunnerMain start() throws Exception { // NOPMD
        checkRpkiConfigVariable();
        initLog4j();
        startEmbeddedJetty(configFilename);
        return this;
    }

    void stop() throws Exception { // NOPMD
        if (server != null) {
            server.stop();
        }
    }

    private void join() throws InterruptedException {
        server.join();
    }

    // configure(server) throws Exception so can't get around that without useless effort
    private void startEmbeddedJetty(String configFilename) throws Exception { // NOPMD
        server = new Server((overridingPort == null ? getPort() : overridingPort.intValue()));

        InputStream inputStream = JettyServerRunnerMain.class.getClassLoader().getResourceAsStream(configFilename);

        XmlConfiguration configuration = new XmlConfiguration(inputStream);
        configuration.configure(server);

        server.start();
    }

    private int getPort() throws IOException {
        String port = (String) RpkiConfigUtil.loadProperties().get("jetty.port");

        return Integer.parseInt(port);
    }


    private void checkRpkiConfigVariable() {
        Properties properties = System.getProperties();

        if (!properties.containsKey(RpkiConfigUtil.RPKI_CONFIG)) {
            File configFile = new File(new File(".").getAbsolutePath() + "/config/rpki-vs.properties");

            properties.put(RpkiConfigUtil.RPKI_CONFIG, configFile.getAbsolutePath());
        }
    }

    private void initLog4j() {
        File log4jConfig = FileResourceUtil.findFileInPathOrConfigPath("log4j.properties");
        PropertyConfigurator.configure(log4jConfig.getAbsolutePath());
    }
}
