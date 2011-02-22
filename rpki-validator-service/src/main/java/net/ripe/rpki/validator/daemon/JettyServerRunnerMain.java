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
