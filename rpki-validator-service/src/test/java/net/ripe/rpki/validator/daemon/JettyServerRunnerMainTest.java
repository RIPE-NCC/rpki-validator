package net.ripe.rpki.validator.daemon;

import org.junit.Test;

public class JettyServerRunnerMainTest {
    @Test
    public void shouldStartAndStopServer() throws Exception {
        JettyServerRunnerMain runner = null;

        try {
            runner = new JettyServerRunnerMain("rpki_validator_service_embedded_jetty-config.xml", 32124);

            runner.start();
        } finally {
            if (runner != null) {
                runner.stop();
            }
        }

    }
}
