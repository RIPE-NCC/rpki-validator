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
package net.ripe.rpki.validator.cli;

import ch.qos.logback.classic.Level;
import io.github.faketime.FakeTime;
import net.ripe.rpki.validator.commands.BottomUpValidationCommand;
import net.ripe.rpki.validator.commands.PrintCertificateRepositoryObjectCommand;
import net.ripe.rpki.validator.commands.PrintVersionCommand;
import net.ripe.rpki.validator.commands.TopDownValidationCommand;
import org.apache.commons.cli.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;


public final class Main {

    private static Logger logger = LoggerFactory.getLogger(Main.class);

    private CommandLineOptions options;

    private Main() {
    }

    public static void main(String[] args) {
        System.out.println("Before fake  " + LocalDateTime.now());
        //-DFAKETIME=[YYYY-MM-DD]T[HH:MM:SS]
        String fakeTime = System.getProperty("FAKETIME");
        if(fakeTime != null)
            FakeTime.stopAt(LocalDateTime.parse(fakeTime));
        System.out.println("After  fake  " + LocalDateTime.now());
        try {
            new Main().run(args);
            System.exit(0);
        } catch (Exception e) {
            logger.error(e.getMessage());
            System.exit(1);
        }
    }

    private void run(String[] args) {
        parseOptions(args);
        execute();
    }

    private void execute() {
        if (options.isPrintVersionMode()) {
            new PrintVersionCommand().execute();
        } else if (options.isPrintHelpMode()) {
            options.printHelp();
        } else if (options.isPrintObjectMode()) {
            new PrintCertificateRepositoryObjectCommand(options).execute();
        } else if (options.isValidationMode()) {
            setVerbosity();
            if (options.isTopDownValidationEnabled()) {
                new TopDownValidationCommand(options).execute();
            } else {
                new BottomUpValidationCommand(options).execute();
            }
        }
    }

    private void parseOptions(String[] args) {
        options = new CommandLineOptions();
        try {
            options.parse(args);
        } catch (ParseException e) {
            logger.error(e.getMessage());
            System.exit(1);
        }

    }

    private void setVerbosity() {
        if (options.isVerboseEnabled()) {
            Logger rootLogger = LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
            if ((rootLogger instanceof ch.qos.logback.classic.Logger)) {
                ch.qos.logback.classic.Logger logbackLogger = (ch.qos.logback.classic.Logger) rootLogger;
                logbackLogger.setLevel(Level.DEBUG);
            }
        }
    }
}
