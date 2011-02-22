package net.ripe.certification.validator.commands;

import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import org.junit.Before;
import org.junit.Test;


public class PrintVersionCommandTest {

    private PrintVersionCommand subject;


    @Before
    public void setUp() {
        subject = new PrintVersionCommand();
    }

    @Test
    public void shouldPrintVersionFromPropertyFile() {
        ByteArrayOutputStream outContent = new ByteArrayOutputStream();
        System.setOut(new PrintStream(outContent));

        subject.execute();

        assertTrue(outContent.toString().startsWith("RIPE NCC"));
        System.setOut(null);
    }
}
