package net.ripe.certification.validator.commands;

import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;


public class PrintVersionCommandTest {

    private PrintVersionCommand subject;
    private PrintStream savedSystemOut;

    @Before
    public void setUp() {
        subject = new PrintVersionCommand();
        savedSystemOut = System.out;
    }
    
    @After
    public void cleanUp() {
        System.setOut(savedSystemOut);
    }

    @Test
    public void shouldPrintVersionFromPropertyFile() {
        ByteArrayOutputStream outContent = new ByteArrayOutputStream();
        System.setOut(new PrintStream(outContent));

        subject.execute();

        assertTrue(outContent.toString().startsWith("RIPE NCC"));
    }
}
