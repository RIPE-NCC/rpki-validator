package net.ripe.certification.validator.util;

import static org.junit.Assert.*;

import java.net.URI;

import org.junit.Test;


public class HierarchicalUriCacheTest {

    private HierarchicalUriCache subject = new HierarchicalUriCache();


    @Test
    public void shouldCheckUriAgainstCache() {
        URI uri = URI.create("rsync://host/path/object.roa");
        subject.add(uri);
        assertTrue(subject.contains(uri));
    }

    @Test
    public void shouldContainChildUri() {
        URI parent = URI.create("rsync://host/bar/");
        subject.add(parent);
        assertTrue(subject.contains(URI.create("rsync://host/bar/foo.cer")));
        assertTrue(subject.contains(URI.create("rsync://host/bar/")));
        assertTrue(subject.contains(URI.create("rsync://host/bar/path/")));
    }

    @Test
    public void shouldNotContainDifferentUris() {
        subject.add(URI.create("rsync://host/foo.cer"));
        assertFalse(subject.contains(URI.create("rsync://host/bar.cer")));
        assertFalse(subject.contains(URI.create("rsync://host/foo.cere")));
    }

    @Test
    public void shouldNotContainParentUri() {
        subject.add(URI.create("rsync://host/foo/bar/baz.roa"));
        assertFalse(subject.contains(URI.create("rsync://host/foo/bar/")));
        assertFalse(subject.contains(URI.create("rsync://host/foo/bar")));
        assertFalse(subject.contains(URI.create("rsync://host/foo/bar.cer")));
        assertFalse(subject.contains(URI.create("rsync://host/foo")));
        assertFalse(subject.contains(URI.create("rsync://host/fo")));
        assertFalse(subject.contains(URI.create("rsync://host/")));
        assertFalse(subject.contains(URI.create("rsync://host")));
        assertFalse(subject.contains(URI.create("rsync://host:9999/foo/bar/baz.roa")));
    }

}
