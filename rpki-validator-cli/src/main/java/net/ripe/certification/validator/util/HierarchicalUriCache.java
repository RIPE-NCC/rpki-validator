package net.ripe.certification.validator.util;

import java.net.URI;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.lang.StringUtils;

public class HierarchicalUriCache {

    private final Set<URI> cache = new HashSet<URI>();


    public void add(URI uri) {
        cache.add(uri);
    }

    public boolean contains(URI uriToCheck) {
        URI uri = uriToCheck;
        while (StringUtils.isNotEmpty(uri.getRawPath())) {
            if (cache.contains(uri)) {
                return true;
            }
            String path = uri.getRawPath();
            if ("/".equals(path)) {
                return false;
            }

            if (path.endsWith("/")) {
                path = path.substring(0, path.length() - 1);
            }

            int i = path.lastIndexOf('/');
            if (i != -1) {
                uri = uri.resolve(path.substring(0, i + 1));
            } else {
                return false;
            }
        }
        return false;
    }
}
