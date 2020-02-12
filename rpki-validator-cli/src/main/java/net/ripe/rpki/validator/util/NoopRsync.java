package net.ripe.rpki.validator.util;

import net.ripe.rpki.commons.rsync.Rsync;

public class NoopRsync extends Rsync {
    @Override
    public int execute() {
        return 0;
    }
}
