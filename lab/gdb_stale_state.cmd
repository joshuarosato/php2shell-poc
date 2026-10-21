set pagination off
set breakpoint pending on

# php_var_unserialize_init() reuses BG(unserialize).data when
# BG(unserialize).level != 0.  A non-zero level at the start of a request
# means the pointer comes from a *previous* request -> use-after-free.
break php_var_unserialize_init
commands
silent
if basic_globals.unserialize.level != 0
    printf "== STALE REUSE: BG(unserialize).data=%p (level=%ld)\n", basic_globals.unserialize.data, basic_globals.unserialize.level
    x/9gx basic_globals.unserialize.data
end
continue
end

break php_var_unserialize_destroy
commands
silent
printf "== DESTROY: level=%ld data=%p\n", basic_globals.unserialize.level, basic_globals.unserialize.data
continue
end

run
