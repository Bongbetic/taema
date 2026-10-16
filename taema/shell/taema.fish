# taema.fish: the prompt hook (see taema/README.md, "The prompt").
#
# At each prompt this reports a command line that ran for 2 s or more to the daemon, and, when
# the daemon has a question about its leftover processes, asks it once. A normal prompt costs
# builtins only: one `test -e` and no subprocess.
#
# Off unless the shell is interactive on a terminal, TAEMA_NO_PROMPT is unset and the hook
# program is executable.

set -g __taema_hook /usr/libexec/taema/taema-hook
set -q TAEMA_HOOK; and set __taema_hook $TAEMA_HOOK

if status is-interactive; and isatty stdin; and isatty stdout; and not set -q TAEMA_NO_PROMPT; and test -x $__taema_hook; and not functions -q __taema_postexec
    set -g __taema_n 0
    if set -q TAEMA_JOB; and test (string split -m1 . -- $TAEMA_JOB)[1] != $fish_pid
        set -gx TAEMA_PARENT_JOB $TAEMA_JOB     # a nested shell: remember the job that started it
    end
    set -g __taema_n (math $__taema_n + 1)
    set -gx TAEMA_JOB $fish_pid.$__taema_n

    # after each command line: report it, then tag the NEXT one (children inherit TAEMA_JOB)
    function __taema_postexec --on-event fish_postexec
        set -l st $status       # first
        set -l dur $CMD_DURATION
        set -l words (string split -n ' ' -- (string trim -- "$argv[1]"))
        set -l word (string sub -l 32 -- "$words[1]")
        if string match -qr '^(kill|pkill|killall)$' -- "$words[1]"; or begin; test "$words[1]" = taema; and test "$words[2]" = kill; end
            $__taema_hook kill $fish_pid "$words[1]" >/dev/null 2>&1 &
            disown 2>/dev/null
        else if test "$dur" -ge 2000
            $__taema_hook done $fish_pid $TAEMA_JOB $st "$word" >/dev/null 2>&1 &
            disown 2>/dev/null
        end
        set -g __taema_n (math $__taema_n + 1)
        set -gx TAEMA_JOB $fish_pid.$__taema_n
    end

    # before each prompt: a pending question is a file that exists
    function __taema_prompt --on-event fish_prompt
        if test -e "$XDG_RUNTIME_DIR/taema/q.$fish_pid"
            $__taema_hook ask $fish_pid 2>/dev/null
        end
    end
end
