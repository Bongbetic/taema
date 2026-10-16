# taema.zsh: the prompt hook (see taema/README.md, "The prompt").
#
# At each prompt this reports a command line that ran for 2 s or more to the daemon, and, when
# the daemon has a question about its leftover processes, asks it once. A normal prompt costs
# builtins only: one `[[ -e ]]` test and no subprocess.
#
# Off unless the shell is interactive on a terminal, TAEMA_NO_PROMPT is unset and the hook
# program is executable. Source it from ~/.zshrc.

[[ -o interactive && -t 0 && -t 1 ]] || return 0
[[ -z ${TAEMA_NO_PROMPT-} ]] || return 0
typeset -g _taema_hook=${TAEMA_HOOK:-/usr/libexec/taema/taema-hook}
[[ -x $_taema_hook ]] || return 0
(( ${precmd_functions[(Ie)_taema_precmd]} )) && return 0       # sourced twice

zmodload -F zsh/datetime p:EPOCHREALTIME 2>/dev/null
typeset -gi _taema_n=0
typeset -g _taema_t0= _taema_word= _taema_kill=
if [[ -n ${TAEMA_JOB-} && ${TAEMA_JOB%%.*} != $$ ]]; then
    export TAEMA_PARENT_JOB=$TAEMA_JOB      # a nested shell: remember the job that started it
fi
export TAEMA_JOB="$$.$((++_taema_n))"

_taema_clock() {
    if [[ -n ${EPOCHREALTIME-} ]]; then _taema_now=$EPOCHREALTIME; else _taema_now=$SECONDS; fi
}

_taema_preexec() {
    _taema_clock
    _taema_t0=$_taema_now
    local -a w
    w=(${(z)1})
    _taema_word=${w[1][1,32]}
    _taema_kill=
    case ${w[1]} in
    kill|pkill|killall) _taema_kill=1 ;;
    taema) [[ ${w[2]-} == kill ]] && _taema_kill=1 ;;
    esac
}

_taema_precmd() {
    local st=$?     # first: the status of the command line that just ended
    if [[ -e ${XDG_RUNTIME_DIR-}/taema/q.$$ ]]; then
        "$_taema_hook" ask $$ 2>/dev/null
    fi
    if [[ -n $_taema_t0 ]]; then
        _taema_clock
        if [[ -n $_taema_kill ]]; then
            "$_taema_hook" kill $$ "$_taema_word" >/dev/null 2>&1 &!
        elif (( _taema_now - _taema_t0 >= 2 )); then
            "$_taema_hook" done $$ "$TAEMA_JOB" "$st" "$_taema_word" >/dev/null 2>&1 &!
        fi
    fi
    _taema_t0= _taema_word= _taema_kill=
    export TAEMA_JOB="$$.$((++_taema_n))"       # tags the NEXT command line
    return $st
}

preexec_functions=(${preexec_functions:#_taema_preexec} _taema_preexec)
# first in the list, so $? is still the command's status; the function returns it unchanged
precmd_functions=(_taema_precmd ${precmd_functions:#_taema_precmd})
