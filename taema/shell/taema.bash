# taema.bash: the prompt hook (see taema/README.md, "The prompt").
#
# At each prompt this reports a command line that ran for 2 s or more to the daemon, and, when
# the daemon has a question about its leftover processes, asks it once. A normal prompt costs
# builtins only: one `[[ -e ]]` test, no subprocess, and no DEBUG trap.
#
# Off unless the shell is interactive on a terminal, TAEMA_NO_PROMPT is unset and the hook
# program is executable.

case $- in *i*) ;; *) return 0 ;; esac
[[ -t 0 && -t 1 ]] || return 0
[[ -z ${TAEMA_NO_PROMPT-} ]] || return 0
_taema_hook=${TAEMA_HOOK:-/usr/libexec/taema/taema-hook}
[[ -x $_taema_hook ]] || return 0
[[ -z ${_taema_loaded-} ]] || return 0
_taema_loaded=1

_taema_n=0
_taema_t0=
_taema_nul=x
_taema_word=
_taema_kill=
if [[ -n ${TAEMA_JOB-} && ${TAEMA_JOB%%.*} != $$ ]]; then
    export TAEMA_PARENT_JOB=$TAEMA_JOB      # a nested shell: remember the job that started it
fi
export TAEMA_JOB="$$.$((++_taema_n))"

if [[ -n ${EPOCHREALTIME-} ]]; then
    _taema_now() { _taema_us=${EPOCHREALTIME/[.,]/}; }
    _taema_ps0='${_taema_nul:$((_taema_t0=${EPOCHREALTIME/[.,]/})):0}'
else
    _taema_now() { _taema_us=$((SECONDS * 1000000)); }
    _taema_ps0='${_taema_nul:$((_taema_t0=SECONDS*1000000)):0}'
fi

# Runs once per command line under ble.sh (which gives the line as $1); plain bash uses PS0.
_taema_preexec() {
    _taema_now
    _taema_t0=$_taema_us
    local w=${1#"${1%%[![:space:]]*}"}
    w=${w%%[[:space:]]*}
    _taema_word=${w:0:32}
    _taema_kill=
    case $w in
    kill|pkill|killall) _taema_kill=1 ;;
    taema) [[ $1 == *[[:space:]]kill* ]] && _taema_kill=1 ;;
    esac
}

_taema_precmd() {
    local st=$?     # first: the status of the command line that just ended
    if [[ -z ${_taema_ble-} && -n ${BLE_VERSION-} ]]; then      # ble.sh attached after this file loaded
        _taema_ble=1
        blehook PREEXEC+=_taema_preexec
    fi
    if [[ -e ${XDG_RUNTIME_DIR-}/taema/q.$$ ]]; then
        "$_taema_hook" ask $$ 2>/dev/null
    fi
    if [[ -n $_taema_t0 ]]; then
        _taema_now
        if [[ -n $_taema_kill ]]; then
            { "$_taema_hook" kill $$ "$_taema_word" >/dev/null 2>&1 & } 2>/dev/null
            disown 2>/dev/null
        elif ((_taema_us - _taema_t0 >= 2000000)); then
            { "$_taema_hook" done $$ "$TAEMA_JOB" "$st" "$_taema_word" >/dev/null 2>&1 & } 2>/dev/null
            disown 2>/dev/null
        fi
    fi
    _taema_t0= _taema_word= _taema_kill=
    export TAEMA_JOB="$$.$((++_taema_n))"       # tags the NEXT command line
    return $st
}

if declare -F blehook >/dev/null 2>&1; then
    blehook PREEXEC+=_taema_preexec
    blehook PRECMD+=_taema_precmd
else
    PS0=${PS0-}$_taema_ps0
    # first in the list, so $? is still the command's status; the function returns it unchanged
    if ((BASH_VERSINFO[0] > 5 || (BASH_VERSINFO[0] == 5 && BASH_VERSINFO[1] >= 1))); then
        PROMPT_COMMAND=(_taema_precmd "${PROMPT_COMMAND[@]}")
    else
        PROMPT_COMMAND="_taema_precmd${PROMPT_COMMAND:+;$PROMPT_COMMAND}"
    fi
fi
