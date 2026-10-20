# Bash completion for taema. Dynamic names come from the CLI registry and live state.
_taema_completion() {
    local current=${COMP_WORDS[COMP_CWORD]}
    local line=${COMP_LINE}
    mapfile -t COMPREPLY < <(
        taema __complete --shell bash --word "$current" --line "$line" \
            --cursor "${COMP_POINT:-${#line}}" 2>/dev/null
    )
}
complete -F _taema_completion taema
