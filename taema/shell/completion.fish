# Fish completion for taema. Dynamic names come from the CLI registry and live state.
function __taema_completion
    set -l word (commandline -ct)
    set -l line (commandline -cp)
    set -l cursor (commandline -C)
    command taema __complete --shell fish --word "$word" --line "$line" --cursor $cursor 2>/dev/null
end

complete -c taema -f -a '(__taema_completion)'
