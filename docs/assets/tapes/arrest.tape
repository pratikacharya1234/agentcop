# Hook replay: the arrest. Not a live Claude Code session.
# Run from the repository root, after `cargo build --release -p cop-cli -p cop-hook`.
Output docs/assets/arrest.gif

Set Shell "bash"
Set FontSize 20
Set Width 1100
Set Height 520
Set TypingSpeed 40ms
Set Theme "Dracula"

# Setup in a throwaway HOME. Nothing here touches a real ~/.claude or ~/.agentcop.
Hide
Env HOME "/tmp/agentcop-demo"
Type "rm -rf /tmp/agentcop-demo && mkdir -p /tmp/agentcop-demo/.claude && echo '{}' > /tmp/agentcop-demo/.claude/settings.json"
Enter
Type "./target/release/agentcop install > /dev/null"
Enter
Sleep 2s
Type "clear"
Enter
Show

# The arrest: the agent's destructive command is sent to the hook, and the hook denies it with a case number.
Type "$HOME/.agentcop/bin/cop-hook < docs/assets/tapes/fixtures/rm-root.json"
Enter
Sleep 4s
