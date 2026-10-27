# Health check in a throwaway HOME. Not a live system.
Output docs/assets/doctor.gif

Set Shell "bash"
Set FontSize 20
Set Width 1100
Set Height 560
Set TypingSpeed 40ms
Set Theme "Dracula"

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

# A session start is recorded first, as Claude Code does when a session opens.
Type "$HOME/.agentcop/bin/cop-hook < docs/assets/tapes/fixtures/session-start.json"
Enter
Sleep 1s
Type "./target/release/agentcop doctor"
Enter
Sleep 3s
