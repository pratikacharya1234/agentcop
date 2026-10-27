# The honeytoken sting: a decoy credential is touched and the hook denies it. Not a live Claude Code session.
Output docs/assets/sting.gif

Set Shell "bash"
Set FontSize 20
Set Width 1100
Set Height 520
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

Type "$HOME/.agentcop/bin/cop-hook < docs/assets/tapes/fixtures/honeytoken.json"
Enter
Sleep 4s
