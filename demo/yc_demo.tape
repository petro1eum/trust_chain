# ┌──────────────────────────────────────────────┐
# │  TrustChain — YC Demo (Terminal Recording)   │
# │                                              │
# │  Pre-req:                                    │
# │    .venv/bin/python demo/yc_demo_cli_setup.py│
# │                                              │
# │  Record:                                     │
# │    vhs demo/yc_demo.tape                     │
# └──────────────────────────────────────────────┘

Output demo/out/yc_trustchain_demo.mp4
Set Shell zsh
Set FontFamily "Menlo"
Set FontSize 22
Set Width 1280
Set Height 720
Set Theme "Catppuccin Mocha"
Set Padding 30
Set Framerate 30
Set PlaybackSpeed 1
Set TypingSpeed 50ms
Set CursorBlink false

# ── Activate venv silently ──
Hide
Type "export PATH=$PWD/.venv/bin:$PATH 2>/dev/null"
Enter
Sleep 300ms
Type "clear"
Enter
Sleep 300ms
Show

# ═══════════════════════════════════════════════
#  PART 1: Show the code, then run it
# ═══════════════════════════════════════════════

Sleep 800ms

# Show the source — viewer sees what will run
Type "head -36 demo/yc_demo.py"
Enter
Sleep 5s

# Run it — sign → verify ✅ → tamper → catch ❌ → revert
Type "python demo/yc_demo.py"
Enter
Sleep 7s

# ═══════════════════════════════════════════════
#  PART 2: CLI — Git for AI Agents
# ═══════════════════════════════════════════════

Type "echo"
Enter
Type "echo '═══ CLI: Git for AI agents ═══'"
Enter
Sleep 1s

# Point to pre-built chain with 5 realistic operations
Type "export TRUSTCHAIN_DIR=/tmp/yc-trustchain-demo/.trustchain"
Enter
Sleep 500ms

# tc log --graph — the DAG visualization
Type "tc log --graph"
Enter
Sleep 5s

# tc blame — forensics on a specific tool
Type "tc blame code_executor"
Enter
Sleep 4s

# tc revert — compensatory transaction
Set TypingSpeed 40ms
Type 'tc revert op_0003 -m "Agent ran rm -rf / — reverting"'
Enter
Sleep 4s
Set TypingSpeed 50ms

# tc chain-verify — prove chain integrity after revert
Type "tc chain-verify"
Enter
Sleep 4s

# Closing
Sleep 1s
Type "echo"
Enter
Type "echo '✅ TrustChain: SSL for AI — pip install trustchain'"
Enter
Sleep 3s
