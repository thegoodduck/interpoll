#!/usr/bin/env bash
# Start all InterPoll services in a tmux session.
# Requires: tmux, node
#
# Pane layout:
#   [Vite dev server] | [WS relay server] | [Gun relay server]

SESSION=interpoll

tmux has-session -t "$SESSION" 2>/dev/null && {
  tmux attach -t "$SESSION"
  exit 0
}

tmux new-session -d -s "$SESSION" -n services

tmux send-keys -t "$SESSION:services.0" "npm run dev" C-m

tmux split-window -h -t "$SESSION:services"
tmux send-keys -t "$SESSION:services.1" "cd community-relay-server && node community-relay-server.js" C-m

tmux split-window -h -t "$SESSION:services"
tmux send-keys -t "$SESSION:services.2" "cd gun-relay-server && node gun-relay.js" C-m

tmux select-layout -t "$SESSION:services" even-horizontal
tmux attach -t "$SESSION"
