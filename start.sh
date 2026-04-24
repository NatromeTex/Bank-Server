#!/bin/bash

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Start bank server in a new terminal
osascript -e "tell application \"Terminal\"
  do script \"cd '$PROJECT_DIR' && source venv/bin/activate && cd bank && python -m uvicorn main:app --reload\"
end tell"

# Start inference model in a new terminal
osascript -e "tell application \"Terminal\"
  do script \"cd '$PROJECT_DIR' && source venv/bin/activate && cd inference && python app.py\"
end tell"

# Start mitigation controller in a new terminal
osascript -e "tell application \"Terminal\"
  do script \"cd '$PROJECT_DIR' && source venv/bin/activate && python mitigation/app.py\"
end tell"

# Start attack load in a new terminal
osascript -e "tell application \"Terminal\"
  do script \"cd '$PROJECT_DIR' && source venv/bin/activate && python tests/attack_load.py\"
end tell"

echo "Launched 4 terminal windows:"
echo "  Bank server          -> http://localhost:8000"
echo "  Inference model      -> http://localhost:8001"
echo "  Mitigation controller (logs to mitigation/logs/)"
echo "  Attack load"
