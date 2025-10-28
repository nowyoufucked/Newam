#!/bin/bash
# HTTP/HTTPS Traffic Viewer GUI Launcher

echo "Starting HTTP/HTTPS Traffic Viewer GUI..."
echo "=========================================="
echo ""
echo "Requirements:"
echo "- Python 3.6+"
echo "- tkinter (usually included with Python)"
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed"
    exit 1
fi

# Check if tkinter is available
python3 -c "import tkinter" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Error: tkinter is not installed"
    echo "Install with: sudo apt-get install python3-tk (Ubuntu/Debian)"
    echo "            : sudo yum install python3-tkinter (CentOS/RHEL)"
    exit 1
fi

# Launch GUI
cd "$(dirname "$0")"
python3 gui.py
