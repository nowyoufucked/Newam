#!/bin/bash
#
# Traffic Viewer Launcher - Linux/Mac
# ====================================
# Quick launcher for HTTP/HTTPS Traffic Viewer
#

echo "╔════════════════════════════════════════════════════════╗"
echo "║   HTTP/HTTPS Traffic Viewer - All-in-One Launcher     ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: python3 not found"
    echo "   Please install Python 3.6 or higher"
    exit 1
fi

echo "✓ Python 3 found: $(python3 --version)"
echo ""

# Check if script exists
if [ ! -f "traffic_viewer_all_in_one.py" ]; then
    echo "❌ Error: traffic_viewer_all_in_one.py not found"
    echo "   Please run this script from the correct directory"
    exit 1
fi

echo "Select launch mode:"
echo "  1) Simple GUI (recommended)"
echo "  2) Proxy only (no GUI)"
echo "  3) Custom port"
echo ""
read -p "Enter choice [1-3]: " choice

case $choice in
    1)
        echo ""
        echo "🚀 Launching Simple GUI..."
        echo ""
        python3 traffic_viewer_all_in_one.py --gui simple
        ;;
    2)
        echo ""
        echo "🚀 Launching Proxy Only..."
        echo "   Press Ctrl+C to stop"
        echo ""
        python3 traffic_viewer_all_in_one.py --no-gui
        ;;
    3)
        echo ""
        read -p "Enter port number [9000]: " port
        port=${port:-9000}
        echo ""
        echo "🚀 Launching on port $port..."
        echo ""
        python3 traffic_viewer_all_in_one.py --port $port
        ;;
    *)
        echo "❌ Invalid choice"
        exit 1
        ;;
esac
