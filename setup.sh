#!/bin/bash
#
# DNS Packet Analyzer Setup Script
# This script sets up the environment and validates prerequisites
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "=========================================="
echo "DNS Packet Analyzer Setup"
echo "=========================================="
echo ""

# Function to print colored messages
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_info() {
    echo -e "  $1"
}

# Check Python version
echo "Checking Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
    
    if [ "$PYTHON_MAJOR" -ge 3 ] && [ "$PYTHON_MINOR" -ge 8 ]; then
        print_success "Python $PYTHON_VERSION found"
    else
        print_error "Python 3.8+ required. Found: $PYTHON_VERSION"
        exit 1
    fi
else
    print_error "Python 3 not found. Please install Python 3.8 or higher."
    exit 1
fi

# Check for tshark
echo ""
echo "Checking Wireshark tools..."
if command -v tshark &> /dev/null; then
    TSHARK_VERSION=$(tshark --version 2>&1 | head -1)
    print_success "tshark found: $TSHARK_VERSION"
else
    print_error "tshark not found in PATH"
    print_info "Please install Wireshark:"
    print_info "  macOS: brew install wireshark"
    print_info "  Ubuntu/Debian: sudo apt-get install wireshark-common"
    print_info "  RHEL/CentOS: sudo yum install wireshark"
    exit 1
fi

# Check for editcap
if command -v editcap &> /dev/null; then
    EDITCAP_VERSION=$(editcap --version 2>&1 | head -1)
    print_success "editcap found: $EDITCAP_VERSION"
else
    print_error "editcap not found in PATH"
    print_info "Please install Wireshark (editcap is included)"
    exit 1
fi

# Create virtual environment
echo ""
echo "Setting up Python virtual environment..."
if [ -d "venv" ]; then
    print_warning "Virtual environment already exists"
    read -p "  Recreate it? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf venv
        python3 -m venv venv
        print_success "Virtual environment created"
    else
        print_info "Using existing virtual environment"
    fi
else
    python3 -m venv venv
    print_success "Virtual environment created"
fi

# Activate virtual environment and install dependencies
echo ""
echo "Installing Python dependencies..."
source venv/bin/activate

if [ -f "requirements.txt" ]; then
    pip install --upgrade pip --quiet
    pip install -r requirements.txt
    print_success "Dependencies installed"
else
    print_error "requirements.txt not found"
    exit 1
fi

# Create output directories
echo ""
echo "Creating output directories..."
mkdir -p output/detailed
mkdir -p output/summary
mkdir -p output/json
print_success "Output directories created"

# Make main script executable
if [ -f "dns_analyzer.py" ]; then
    chmod +x dns_analyzer.py
    print_success "dns_analyzer.py made executable"
fi

# Test installation
echo ""
echo "Testing installation..."
if python3 -c "import watchdog, pandas" 2>/dev/null; then
    print_success "Python dependencies verified"
else
    print_error "Failed to import required modules"
    exit 1
fi

# Test tshark access
if tshark --version &> /dev/null; then
    print_success "tshark is accessible"
else
    print_error "tshark is not accessible"
    exit 1
fi

# Summary
echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "To use the DNS Analyzer:"
echo ""
echo "1. Activate the virtual environment:"
echo "   source venv/bin/activate"
echo ""
echo "2. Run the analyzer:"
echo "   python3 dns_analyzer.py --input-dir /path/to/pcap/files --output-dir ./output"
echo ""
echo "3. Or run directly (if venv is activated):"
echo "   ./dns_analyzer.py --input-dir /path/to/pcap/files --output-dir ./output"
echo ""
echo "For continuous monitoring:"
echo "   python3 dns_analyzer.py --input-dir /path/to/pcap/files --output-dir ./output"
echo "   (Press Ctrl+C to stop)"
echo ""
echo "Output files will be in:"
echo "   - ./output/detailed/  (detailed CSV files)"
echo "   - ./output/summary/     (summary CSV files)"
echo "   - ./output/json/       (intermediate JSON files, if kept)"
echo ""


