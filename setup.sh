# setup.sh

```bash
#!/bin/bash

set -e

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║    Quaternary Merkle Tree ZK - Setup Script                  ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Rust is installed
echo -n "Checking Rust installation... "
if command -v rustc &> /dev/null; then
    RUST_VERSION=$(rustc --version)
    echo -e "${GREEN}✓${NC} $RUST_VERSION"
else
    echo -e "${RED}✗ Rust not found${NC}"
    echo ""
    echo "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
    echo -e "${GREEN}✓ Rust installed${NC}"
fi

# Set up official Pico nightly toolchain (REQUIRED)
echo -n "Setting up Pico nightly toolchain (nightly-2025-08-04)... "
rustup toolchain install nightly-2025-08-04
rustup update nightly-2025-08-04
rustup component add rust-src --toolchain nightly-2025-08-04
rustup override set nightly-2025-08-04
echo -e "${GREEN}✓${NC}"

# Verify correct toolchain is active
echo -n "Verifying toolchain version... "
ACTIVE_TOOLCHAIN=$(rustc --version)
echo -e "${GREEN}$ACTIVE_TOOLCHAIN${NC}"

# Add RISC-V target
echo -n "Checking RISC-V target... "
if rustup target list --toolchain nightly-2025-08-04 | grep -q "riscv32im-unknown-none-elf (installed)"; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${YELLOW}Installing...${NC}"
    rustup target add --toolchain nightly-2025-08-04 riscv32im-unknown-none-elf
    echo -e "${GREEN}✓ RISC-V target added${NC}"
fi

# Check for Pico CLI
echo -n "Checking Pico CLI... "
if command -v pico-cli &> /dev/null || command -v cargo-pico &> /dev/null; then
    PICO_VERSION=$(pico-cli --version 2>&1 || cargo pico --version 2>&1 || echo "installed")
    echo -e "${GREEN}✓${NC} $PICO_VERSION"
else
    echo -e "${YELLOW}Not found${NC}"
    echo ""
    echo "Installing Pico CLI (official toolchain nightly-2025-08-04)..."
    cargo +nightly-2025-08-04 install --git https://github.com/brevis-network/pico pico-cli

    echo ""
    echo -e "${GREEN}✓ Pico CLI installed${NC}"
fi

# Check for Docker (optional, for EVM mode)
echo -n "Checking Docker (optional)... "
if command -v docker &> /dev/null; then
    DOCKER_VERSION=$(docker --version)
    echo -e "${GREEN}✓${NC} $DOCKER_VERSION"
else
    echo -e "${YELLOW}Not found${NC}"
    echo "  Docker is required only for --evm mode (Groth16 proofs)"
    echo "  Install: https://docs.docker.com/engine/install/"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Building project..."
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Build core
echo "Building core library..."
cd core
cargo +nightly-2025-08-04 build --release
cd ..
echo -e "${GREEN}✓ Core built${NC}"
echo ""

# Build guest (RISC-V)
echo "Building guest program (RISC-V)..."
cd guest
cargo +nightly-2025-08-04 build --target riscv32im-unknown-none-elf --release
cd ..
echo -e "${GREEN}✓ Guest built${NC}"
echo ""

# Build host
echo "Building host program..."
cd host
cargo +nightly-2025-08-04 build --release
cd ..
echo -e "${GREEN}✓ Host built${NC}"
echo ""

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                     Setup Complete!                           ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "Toolchain: nightly-2025-08-04"
echo ""
echo "Next steps:"
echo ""
echo "1. Run the demo (generates membership proof):"
echo "   cd host && cargo run --release"
echo "   # Output: quad_proof.json and quad_proof.bin"
echo ""
echo "2. Generate ZK proof (fast mode for testing, ~5 min):"
echo "   cd guest"
echo "   RUST_LOG=info cargo pico prove --input ../host/quad_proof.bin --fast --elf elf/riscv32im-pico-zkvm-elf"
echo ""
echo "3. Generate production STARK proof (~8-10 min):"
echo "   cd guest"
echo "   mkdir -p ../proof_output"
echo "   RUST_LOG=info cargo pico prove --input ../host/quad_proof.bin --elf elf/riscv32im-pico-zkvm-elf --output ../proof_output"
echo ""
echo "4. Generate Groth16 proof for EVM (requires Docker, 32GB+ RAM):"
echo "   cd guest"
echo "   cargo pico prove --evm --setup --input ../host/quad_proof.bin --elf elf/riscv32im-pico-zkvm-elf  # First time"
echo "   cargo pico prove --evm --input ../host/quad_proof.bin --elf elf/riscv32im-pico-zkvm-elf --output ../evm_proof"
echo ""
echo "5. Run tests:"
echo "   cargo test --workspace"
echo ""
echo "For more information, see README.md and PROOF_RESULTS.md"
echo "Pico documentation: https://docs.brevis.network"
