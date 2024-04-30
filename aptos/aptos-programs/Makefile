# Directory definitions
PROGRAMS_DIR := ../programs
ELF_DIR := elf
ARTIFACTS_DIR := artifacts
BUILD_RESULT_NAME := riscv32im-succinct-zkvm-elf

# Automatically discover program directories
PROGRAMS := $(notdir $(wildcard $(PROGRAMS_DIR)/*))

# Default target
.PHONY: all clean $(PROGRAMS)

all: $(PROGRAMS) clean_elf

# Build targets for each program
$(PROGRAMS):
	@echo "Building program $@"
	@# Command to build each program
	@cd $(PROGRAMS_DIR)/$@ && rustup run succinct cargo prove build
	@echo "Moving artifacts..."
	@mkdir -p $(ARTIFACTS_DIR)
	@mv $(PROGRAMS_DIR)/$@/$(ELF_DIR)/$(BUILD_RESULT_NAME) $(ARTIFACTS_DIR)/$@-program

# Clean elf directories
clean_elf:
	@echo "Cleaning ELF directories..."
	@rm -rf $(PROGRAMS_DIR)/*/$(ELF_DIR)

# Clean up the artifacts directory
clean:
	@echo "Cleaning up artifacts..."
	@rm -f $(ARTIFACTS_DIR)/*
