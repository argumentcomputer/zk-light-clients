# Directory definitions
PROGRAMS_DIR := ../programs
ELF_DIR := ../elf
ARTIFACTS_DIR := artifacts
BUILD_RESULT_NAME := riscv32im-succinct-zkvm-elf

# Automatically discover program directories
PROGRAMS := $(notdir $(wildcard $(PROGRAMS_DIR)/*))

# Default target
.PHONY: all clean $(PROGRAMS)

all: $(PROGRAMS) move_artifacts clean_elf

# Build targets for each program
$(PROGRAMS):
	@echo "Building program $@"
	@# Command to build each program
	@cd $(PROGRAMS_DIR)/$@ && rustup run succinct cargo prove build

# Move and rename artifacts after build, finally remove elf directory
move_artifacts:
	@echo "Moving artifacts..."
	@mkdir -p $(ARTIFACTS_DIR)
	@$(foreach prog,$(PROGRAMS),mv $(ELF_DIR)/$(BUILD_RESULT_NAME) $(ARTIFACTS_DIR)/$(prog)-program;)

# Clean elf directory
clean_elf:
	@echo "Cleaning ELF directory..."
	@rm -rf $(ELF_DIR)

# Clean up the artifacts directory
clean:
	@echo "Cleaning up artifacts..."
	@rm -f $(ARTIFACTS_DIR)/*
