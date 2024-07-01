# Directory definitions
PROGRAMS_DIR := ../programs
BENCHMARKS_DIR := ../programs/benchmarks
ELF_DIR := elf
ARTIFACTS_DIR := artifacts
BUILD_RESULT_NAME := riscv32im-succinct-zkvm-elf

# Automatically discover program directories
PROGRAMS := $(notdir $(wildcard $(PROGRAMS_DIR)/*))
BENCHMARKS := $(notdir $(wildcard $(BENCHMARKS_DIR)/*))

# Exclude the benchmarks directory from PROGRAMS
PROGRAMS := $(filter-out benchmarks,$(PROGRAMS))

# Append the benchmarks directories to PROGRAMS
PROGRAMS += $(addprefix benchmarks/,$(BENCHMARKS))

# Default target
.PHONY: all clean $(PROGRAMS)

all: $(PROGRAMS) clean_elf

# Build targets for each program
$(PROGRAMS):
	@echo "Building program $@"
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