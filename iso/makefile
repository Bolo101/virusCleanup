# Define variables
SCRIPT_XFCE := ./forgeIsoXfce.sh
SCRIPT_KDE := ./forgeIsoKde.sh
BUILD_DIR := $(PWD)/debian-live-build

.PHONY: all clean

# Default target: run the script
all:
	chmod +x $(SCRIPT_XFCE)
	bash $(SCRIPT_XFCE)

kde:
	chmod +x $(SCRIPT_KDE)
	bash $(SCRIPT_KDE)

# Clean target: remove the debian-live-build directory
clean:
	rm -rf $(BUILD_DIR)
