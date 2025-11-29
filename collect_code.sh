#!/bin/bash

# --- CONFIGURATION ---
OUTPUT_FILE="$HOME/Desktop/all_source_code.txt"
TARGET_DIR="."

# Initialize ignore list with standard exclusions
# We construct the "find" command to PRUNE (skip) these directories
# -o means "OR"
IGNORE_ARGS=(
    -name ".git" -prune -o \
    -name ".DS_Store" -o \
    -name "venv" -prune -o \
    -name "__pycache__" -prune -o \
    -name ".pytest_cache" -prune -o \
    -name "*.egg-info" -prune -o
)

# --- STEP 1: PARSE .GITIGNORE ---
echo "Reading .gitignore..."

if [ -f "$TARGET_DIR/.gitignore" ]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
        # 1. Trim whitespace
        line=$(echo "$line" | xargs)
        
        # 2. Skip empty lines and comments
        if [[ -z "$line" ]] || [[ "$line" == \#* ]]; then
            continue
        fi

        # 3. CLEANUP: Remove trailing slashes (e.g. 'venv/' -> 'venv')
        # This fixes the "matches against basenames" warning
        clean_line="${line%/}"
        
        # 4. CLEANUP: Remove leading slashes (e.g. '/dist' -> 'dist')
        clean_line="${clean_line#/}"

        # Add to find arguments
        IGNORE_ARGS+=(-name "$clean_line" -prune -o)
        
    done < "$TARGET_DIR/.gitignore"
fi

# Finalize the find arguments
IGNORE_ARGS+=(-type f -print)

# --- STEP 2: PREPARE OUTPUT FILE ---
{
    echo "Generated on $(date)"
    echo "=========================================="
    echo "IGNORE PATTERNS USED:"
    echo "${IGNORE_ARGS[@]}"
    echo "=========================================="
    echo ""
} > "$OUTPUT_FILE"

echo "Scanning directory: $TARGET_DIR"
echo "Outputting to: $OUTPUT_FILE"

# --- STEP 3: FIND AND CONCATENATE ---
find "$TARGET_DIR" "${IGNORE_ARGS[@]}" | sort | while read -r file; do
    
    # Binary Check: grep looks for a null byte. If found, it's binary.
    if grep -Iq . "$file"; then
        echo "Processing: $file"
        
        {
            echo "----------------------------------------------------------------"
            echo " FILE: $file"
            echo "----------------------------------------------------------------"
            cat "$file"
            echo -e "\n\n"
        } >> "$OUTPUT_FILE"
        
    else
        echo "Skipping binary file: $file"
    fi
done

echo "Done! File saved to $OUTPUT_FILE"