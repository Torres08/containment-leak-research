import json
import os
import re

log_path = "/home/researcher/.gemini/antigravity/brain/1b5236c6-d0ab-4ef6-9c2d-6b50712adf42/.system_generated/logs/overview.txt"
output_dir = "/home/researcher/containment-leak-research/logs"
os.makedirs(output_dir, exist_ok=True)

# Keep track of file contents
files = {}

with open(log_path, "r", encoding="utf-8") as f:
    for line_num, line in enumerate(f, 1):
        try:
            data = json.loads(line)
        except Exception:
            continue
        
        # Check tool calls
        tool_calls = data.get("tool_calls", [])
        if not tool_calls:
            continue
            
        for tc in tool_calls:
            name = tc.get("name")
            args = tc.get("args")
            if not args:
                continue
            
            # Since args in the JSON might be serialized as strings, we parse them if necessary
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    # Try to clean up stringified JSON or use regex
                    pass
            
            if not isinstance(args, dict):
                continue
                
            target_file = args.get("TargetFile")
            if not target_file:
                continue
                
            # Normalize target file name
            filename = os.path.basename(target_file.strip('"\''))
            
            if "logs/" in target_file or target_file.endswith(".log") or "logs" in target_file:
                if name == "write_to_file":
                    content = args.get("CodeContent")
                    if content:
                        files[filename] = content
                        print(f"[{line_num}] write_to_file -> {filename} ({len(content)} chars)")
                elif name == "replace_file_content":
                    replacement = args.get("ReplacementContent")
                    target_content = args.get("TargetContent")
                    if replacement and filename in files:
                        files[filename] = files[filename].replace(target_content, replacement)
                        print(f"[{line_num}] replace_file_content -> {filename}")
                    elif replacement:
                        # If we don't have it, just record the replacement for now
                        files[filename] = replacement
                        print(f"[{line_num}] replace_file_content (new) -> {filename}")

print("\n--- Recovered files ---")
for fname, content in files.items():
    out_path = os.path.join(output_dir, fname)
    with open(out_path, "w", encoding="utf-8") as out_f:
        out_f.write(content)
    print(f"Wrote {out_path} ({len(content)} chars)")
