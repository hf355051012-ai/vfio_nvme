#!/usr/bin/env python3

#######################################################
# 使い方
#
# 1. 事前準備(1回だけ)
# sudo apt install clang-tools
# pip install compiledb
#
# 2. ソースファイルを追加・削除した時実行
# compiledb make
#
# 3. ツリー表示
# 正引き : ./clang_calltree.py -f -d 2 tcp_recv src/*.c
# 逆引き : ./clang_calltree.py -r -d 4 tcp_recv src/*.c
#
#######################################################

import sys
import subprocess
import re
import argparse
from collections import defaultdict

def get_clang_query_matches(target_files):
    query = 'match functionDecl(forEachDescendant(callExpr(callee(functionDecl().bind("callee"))))).bind("caller")'
    cmd = ["clang-query", "-c", query] + target_files
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing clang-query: {e.stderr}", file=sys.stderr)
        sys.exit(1)
        
    return result.stdout

def parse_output(output_text):
    forward_map = defaultdict(set)
    reverse_map = defaultdict(set)
    file_map = {}
    
    matches = output_text.split("Match #")
    for match in matches:
        if not match.strip():
            continue
            
        lines = match.splitlines()
        caller, callee = None, None
        caller_file, callee_file = None, None
        
        for i, line in enumerate(lines):
            file_match = re.search(r'^([^\s:]+\.[ch]):\d+:\d+:\s*note:\s*"([^"]+)"\s*binds\s*here', line)
            if file_match:
                path = file_match.group(1)
                bind_type = file_match.group(2)
                
                if "src/" in path:
                    path = "src/" + path.split("src/", 1)[1]
                
                if i + 1 < len(lines):
                    decl_line = lines[i + 1]
                    name_match = re.search(r'(\w+)\s*\(', decl_line)
                    if name_match:
                        func_name = name_match.group(1)
                        if bind_type == "caller":
                            caller = func_name
                            caller_file = path
                        elif bind_type == "callee":
                            callee = func_name
                            callee_file = path

        if caller and callee and caller != callee:
            forward_map[caller].add(callee)
            reverse_map[callee].add(caller)
            if caller_file:
                file_map[caller] = caller_file
            if callee_file:
                file_map[callee] = callee_file
            
    return forward_map, reverse_map, file_map

def print_tree(func_name, graph, file_map, max_depth, current_depth=0, prefix="", is_last=True):
    if current_depth > max_depth:
        return
        
    file_info = f" ({file_map[func_name]})" if func_name in file_map else ""
    
    if current_depth > 0:
        marker = "\\- " if is_last else "+- "
        print(f"{prefix}{marker}{func_name}{file_info}")
        prefix += "   " if is_last else "|  "
    else:
        print(f"{func_name}{file_info}")
        
    children = sorted(list(graph.get(func_name, [])))
    for i, child in enumerate(children):
        is_child_last = (i == len(children) - 1)
        print_tree(child, graph, file_map, max_depth, current_depth + 1, prefix, is_child_last)

def main():
    parser = argparse.ArgumentParser(description="Generate program calltree via clang-query AST parsing.")
    
    # モードを排他的なオプションフラグ (-f または -r) に変更
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("-f", "--forward", action="store_true", help="Forward call tree (What does this function call?)")
    mode_group.add_argument("-r", "--reverse", action="store_true", help="Reverse call tree (Who calls this function?)")
    
    # 残りの位置引数
    parser.add_argument("function", help="Target function name to start the graph")
    parser.add_argument("files", nargs="+", help="Source file(s) to analyze (e.g., src/*.c)")
    
    # 深さオプション
    parser.add_argument("-d", "--depth", type=int, default=5, help="Set the depth at which the flowgraph is cut off (default: 5)")

    args = parser.parse_args()
    
    print("Analyzing AST via clang-query... (This may take a moment)")
    raw_output = get_clang_query_matches(args.files)
    forward_map, reverse_map, file_map = parse_output(raw_output)
    
    print(f"\n--- Call Tree (Max Depth: {args.depth}) ---")
    if args.forward:
        print_tree(args.function, forward_map, file_map, max_depth=args.depth)
    elif args.reverse:
        print_tree(args.function, reverse_map, file_map, max_depth=args.depth)

if __name__ == "__main__":
    main()
