# Version 1.3
#   change_log:
#   - added slave notion
#   - added the posibility to check only 1 mod via the command line
#
# TODO for next release : 
#   - on first printed mods list add info if mod is conflicting
#   - log conflicts by file extension
#   - use a file named accepted_key_conflict.txt which will contain accepted minor key conflicts : (rel_path, key) | mod_file1 | mod_file2 | ...
#   - build a database, instead of a log_buffer

import os, sys, re, sqlite3
import time, threading
from collections import defaultdict, Counter
from urllib.parse import quote
from typing import Any, Dict, List, Set

# === PATHS ===
LAUNCHER_DB_PATH = os.path.expanduser(r"~\Documents\Paradox Interactive\Crusader Kings III\launcher-v2.sqlite")
MODS_DIR_LOCAL = os.path.expanduser(r"~\Documents\Paradox Interactive\Crusader Kings III\mod")
GAME_DIR = r"H:\SteamLibrary\steamapps\common\Crusader Kings III\game"
OUTPUT_LOG_FILE = "ck3_mod_conflicts_report.log"
EXCEPTION_FILE = "CK3_conflicts_exception.txt"
DEFINE_FILE = "CK3_define_files.txt"
PATCH_FILE = "CK3_mod_patches.txt"
RELPATH_EXCEPTION_FILE = "CK3_conflicts_relpath_exception.txt"

# size of tabulation for logs
TAB_SIZE = 3

def make_conflict_entry():
    return {
        "is_flat": False,
        "keys": defaultdict(lambda: defaultdict(dict))
    }

conflict_datas = defaultdict(  # ext
    lambda: defaultdict(        # rel_path
        lambda: defaultdict(    # conflict_group_id
            make_conflict_entry
        )
    )
)

def add_conflict(ext, rel_path, conflict_counter, keys, mod_file, file, is_gfo, is_master, is_slave, is_flat):
    entry = conflict_datas[ext][rel_path][conflict_counter]
    entry["is_flat"] = is_flat
    entry["keys"].setdefault(tuple(keys), {}).setdefault(mod_file, {})[file] = (is_gfo, is_master, is_slave)

def has_mod_file(mod_file):
    for ext_dict in conflict_datas.values():
        for rel_path_dict in ext_dict.values():
            for conflict_entry in rel_path_dict.values():
                keys_dict = conflict_entry["keys"]
                for keys_tuple in keys_dict:
                    if mod_file in keys_dict[keys_tuple]:
                        return True
    return False


# level of merge :
#  (-1) no merge
#   (0) simple merge (copy/override files)
#   (1) intelligent copy (push master keys in a copy of original file and new mod keys in a new mod.txt file)
create_merged_mod = -1
merged_mod_name = "merged_mod"
merged_mod_tags = "Gameplay"

# file extensions to process
EXT_FILES = ["txt", "gui", "font"]#, "dds"]
FLAT_CONFLICT_FILES = ["gui", "font"]#, "dds"]

# === REGEX FOR KEY EXTRACTION ===
# TODO: create a PATTERN rules by file extension (example: '.yaml' file use a different rule than '.txt' files)
SPECIFIC_CONFLICT_RULES = {
    ("rel_path_0", "file_ext_0", r'reg_exp_0'),
    ("rel_path_1", "file_ext_1", r'reg_exp_1')
}

KEY_PATTERN = re.compile(r'^([a-zA-Z0-9_]+)\s*=\s*\{')
SUBKEY_PATTERN = re.compile(r'^\t([a-zA-Z0-9_]+)\s*=')

# === UTIL FUNCTIONS
def color_text(text, color="white", bright=False):
    colors = {
        "black": 30,
        "red": 31,
        "green": 32,
        "yellow": 33,
        "blue": 34,
        "magenta": 35,
        "cyan": 36,
        "white": 37
    }
    
    if color not in colors:
        raise ValueError(f"Unknown color: {color}")
    
    code = colors[color]
    if bright:
        code += 60  # turns standard color into bright variant
    
    return f"\033[{code}m{text}\033[0m"

# === FUNCTION TO LOAD EXCEPTIONS ===
def load_exceptions():
    exceptions = set()
    if os.path.exists(EXCEPTION_FILE):
        with open(EXCEPTION_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if line.endswith(".mod"):
                    exceptions.add(line)
    return exceptions
    
def load_defines():
    defines = set()
    if os.path.exists(DEFINE_FILE):
        with open(DEFINE_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Normalize path separators
                normalized_path = line.replace('/', '\\')
                defines.add(normalized_path)
    return defines

# === FUNCTION TO LOAD RELPATH EXCEPTIONS ===
def load_relpath_exceptions():
    exceptions = set()
    if os.path.exists(RELPATH_EXCEPTION_FILE):
        with open(RELPATH_EXCEPTION_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Normalize path separators
                normalized_path = line.replace('/', '\\')
                exceptions.add(normalized_path)
    return exceptions

# === FUNCTION TO LOAD MOD PATCH RELATIONSHIPS ===
def load_mod_patches():
    patch_relations = defaultdict(set)
    all_originals = set()

    if os.path.exists(PATCH_FILE):
        with open(PATCH_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                parts = [part.strip() for part in line.split('|')]
                if len(parts) < 2:
                    continue

                original = parts[0]
                patches = parts[1:]

                if not os.path.join(MODS_DIR_LOCAL, original):
                    print(f"  ⚠️ mod file (from CK3_mod_patches.txt): '{original}' does not exist !!!")
                    continue
                
                for patch in patches:
                    if patch:
                        if os.path.join(MODS_DIR_LOCAL, patch):
                            patch_relations[patch].add(original)
                            all_originals.add(original)
                        else:
                            print(f"  ⚠️ patch file (from CK3_mod_patches.txt): '{patch}' does not exist !!!")

    return patch_relations, all_originals

# === DATABASE QUERY TO GET MODS FROM ACTIVE PLAYSET ===
def get_mods_from_active_playset():
    conn = sqlite3.connect(LAUNCHER_DB_PATH)
    cur = conn.cursor()

    # Step 1: Get active playset
    cur.execute("SELECT id, name FROM playsets WHERE isActive = 1")
    playset = cur.fetchone()
    if not playset:
        print("❌ No active playset found")
        return [], ""

    playset_id, playset_name = playset
    print(f"🔍 Active playset: \"{playset_name}\" (ID: {playset_id})")

    # Step 2: Get mods in playset
    cur.execute("""
        SELECT pm.modId, pm.position + 1 AS position_plus_one, m.displayName, m.gameRegistryId
        FROM playsets_mods pm
        JOIN mods m ON pm.modId = m.id
        WHERE pm.playsetId = ? AND pm.enabled = 1
        ORDER BY pm.position ASC
    """, (playset_id,))

    mods = cur.fetchall()
    conn.close()

    return mods, playset_name

# === BUILD THE CONFLICT REPORT
def build_conflicts_report(log_content, mod_info, relpath_exceptions):
    # loop over file extensions
    for ext_file, conflict_groups in conflict_datas.items():
        acc_open = '{'
        log_content.append(f"\n{acc_open}📁 file extension: {ext_file}")
        # loop over paths
        for rel_path, conflict_group_ids in conflict_groups.items():
            acc_open = '{'
            log_content.append(f"\n\t{acc_open}📁 Path: {rel_path}")
            # loop over conflict_groups
            for conflict_counter, entry in conflict_group_ids.items():
                acc_open = '{'
                conflict_num = str(conflict_counter).zfill(5)  # Format to 5 digits
                is_flat = entry["is_flat"]
                keys_dict = entry["keys"]
                # loop over keys conflicts
                for keys, mod_files in keys_dict.items():
                    keys_empty = False
                    if is_flat or rel_path in relpath_exceptions:
                        keys_empty = True
                        keys_log = ""
                    else:
                        keys_log = ": " + ", ".join([("'" + k.replace("=", " → ") + "'") for k in keys ])
                    log_content.append(f"\n\t\t{acc_open}⚠️ ({conflict_num}) Conflict on{'' if keys_empty or len(keys)==1 else (' ' + str(len(keys)))} {('key' + ('(and subkey)' if any('=' in k for k in keys) else '')) if keys_log else 'filename(s):'}{'s' if keys_log and len(keys)>1 else ''}" + keys_log)
                    log_content.append("\t\t\tMods involved:")
                    gfo_files = set()
                    # loop over mods
                    for mod_file, files_dict in mod_files.items():
                        for file, (is_gfo, is_master, is_slave) in files_dict.items():
                            # Now you have all the data for this record
                            line = f"\t\t\t- [{mod_info[mod_file]['position']}] {mod_file} | {mod_info[mod_file]['name']} | File: {file}"
                            if is_gfo:
                                gfo_files.add(file)
                                if is_slave:
                                    line += " 📁GFO(slave)"
                                else:
                                    line += " 📁GFO"
                            if is_master:
                                line += " ✅(Master)"
                            
                            # Mod file path
                            fpath = os.path.join(mod_info[mod_file]["path"], rel_path, file)
                            line += "\n\t\t\t\t\t>> File path: file:///" + quote(fpath.replace("\\", "/"), safe=":/")
                            log_content.append(line)
                    if gfo_files:
                        log_content.append("")
                        log_content.append("\t\t\t📁 Game files involved in conflict (key(s) or file overwritten):")
                        for f in sorted(list(gfo_files)):
                            base_path = get_base_game_file_path(rel_path, f)
                            log_content.append("\t\t\t\t\t>> " + "file:///" + quote(base_path.replace("\\", "/"), safe=":/"))
                    log_content.append("\t\t}")
            log_content.append("\n\t}")
        log_content.append("\n}")

# === FUNCTION TO PARSE .mod FILE AND GET PATH ===
def parse_mod_file(mod_file_name, local_mod_dir):
    mod_path = os.path.join(local_mod_dir, mod_file_name)
    if not os.path.exists(mod_path):
        return None, None

    path = None
    remote_id = None

    try:
        with open(mod_path, 'r', encoding='utf-8-sig') as f:
            for line in f:
                line = line.strip()
                if line.startswith("path="):
                    path = line.split("=", 1)[1].strip('"')
                elif line.startswith("remote_file_id="):
                    remote_id = line.split("=", 1)[1].strip('"')
            
    except Exception as e:
        print(f"⚠️ Error reading {mod_file_name}: {e}")

    return path, remote_id

# === CHECK IF FILE OVERWRITES A GAME FILE ===
def is_game_file_overwrite(rel_path, file_name):
    game_file_path = os.path.join(GAME_DIR, rel_path, file_name)
    return os.path.exists(game_file_path)

# === GET BASE GAME FILE PATH ===
def get_base_game_file_path(rel_path, file_name):
    return os.path.join(GAME_DIR, rel_path, file_name)

# === EXTRACT DEFINED KEYS FROM EXT_FILES ===
def extract_defined_keys_from_mod(mod_name, mod_file, full_mod_path, key_mod_map, relpath_exceptions, definition_files):
    if not os.path.isdir(full_mod_path):
        print(f"⚠️ Mod folder not found: {full_mod_path}")
        return
    
    ext_files = tuple('.'+str(f) for f in EXT_FILES)
    ruled_ext_files = tuple('.'+str(f) for f in FLAT_CONFLICT_FILES)
    for root, _, files in os.walk(full_mod_path):
        for file in files:
            if file.lower().endswith(ext_files):
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(os.path.dirname(file_path), full_mod_path)
                if rel_path in relpath_exceptions:
                    ex_key = '{'+file
                    is_gfo = is_game_file_overwrite(rel_path, file)
                    key_id = (rel_path, file, ex_key)
                    key_mod_map[key_id].append((mod_file, mod_name, is_gfo))
                    continue
                if file.lower().endswith(ruled_ext_files):
                    relpath_exceptions.add(rel_path)
                    ex_key = '{'+file
                    is_gfo = is_game_file_overwrite(rel_path, file)
                    key_id = (rel_path, file, ex_key)
                    key_mod_map[key_id].append((mod_file, mod_name, is_gfo))
                    continue
                try:
                    with open(file_path, 'r', encoding='utf-8-sig', errors='ignore') as f:
                        cur_match_1 = ""
                        definition_file = False
                        if rel_path.startswith(tuple(definition_files)):
                            definition_file = True
                        for line in f:
                            line = line.strip('\n')
                            match_1 = KEY_PATTERN.match(line)
                            match_2 = ""
                            if match_1 and match_1 != cur_match_1:
                                cur_match_1 = match_1
                            if definition_file and not match_1:
                                match_2 = SUBKEY_PATTERN.match(line)
                            register_key = False
                            if definition_file and match_2 and cur_match_1:
                                key = cur_match_1.group(1) + "=" +  match_2.group(1)
                                register_key = True
                            if not definition_file and match_1:
                                key = match_1.group(1)
                                register_key = True
                            if register_key:
                                key_id = (rel_path, file, key)
                                is_gfo = is_game_file_overwrite(rel_path, file)
                                key_mod_map[key_id].append((mod_file, mod_name, is_gfo))
                except Exception as e:
                    print(f"⚠️ Error reading {file}: {e}")

def extract_keys_from_game(relpath_exceptions, definition_files):
    if not os.path.isdir(GAME_DIR):
        print(f"⚠️ Game folder not found: {GAME_DIR}")
        return None
    
    ext_files = tuple('.'+str(f) for f in EXT_FILES)
    ruled_ext_files = tuple('.'+str(f) for f in FLAT_CONFLICT_FILES)
    keys_game = defaultdict()
    for root, _, files in os.walk(GAME_DIR):
        for file in files:
            if file.endswith(ext_files):
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(os.path.dirname(file_path), GAME_DIR)
                if rel_path in relpath_exceptions:
                    ex_key = (rel_path, '{'+file)
                    if ex_key not in keys_game:
                       keys_game[ex_key] = file
                    continue
                if file.lower().endswith(ruled_ext_files):
                    relpath_exceptions.add(rel_path)
                    ex_key = (rel_path, '{'+file)
                    if ex_key not in keys_game:
                       keys_game[ex_key] = file
                    continue
                try:
                    with open(file_path, 'r', encoding='utf-8-sig', errors='ignore') as f:
                        cur_match_1 = ""
                        definition_file = False
                        if rel_path.startswith(tuple(definition_files)):
                            definition_file = True
                        for line in f:
                            line = line.strip('\n')
                            match_1 = KEY_PATTERN.match(line)
                            match_2 = ""
                            if match_1 and match_1 != cur_match_1:
                                cur_match_1 = match_1
                            if definition_file and not match_1:
                                match_2 = SUBKEY_PATTERN.match(line)
                            register_key = False
                            if definition_file and match_2 and cur_match_1:
                                key = cur_match_1.group(1) + "=" +  match_2.group(1)
                                register_key = True
                            if not definition_file and match_1:
                                key = match_1.group(1)
                                register_key = True
                            if register_key:
                                keys_game[(rel_path, key)] = file
                except Exception as e:
                    print(f"⚠️ Error reading {file}: {e}")
    return keys_game

# === FUNCTION TO CHECK IF CONFLICT IS FAKE (PATCH OF ORIG) ===

def conflict_is_covered(
        mod_files_list: List[str],
        patch_relations: Dict[str, List[str]],
        mod_info: Dict[str, Dict[str, Any]],
        all_known_originals: Set[str]
    ) -> bool:
    """
    Return True if the conflict is considered covered, defined by:
      1) If mod_files_list has 0 or 1 entries → covered (True).
      2) Otherwise, every file in mod_files_list:
         a) participates in at least one patch<-->original edge;
         b) the induced sub‑graph is fully connected;
         c) for each patch→original, patch.position > original.position.

    Parameters
    ----------
    mod_files_list : List[str]
        Filenames (originals and patches) that conflict on the same key.
    patch_relations : Dict[str, List[str]]
        Mapping from each patch filename to the list of originals it patches.
    mod_info : Dict[str, Dict[str, Any]]
        Metadata per filename; must include mod_info[name]["position"] as int.

    Returns
    -------
    bool
        True if the conflict is “covered” (complete and correctly ordered).
    """
    # Dedupe and handle trivial cases
    mod_files: Set[str] = set(mod_files_list)
    if len(mod_files) <= 1:
        return True

    # Adjacency for connectivity
    adjacency: Dict[str, Set[str]] = {m: set() for m in mod_files}
    all_known_originals = {m for mods in patch_relations.values() for m in mods }

    for patch, originals in patch_relations.items():
        if patch not in mod_files:
            continue  # patch not involved in this conflict

        patch_pos = mod_info[patch]["position"]

        # Track if at least one original is present
        valid_link_found = False

        for orig in originals:
            if orig not in mod_files:
                continue  # skip, but don't fail yet

            orig_pos = mod_info[orig]["position"]
            if orig_pos >= patch_pos:
                return False  # patch must load after original

            # Link is valid
            valid_link_found = True
            adjacency[patch].add(orig)
            adjacency[orig].add(patch)

        if not valid_link_found:
            if patch not in all_known_originals:
                return False  # patch not also an original and connected to any original → broken

    # No isolated nodes
    for mod, neighbors in adjacency.items():
        if not neighbors:
            return False

    # Connectivity check
    seen: Set[str] = set()
    stack = [next(iter(mod_files))]
    while stack:
        node = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        stack.extend(adjacency[node] - seen)

    return seen == mod_files

# === MAIN FUNCTION ===
def conflict_manager(mod_check):
    if mod_check:
         print(f'🚴🏼 We will check conflict for mod: "{mod_check}"\n')
    
    print("🚴🏼 Loading active playset mods...")
    mods_data, playset_name = get_mods_from_active_playset()
    if not mods_data:
        print("❌ No enabled mods found in active playset.")
        return

    # fast check for the mod_check passed to the script if any
    if mod_check:
        if not any(mod_check.strip().lower() == m.strip().lower() for _, _, m, _ in mods_data):
            print(f'❌ mod: "{mod_check}" is not in this playset.')
            return 

    print(" ")
    print("🚴🏼‍ Loading subfolder exceptions...")
    relpath_exceptions = load_relpath_exceptions()

    print("🚴🏼‍ Loading game keys...")
    keys_definitions = load_defines()
    keys_game = extract_keys_from_game(relpath_exceptions, keys_definitions)

    print("🚴🏼‍ Loading patches...")
    patch_relations, all_originals = load_mod_patches()

    print("🚴🏼‍ Loading mod exceptions...")
    exceptions = load_exceptions()

    print(" ")
    print(f"✅  Found {len(mods_data)} enabled mods")
    print(f"✅  {len(exceptions)} mods in exception list")
    print(f"✅  {len(relpath_exceptions)} relative paths in exception list")
    print(f"✅  {sum(len(v) for v in patch_relations.values())} patch relationships loaded\n")

    print("🚴🏼‍ Calculating conflicts...\n")
    
    key_mod_map = defaultdict(list)
    mod_info = defaultdict()

    # Load mod info and extract gameplay keys
    mod_list = defaultdict(list)
    log_content = []
    print_pool= []
    for mod_id, position, mod_name, registry_id in mods_data:
        if not registry_id or not registry_id.endswith(".mod"):
            continue

        mod_file = registry_id.replace("mod/", "").strip()
        mod_path, remote_id = parse_mod_file(mod_file, MODS_DIR_LOCAL)

        if not mod_path or not os.path.isdir(mod_path):
            print(f"⚠️ Mod folder not found: {mod_path}")
            continue

        mod_info[mod_file] = {
            "name": mod_name,
            "path": mod_path,
            "position": position
        }

        if mod_file in exceptions:
            mod_list[position] = (mod_name, mod_file, True)
            continue
        mod_list[position] = (mod_name, mod_file, False)
        
        extract_defined_keys_from_mod(mod_name, mod_file, mod_path, key_mod_map, relpath_exceptions, keys_definitions)

    # Group conflicts by (rel_path, key) -> (mod_file, file, mod_name, is_gfo)
    conflict_groups_by_key = defaultdict(list)

    for (rel_path, file, key), entries in key_mod_map.items():
        for mod_file, mod_name, is_gfo in entries:
            conflict_groups_by_key[(rel_path, key)].append((mod_file, file, mod_name, is_gfo))

    # === DETECT CONFLICTS WITH BUFFERING ===
    log_content += [
        "=== CK3 MOD CONFLICT REPORT ===",
        f"Active Playset: {playset_name}",
        "",
        "📌 Legend:",
        " - GFO = Game File Overwrite (this mod file overwrites a base game file)",
        " - Master = This mod takes precedence due to load order or file naming",
        " - slave = This is the last mod overwriting a game file"
    ]

    total_conflicts = 0
    total_key_conflicts = 0
    current_group = None
    buffered_conflicts = []
    conflict_counter = 1  # Initialize conflict counter
    prev_relpath = ""

    # Sort conflicts by (rel_path, file)
    sorted_conflicts = sorted(
        # filtered_conflicts.items(),
        conflict_groups_by_key.items(),
        key=lambda x: (
            x[0][0],  # rel_path
            tuple(sorted({m[0] for m in x[1]}))  # mod_files
        )
    )

    def build_conflict_datas(buffered_conflicts):
        nonlocal mod_check, total_conflicts, total_key_conflicts
        nonlocal mod_info, conflict_counter, relpath_exceptions, prev_relpath
        total_conflicts += 1
        rel_path_buf  = buffered_conflicts[0][1]
        keys          = {k for (k, _, _, _, _) in buffered_conflicts}
        tmp           = {m for (_, _, l, _, _) in buffered_conflicts for m in l}
        mod_entries_buf = sorted(list(tmp), key=lambda m: (mod_info[m[0]]['position'],m[1]))
        all_files = [m[1] for (_, _, l, _, _) in buffered_conflicts for m in l]
        keys = sorted({k for k in keys})
        conflict_num = str(conflict_counter).zfill(5)  # Format to 5 digits
        if rel_path_buf != prev_relpath:
            prev_relpath = rel_path_buf
        
        if not rel_path_buf in relpath_exceptions:
            total_key_conflicts += len(keys)
            
        len_mod_entries = len(mod_entries_buf)
        master_buf = [False] * len_mod_entries
        slave_buf = [False] * len_mod_entries
        
        last_master = (mod_entries_buf[-1][1], mod_entries_buf[-1][3], len_mod_entries - 1)
        last_slave = -1
        local_file_check = defaultdict()
        for ri, (mod_file, file, mod_name, is_gfo) in enumerate(reversed(mod_entries_buf)):
            i = len_mod_entries - 1 - ri
            if ri == 0 and is_gfo:
                last_slave = i
            elif not is_gfo and last_master[1]:
                last_master = (file, is_gfo, i)
            elif not is_gfo and not last_master[1] and file > last_master[0]:
                last_master = (file, is_gfo, i)
            elif is_gfo and last_slave == -1:
                last_slave = i
        master_buf[last_master[2]] = True
        slave_buf[last_slave] = True

        logged = set() # will be used for gfo_files
        mod_to_add = 0

        prev_file = mod_entries_buf[0][1]
        for i, (mod_file, file, mod_name, is_gfo) in enumerate(mod_entries_buf):
            logged.add(file)
            mod_to_add += 1
            is_master = False
            is_slave = False
            if is_gfo:
                if slave_buf[i]:
                    is_slave = True
            if master_buf[i]:
                is_master = True
            
            # fill database
            ext = os.path.splitext(file)[1][1:]
            is_flat = rel_path in FLAT_CONFLICT_FILES or (len(keys)>0 and keys[0].startswith('{'))
            add_conflict(ext, rel_path, conflict_counter, keys, mod_file, file, is_gfo, is_master, is_slave, is_flat)
            
        if mod_to_add > 0:
            conflict_counter += 1  # Increment counter
           
    # sorted_conflicts: (rel_path, key) -> [(mod_file, file, mod_name, is_gfo), ...]
    for (rel_path, key), mod_entries in sorted_conflicts:

        if len(mod_entries) < 2:
            continue  # No conflict between mods

        # Deduplicate by mod_file
        unique_mods_files = set()
        unique_mods = [m for m in mod_entries if not ((m[0], m[1]) in unique_mods_files or unique_mods_files.add((m[0], m[1])))]

        if len(unique_mods) < 2:
            continue

        mod_files_in_conflict = [m[0] for m in unique_mods]

        # Skip conflict when is covered by patches (in the group)
        if conflict_is_covered(mod_files_in_conflict, patch_relations, mod_info, all_originals):
            continue

        # NEW MASTER MOD DETERMINATION:
        # Prioritize non-GFO files when determining master
        non_gfo_mods = [m for m in unique_mods if not m[3]]
        gfo_mods = [m for m in unique_mods if m[3]]
        
        # If there are non-GFO mods, use them to determine master
        if non_gfo_mods:
            non_gfo_mods.sort(key=lambda x: mod_info[x[0]]["position"])
            master_mod = non_gfo_mods[-1][0]
        # Otherwise use GFO mods
        elif gfo_mods:
            gfo_mods.sort(key=lambda x: mod_info[x[0]]["position"])
            master_mod = gfo_mods[-1][0]
        else:
            # Fallback - should never happen
            unique_mods.sort(key=lambda x: mod_info[x[0]]["position"])
            master_mod = unique_mods[-1][0]

        files = tuple(sorted(list(set((x[1] for x in unique_mods_files)))))
        group_id = (rel_path, files)

        # Flush previous buffer if group changed
        if current_group is not None and group_id != current_group and buffered_conflicts:
            # order list on mod's files' name // build_logs sort also mod_entries on position
            build_conflict_datas(buffered_conflicts) 
            buffered_conflicts.clear()

        # Collect base game files for this conflict
        gfo_files = set()
        for mod_file, file, mod_name, is_gfo in unique_mods:
            if is_gfo:
                base_path = get_base_game_file_path(rel_path, file)
                gfo_files.add(base_path)
            else:
                game_file = keys_game.get((rel_path, key), False)
                if game_file:
                    base_path = get_base_game_file_path(rel_path, game_file)
                    gfo_files.add(base_path)
                
        # Buffer current conflict
        current_group = group_id
        # check if we verify a conflict for a mod_name passed through the command line
        if mod_check and not mod_check.lower() in { m[2].lower() for m in unique_mods }:
            continue
        buffered_conflicts.append((key, rel_path, unique_mods, master_mod, gfo_files))

    # Final flush
    if buffered_conflicts:
        build_conflict_datas(buffered_conflicts) 
        
    # === FLUSH REPORT ===

    print_pool = ["\n🔍 Mods list (❌ = conflict):\n"]
    log_content.append("\n🔍 Mods in conflict:")

    # first flush mod list
    nb_mod_in_conflict = 0
    for position, mod_infos in mod_list.items():
        (mod_name, mod_file, skipped) = mod_infos
        if skipped:
            line = f'\t🚫 Skipping: [{position}] {mod_name} → {mod_file} (see "{EXCEPTION_FILE}")'
            print_pool.append(line)
            continue
        is_conflicting = has_mod_file(mod_file)
        conflict_txt = "✅"
        if is_conflicting:
            nb_mod_in_conflict += 1
            conflict_txt = "❌"
        line = (f"{conflict_txt} [{position}] {mod_name} → {mod_file}")
        print_pool.append('\t' + color_text(line, 'white',True) if is_conflicting else '\t' + line)
        if is_conflicting:
            log_content.append('\t'+line)

    for l in print_pool:
        print(l.expandtabs(TAB_SIZE))

    # build log report
    log_content.append("\n🔍 Detailed report:")
    build_conflicts_report(log_content, mod_info, relpath_exceptions)
    
    # summerize results
    if total_conflicts == 0:
        if mod_check:
            log_content.append('\n✅ No conflicts found for mod: "{mod_check}".')
        log_content.append("\n✅ No conflicts found between mods.\n")
        print("✅ No conflicts found between mods.\n")
    else:
        line = f"\n❌  {nb_mod_in_conflict} mod(s) in conflict."
        print(line)
        log_content.append(line)
        line = f"❌  {total_conflicts} group(s) of conflicts."
        print(line)
        log_content.append(line)
        line = f"❌  {total_key_conflicts} key(s) in conflicts."
        print(line)
        log_content.append(line)

    # === WRITE LOG FILE ===
    try:
        with open(OUTPUT_LOG_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join([l.expandtabs(TAB_SIZE) for l in log_content]))
        print(f"\n📄 Report saved at: {os.path.abspath(OUTPUT_LOG_FILE)}")
    except Exception as e:
        print(f"❌ Failed to write report: {e}")

# === RUN SCRIPT ===
if __name__ == "__main__":
    mod = ""
    if len(sys.argv) > 1:
            mod = sys.argv[1]
    conflict_manager(mod)