# CK3_Conflict_Detection_Script (1.4)
⚠️this is an alpha version: expect inaccurate results in some cases.  

This script detects conflicts between Crusader Kings III mods by comparing files, keys defined in the same relative paths.
It uses CK3 launcher SQL Database to get active playest and get mods list.

## Features
- Detects mod conflicts in CK3 files:
    - by file override:
        * by path rule
        * by file extension rule
    - by game_key (format detection: "game_key = {")
    - by game_key and sub_key :
        * for the moment the processsing of sub_key is raw (format detection: " \tsub_key = {")
- Handles mod patches and exceptions:
    - you can configure list known of mods with patches in order to avoid report conflicts between them
- Shows prevalent informations :
    - overriden game files (GFO)
    - master record (which mod/file/key is accounted)
    - slave file (last overriden game file)
- Generates clickable file links for text editor that support it (ex: Notepad++)
    - you directly open files involved in conflict
- Groups related conflicts together:
    - conflicts are reported by conflict groups regrouping mod file conflicting on a same path/file/key
- report is generated in ck3_mod_conflicts_report.log
    - In Notepad ++, you can explore it more easily using langage based on brackets (view by block) ex: Powershell

## Requirements
- Python 3.10+
- Crusader Kings III with mods installed
- Paradox Launcher
- Not required but preferred :
    - windows terminal (preferred for emoji)
    - notepad++ (tested)

## Setup
1. Install Python
2. Clone this repository:
   git clone https://github.com/yourusername/CK3_Conflict_Detection_Script.git
3. in ck3_mods_conflict.py configure GAME_DIR, example:
   GAME_DIR = r"D:\SteamLibrary\steamapps\common\Crusader Kings III\game"
4. in CK3_mod_patches.txt add mod with its patches (by descriptors, ex: ugc_2220098919.mod), example:  
   \# RICE | RICE + EPE compatch  
   ugc_2273832430.mod | ugc_2553043828.mod
5. in CK3_conflicts_exception.txt add mods that you don't want to be checked for conflicts with (by descriptors, ex: ugc_2220098919.mod), example:
   \# Unofficial CK3 patch  
   ugc_2871648329.mod
6. CK3_conflicts_relpath_exception.txt contain subfolders where only file overriding is needed to check conflict 

## Usage
1. Make active the playset you want to verify conflicts on
2. via a terminal windows laucnh the script: python ck3_mods_conflicts.py

NB: you can also ask the script to detect all conflict for 1 mod only:  
   - python ck3_mods_conflicts.py "name_of_mod"



