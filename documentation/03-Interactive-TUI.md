# ScottyScan -- Interactive TUI System

ScottyScan provides a full-screen, keyboard-navigable Terminal User Interface (TUI) for configuring and launching scans without memorizing CLI parameters. The TUI takes over the terminal, renders menus at fixed screen positions, and supports back-navigation through a state machine so you can revise selections before executing.

---

## Menu System Architecture

### Rendering Engine

The TUI avoids `Write-Host` for menu rendering. Instead, it uses two low-level console primitives:

- **`[Console]::SetCursorPosition(column, row)`** -- Positions the cursor at an absolute screen coordinate.
- **`[Console]::Write(string)`** -- Writes text at the current cursor position without appending a newline.

These are wrapped in the `Write-LineAt` helper function, which:

1. Takes a row number, text string, foreground color, and background color.
2. Truncates text that exceeds console width (leaving the rightmost column empty to prevent wrapping).
3. Pads shorter text to full width to overwrite any previous content on that row.
4. Sets cursor position, writes the padded text with the specified colors, then restores the original colors.

This approach produces scroll-free rendering -- the terminal never scrolls, and any row can be updated independently without affecting other rows.

### Console Host Detection

The TUI checks whether it is running in a real console host (not PowerShell ISE or a non-interactive session). If a real console is not detected, all menus fall back to a simpler text-based input mode using `Write-Host` and `Read-Host`. This ensures ScottyScan remains functional in environments that do not support cursor positioning.

### Cursor Visibility

The TUI hides the blinking cursor during menu rendering (`[Console]::CursorVisible = $false`) and restores it when exiting each menu via a `try/finally` block.

### Critical Rule: No Write-Host During TUI Rendering

Never call `Write-Host` (or `Write-Log` without the `-Silent` switch) inside a rendering loop that uses `Write-LineAt`. `Write-Host` outputs text at the current cursor position and advances the cursor, which corrupts the fixed-position display layout. During TUI sections, all logging must use `Write-Log -Silent` to write to the log file only.

---

## Keyboard Controls

All TUI menus share a consistent keyboard interface:

| Key | Action | Context |
|-----|--------|---------|
| Arrow Up | Move highlight cursor up (wraps to bottom at top) | All menus |
| Arrow Down | Move highlight cursor down (wraps to top at bottom) | All menus |
| Space | Toggle checkbox on/off (multi-select) or select radio option (single-select) | Selection menus |
| Enter | Confirm current selection and proceed to next step | All menus |
| Escape | Go back to previous step, or exit at first menu | All menus |
| A | Select all items | Multi-select menus only |
| N | Deselect all items | Multi-select menus only |

### Menu Types

**Single-select menus** (radio-button style): Only one item can be selected at a time. Moving the cursor and pressing Enter confirms the highlighted item. The currently selected item is marked with `(*)`.

**Multi-select menus** (checkbox style): Multiple items can be toggled independently with Space. Enter confirms the current set of selections. Selected items are marked with `[X]`, unselected with `[ ]`.

Multi-select menus with the `AllowSelectAll` flag prepend two action buttons at the top of the item list:

- `>> Select ALL` -- Selects every item in the menu.
- `>> Select NONE` -- Deselects every item.

These action buttons are navigable rows -- highlight them and press Space or Enter to trigger the bulk action.

### Scroll Support

When a menu has more items than fit on screen, the visible window scrolls as the cursor moves beyond the edges. Scroll indicators appear above and below the item list:

- `^` at the top when items are scrolled out of view above.
- `v` at the bottom when items are scrolled out of view below.

The number of visible rows is calculated dynamically from the console height.

### Pre-Selection

Menu items can be pre-selected based on the last saved configuration. When a menu opens, the cursor is positioned on the first pre-selected item so that pressing Enter immediately confirms the previous choices. For single-select menus, if nothing is pre-selected, the first item is auto-selected.

---

## State Machine Flow

The interactive TUI is implemented as a `while` loop over a `$step` variable that ranges from 1 to 8. Each step corresponds to one screen of the configuration process. Pressing Escape decrements the step (navigating backward), and confirming a selection increments it (navigating forward).

### Step 1: Mode Selection

**Menu type:** Single-select (radio)

**Options:**
- Network Scan -- Discover hosts on CIDRs and scan for vulnerabilities
- List Scan -- Scan specific hosts from a file
- Validate -- Validate OpenVAS findings against live hosts

**Navigation:**
- Enter = proceed to Step 2
- Escape = exit ScottyScan

The Escape hint on this menu displays in red (`Esc=Exit`) since it is the root menu and pressing Escape exits the program entirely. All subsequent menus display `Esc=Back` in gray.

**Pre-selection:** Defaults to the mode used in the last run (stored in `scottyscan.json` as `LastMode`).

### Step 2: Plugin Selection

**Menu type:** Multi-select (checkbox) with Select All / Select None

**Options:**
- Software Version Check (special entry, internal value `__SoftwareVersionCheck__`)
- All loaded plugins from the `plugins/` directory (e.g., DHEater-TLS, DHEater-SSH, SSH1-Deprecated, 7Zip-Version)

**Navigation:**
- Enter = proceed to Step 3 (if Software Version Check is selected) or Step 5 (if not)
- Escape = back to Step 1

**Pre-selection:** Defaults to plugins selected in the last run (stored in `scottyscan.json` as `DefaultPlugins`). If no previous selection exists, all plugins are pre-selected.

### Step 3: Flag Rules Configuration (conditional)

This step only appears if "Software Version Check" was selected in Step 2 and the mode is not Validate.

**Menu type:** Single-select (radio)

**Options:**
- Load from file -- Opens a file prompt to select a flag rules CSV
- Enter manually -- Prompts for pattern, version rule, and label inputs
- Use saved rules -- Loads rules from `scottyscan.json` (only shown if saved rules exist)
- Skip -- Proceed without flag rules

**Navigation:**
- Enter = proceed to Step 4
- Escape = back to Step 2

**Flag rules file format:** CSV with one rule per line, columns `pattern,versionrule,label`:

```
*notepad*,<8.9.1,CVE-2025-15556
*7-zip*,<24.9.0,CVE-2024-11477
*putty*,<0.82,CVE-2024-31497
*flash*,*,EOL software
```

Version operators in files use symbolic notation: `<`, `<=`, `>`, `>=`, `=`, `!=`, `*`. The CLI uses text operators: `LT`, `LE`, `GT`, `GE`, `EQ`, `NE`, `*`.

### Step 4: Credential Prompt (conditional)

This step only appears if "Software Version Check" was selected in Step 2.

Prompts for credentials to use when connecting to remote Windows hosts via WMI, PSRemoting, or Remote Registry. If skipped, the current session credentials (domain account) are used.

**Navigation:**
- Enter = proceed to Step 5
- Escape = back to Step 3 (if flag rules were shown) or Step 2 (if not)

### Step 5: Output Selection

**Menu type:** Multi-select (checkbox) with Select All / Select None

**Options:**
- Master CSV -- All findings in a single CSV file
- Summary Report -- Human-readable text report
- Per-Plugin CSVs -- One CSV per plugin
- Discovery CSV -- Host discovery results (IP, hostname, OS, TTL, open ports)

**Navigation:**
- Enter = proceed to Step 6
- Escape = back to Step 4 (or Step 2/3 depending on whether Software Version Check was selected)

**Pre-selection:** Defaults to outputs selected in the last run.

### Step 6: Settings

**Menu type:** Single-select with in-place editing

**Options:**
- Max threads: (current value) -- Select to change
- Timeout (ms): (current value) -- Select to change
- Discovery ports: (current value) -- Select to change
- Continue with current settings -- Proceed without changes

When "Max threads" or "Timeout (ms)" is selected, a text prompt appears for entering a new value. When "Discovery ports" is selected, a sub-menu offers:

- All ports (1-65535)
- Top 100 enterprise ports
- Plugin recommended ports (shows the union of all selected plugins' ScanPorts with count)
- Custom port list (prompts for comma-separated port numbers)

**Navigation:**
- Selecting "Continue with current settings" = proceed to Step 7
- Escape = back to Step 5

**Pre-selection:** Defaults to settings from the last run. If only Software Version Check is selected with no vulnerability plugins, ports automatically default to management ports only (135, 445, 5985, 5986).

### Step 7: Mode-Specific Input

The content of this step varies by the mode selected in Step 1:

**Scan mode:** Offers a choice between reusing a previous Discovery CSV (if one exists in the output directory) or entering new CIDRs. If entering CIDRs, uses the file prompt TUI with CIDR history.

**List mode:** File prompt for selecting a host list file.

**Validate mode:** File prompt for selecting an OpenVAS CSV file.

See the "File Input Prompt" section below for details on the file selection TUI.

**Navigation:**
- Enter (after providing input) = proceed to Step 8
- Escape = back to Step 6

### Step 8: Confirmation Screen

Displays a full-screen summary of all selections:

```
==========================================
READY TO EXECUTE
==========================================

Mode:      Network Scan
Plugins:   DHEater-TLS, DHEater-SSH, SSH1-Deprecated
SW Check:  3 flag rules loaded
Creds:     DOMAIN\admin
Outputs:   Master CSV, Summary Report, Per-Plugin CSVs
Threads:   20
Timeout:   5000ms
Ports:     All ports (1-65535)
Input:     CIDRs: 192.168.100.0/24, 192.168.101.0/24

Enter=Execute  Esc=Back
```

**Navigation:**
- Enter = begin scan execution
- Escape = back to Step 7

---

## File Input Prompt (Show-FilePrompt)

The file input prompt uses a two-panel TUI layout for selecting input files (host lists, OpenVAS CSVs, CIDR files, flag rule files).

### Layout

**Right panel (default):** Displays the last 5 file paths used for this input type, drawn from the history stored in `scottyscan.json`. Each history entry is a navigable row. Use Arrow Up/Down to highlight a path and Enter to select it. Long paths are truncated with `...` prefix to fit the console width.

**Left panel (via Left arrow):** Provides two actions:
- **Browse for file...** -- Opens a Windows file picker dialog.
- **Type manually...** -- Drops to a text prompt where you can type or paste a full file path.

### Navigation

| Key | Action |
|-----|--------|
| Arrow Up/Down | Move highlight within the current panel |
| Left Arrow | Switch from the history panel to the actions panel |
| Right Arrow | Switch from the actions panel back to the history panel |
| Enter | Select the highlighted item (history path or action) |
| Escape | Cancel and go back to the previous step |

### History Persistence

File paths are stored per input type in `scottyscan.json`. Each time a file is selected, it is added to the front of the history list (most recent first). The list is capped at 5 entries. If the history is empty when the prompt opens, the TUI starts on the actions panel instead.

### Fallback Mode

When running outside a real console host, the file prompt falls back to a simple text-based interface:

```
Type path, 'browse' for file picker, Enter for last used, empty to go back
```

---

## Real-Time Console Output During Scanning

Once the TUI menus are complete and execution begins, the console switches from TUI mode to real-time output mode. The cursor is restored, `Clear-Host` resets the screen, and the banner is redrawn.

### Discovery Phase Display

During host discovery, a fixed-position 15-row display block is rendered using `Write-LineAt`. The block is anchored to a specific screen row and redrawn every 250 milliseconds. It never scrolls -- each row is overwritten in place.

**Display layout (15 rows total):**

| Rows | Content |
|------|---------|
| 1-6 | **Host results window** -- Shows the last 6 discovery results. Each entry shows the host counter, IP address, status (ALIVE/no response), open port count, OS guess, and hostname. Alive hosts are green, dead hosts are dark gray. |
| 7 | **Port window header** -- Shows the total count of open ports found so far (e.g., `-- Open ports (47 found) --`). |
| 8-13 | **Open port discoveries window** -- Shows the last 6 port discoveries as `[*] 192.168.100.10:443` entries in cyan. |
| 14 | **Spinner / status line** -- Animated spinner with progress: host count, number still scanning, total open ports found, current port range percentage, and elapsed time. Example: `/ [14/254 hosts] 3 scanning 47 ports found -- ports 2001-4000 (6%) elapsed 01:23` |
| 15 | **Hint line** -- `Press [E] to end scan early` |

**Progress reporting from worker threads:** Each RunspacePool worker thread reports its progress via a synchronized hashtable. The main thread polls this hashtable during each redraw cycle to detect newly discovered open ports before the worker has finished all 65535 ports. This provides immediate feedback when a port is found open, even while the full scan continues.

### Early Exit During Discovery

Pressing `[E]` during the discovery phase triggers an early exit sequence:

1. The hint line changes to: `End scan early? Press [Y] to confirm, any other key to continue` (white text on dark red background).
2. If `[Y]` is pressed:
   - All still-running worker threads are stopped.
   - Partial results are harvested from the progress hashtable -- any ports found so far on incomplete hosts are included in the results.
   - Partial hosts are marked with `[~] PARTIAL` (dark yellow) showing the port count and percentage scanned.
   - Hosts with no data yet are marked `[~] SKIPPED (scan ended early)` (dark gray).
   - The display redraws one final time with all partial results.
   - A warning is logged: `Discovery ended early by user. N/M hosts processed, P ports found.`
3. If any other key is pressed, scanning continues normally.

### Plugin Scan Phase Display

During vulnerability scanning (after discovery), the display switches to **scrolling output mode** -- each test result is printed as a new line that scrolls normally (using `Write-Host`, not `Write-LineAt`).

Each completed test prints one line:

```
[1/24] [VULN]  192.168.100.164:3389 (DHEater-TLS) -- DHE cipher accepted: TLS_DHE_RSA_...
[2/24] [FIXED] 192.168.100.165:3389 (DHEater-TLS) -- No DHE cipher response
[3/24] [DOWN]  192.168.100.166:22 (DHEater-SSH) -- TCP connect failed
```

Result indicators and colors:

| Symbol | Result | Color |
|--------|--------|-------|
| `[VULN]` | Vulnerable | Red |
| `[FIXED]` | Remediated | Green |
| `[DOWN]` | Unreachable | Dark Yellow |
| `[ERR]` | Error | Gray |
| `[???]` | Inconclusive | Gray |

Between result lines, a progress spinner runs on the same line (using `\r` carriage return, no newline):

```
/ [3/24 complete] 4 tests running... elapsed 00:15
```

The spinner line is cleared before each new result is printed to prevent visual artifacts. Detail strings longer than 80 characters are truncated with `...` in the console output, but the full untruncated detail is written to the log file.

---

## Config Persistence

All TUI selections are persisted in `scottyscan.json` in the script's root directory. This file is loaded at startup and saved after each successful scan execution.

### Stored Settings

| Key | Type | Description |
|-----|------|-------------|
| `LastMode` | string | Last selected mode (Scan/List/Validate) |
| `DefaultPlugins` | string[] | Last selected plugin names (including `__SoftwareVersionCheck__` if selected) |
| `DefaultOutputs` | string[] | Last selected output format names |
| `DefaultThreads` | int | Last configured thread count |
| `DefaultTimeoutMs` | int | Last configured timeout |
| `DefaultPorts` | string | Last configured port range (empty = all, `top100`, `plugin`, or CSV) |
| `LastOutputDir` | string | Output directory path |
| `SavedFlagRules` | array | Flag rules saved from interactive entry |
| `CIDRHistory` | string[] | Last 5 CIDR inputs (Scan mode) |
| `HostFileHistory` | string[] | Last 5 host file paths (List mode) |
| `CSVHistory` | string[] | Last 5 OpenVAS CSV paths (Validate mode) |
| `FlagFileHistory` | string[] | Last 5 flag rule file paths |

### Behavior

- Menu defaults are pre-populated from the last run's values. The cursor starts on the first pre-selected item so pressing Enter immediately re-confirms previous choices.
- File prompts show the last 5 used paths in the history panel.
- The config file is auto-created on first run if it does not exist.
- Settings from CLI parameters (e.g., `-Threads 50`) override config defaults for that run but do not update the config file unless the scan completes.
