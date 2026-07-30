"""
Proximity-triggered workspace guard driven by the Arduino perimeter sensor.

Listens to the checksummed JSON telemetry stream and reacts to CRITICAL/OVERRIDE
zones by minimizing sensitive windows AND raising a fullscreen animated warning
overlay. The escalation-to-full-lock countdown only advances while the object
is actively in breach range: the moment it retreats, the countdown freezes
(and the overlay switches from a red "breach" pulse to an amber "retreating"
pulse) rather than continuing to run down. Sustained retreat fully restores
everything. Auto-reconnects on cable drops, logs to a rotating file, restores
everything on exit (even on a crash), and supports a manual test hotkey.

Windows-only (uses ctypes.windll). Requires: pip install pyserial
Optional:      pip install keyboard   (enables the manual test hotkey)

Architecture:
    Main thread   -> Tkinter (owns all GUI calls; Tkinter is not thread-safe)
    Worker thread -> serial I/O + breach state machine + OS window control
    Communication -> a single queue.Queue, worker -> GUI, drained on a timer
"""

import atexit
import ctypes
from ctypes import wintypes
import json
import logging
import math
import os
import queue
import sys
import threading
import time
import tkinter as tk
from logging.handlers import RotatingFileHandler

import serial

# --- Configuration -----------------------------------------------------------

CONFIG_PATH = "monitor_config.json"

DEFAULT_CONFIG = {
    "serial_port": "COM3",
    "baud_rate": 9600,
    "log_file": "security_audit.log",
    "log_max_bytes": 1_048_576,       # 1 MB per file
    "log_backup_count": 3,
    "target_app_keywords": ["PowerShell", "Command Prompt", "Arduino", "Visual Studio Code"],
    "required_breach_frames": 2,      # consecutive CR/OV frames before triggering
    "required_clear_frames": 5,       # consecutive SF/AP frames before restoring
    "escalation_seconds": 8,          # cumulative breach time before full OS lock
    "test_hotkey": "ctrl+alt+f9",
    "reconnect_delay_seconds": 3,
    "reconnect_max_delay_seconds": 30,
    "overlay_enabled": True,
    # If no telemetry arrives for this long during a lockdown (broken wire,
    # brownout, etc.), treat it the same as an explicit "out of frame" signal
    # rather than freezing on stale CRITICAL/OVERRIDE state forever.
    "signal_timeout_seconds": 1.5,
    # Attended vs. unattended breach classification: a real security concern
    # is "I stepped away and someone approached," not "I'm leaning in while
    # working." Only escalate to a full lockdown if the machine has ALSO been
    # idle (no keyboard/mouse input) for this long. Set to false to disable
    # and go back to distance-only triggering.
    "require_idle_for_lockdown": True,
    "idle_threshold_seconds": 5.0,
}


def load_config():
    """Load monitor_config.json, creating it with defaults on first run."""
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH) as f:
                user_cfg = json.load(f)
            cfg = DEFAULT_CONFIG.copy()
            cfg.update(user_cfg)
            return cfg
        except (json.JSONDecodeError, OSError) as e:
            print(f"[-] Failed to read {CONFIG_PATH} ({e}); using defaults.")
            return DEFAULT_CONFIG.copy()
    with open(CONFIG_PATH, "w") as f:
        json.dump(DEFAULT_CONFIG, f, indent=2)
    print(f"[+] Created default config at {CONFIG_PATH} — edit it to customize thresholds, port, keywords, etc.")
    return DEFAULT_CONFIG.copy()


def setup_logger(cfg):
    logger = logging.getLogger("security_monitor")
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(
        cfg["log_file"], maxBytes=cfg["log_max_bytes"], backupCount=cfg["log_backup_count"]
    )
    handler.setFormatter(logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    logger.addHandler(handler)
    return logger


def calculate_adler32(payload_string):
    """Mirrors the Arduino's Adler-32 implementation exactly (verified against zlib.adler32)."""
    a, b = 1, 0
    for ch in payload_string:
        a = (a + ord(ch)) % 65521
        b = (b + a) % 65521
    return (b << 16) | a


class _LASTINPUTINFO(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]


def get_idle_seconds():
    """Seconds since the last keyboard/mouse input, system-wide (Windows only)."""
    info = _LASTINPUTINFO()
    info.cbSize = ctypes.sizeof(_LASTINPUTINFO)
    if not ctypes.windll.user32.GetLastInputInfo(ctypes.byref(info)):
        return 0.0  # fail safe: treat as "attended" rather than mis-trigger
    millis_idle = ctypes.windll.kernel32.GetTickCount() - info.dwTime
    return max(0.0, millis_idle / 1000.0)


# --- Win32 window control -----------------------------------------------------

class Win32WindowManager:
    """Minimize/restore target windows by title match, or fall back to a full OS lock."""

    SW_MINIMIZE = 6
    SW_SHOW = 5
    SW_RESTORE = 9

    def __init__(self, keywords):
        self.keywords = keywords
        self.user32 = ctypes.windll.user32

    def _enum_and_apply(self, action):
        matched = []
        EnumWindowsProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

        def callback(hwnd, _lparam):
            if self.user32.IsWindowVisible(hwnd):
                length = self.user32.GetWindowTextLengthW(hwnd)
                if length > 0:
                    buff = ctypes.create_unicode_buffer(length + 1)
                    self.user32.GetWindowTextW(hwnd, buff, length + 1)
                    title = buff.value
                    if any(k.lower() in title.lower() for k in self.keywords):
                        action(hwnd)
                        matched.append(title)
            return True

        self.user32.EnumWindows(EnumWindowsProc(callback), 0)
        return matched

    def minimize_targets(self):
        return self._enum_and_apply(lambda hwnd: self.user32.ShowWindow(hwnd, self.SW_MINIMIZE))

    def restore_targets(self):
        def action(hwnd):
            self.user32.ShowWindow(hwnd, self.SW_RESTORE)
            self.user32.ShowWindow(hwnd, self.SW_SHOW)
            self.user32.SetForegroundWindow(hwnd)
        return self._enum_and_apply(action)

    def lock_workstation(self):
        self.user32.LockWorkStation()


# --- Fullscreen alert overlay (main-thread only) ------------------------------

class AlertOverlay:
    """
    Borderless fullscreen Toplevel that fades in on a breach, pulses a border
    (red while actively breaching, amber while the object is retreating),
    shows live telemetry and an escalation countdown bar, then fades out on
    clear. All animation runs on Tkinter's own `after()` loop so it never
    blocks and stops scheduling itself the moment it's hidden.
    """

    PULSE_PERIOD = 1.6      # seconds for one full pulse cycle
    PULSE_INTERVAL_MS = 33  # ~30 fps, smooth without hogging the CPU
    FADE_STEPS = 14
    FADE_INTERVAL_MS = 15

    ZONE_LABELS = {
        "CR": "CRITICAL", "OV": "OVERRIDE / LUNGE", "AP": "APPROACH",
        "SF": "SAFE", "OF": "OUT OF FRAME",
    }

    BREACH_MSG = "Workspace concealed — monitoring for clear perimeter"
    RETREAT_MSG = "Clear signal detected — hold position to stand down"

    def __init__(self, root):
        self.root = root
        self.visible = False
        self._phase = "breach"
        self._pulse_job = None
        self._pulse_t0 = 0.0

        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()

        self.win = tk.Toplevel(root)
        self.win.overrideredirect(True)
        self.win.attributes("-topmost", True)
        self._set_alpha(0.0)
        self.win.geometry(f"{sw}x{sh}+0+0")
        self.win.configure(bg="#0a0a0a")

        self.canvas = tk.Canvas(self.win, bg="#0a0a0a", highlightthickness=0, width=sw, height=sh)
        self.canvas.pack(fill="both", expand=True)

        self.border_id = self.canvas.create_rectangle(6, 6, sw - 6, sh - 6, outline="#b02020", width=6)

        cx, cy = sw // 2, sh // 2
        self.title_id = self.canvas.create_text(
            cx, cy - 120, text="PERIMETER BREACH", fill="#ff4040", font=("Consolas", 54, "bold")
        )
        self.reason_id = self.canvas.create_text(cx, cy - 55, text="", fill="#ffffff", font=("Consolas", 22))
        self.telemetry_id = self.canvas.create_text(cx, cy + 10, text="", fill="#f0f0f0", font=("Consolas", 20))
        self.sub_id = self.canvas.create_text(
            cx, cy + 65, text=self.BREACH_MSG, fill="#a0a0a0", font=("Consolas", 14)
        )

        bar_w, bar_h = 480, 10
        bar_y = cy + 120
        self._bar_x0 = cx - bar_w // 2
        self._bar_w = bar_w
        self.bar_bg = self.canvas.create_rectangle(
            self._bar_x0, bar_y, self._bar_x0 + bar_w, bar_y + bar_h, fill="#2a2a2a", outline=""
        )
        self.bar_fill = self.canvas.create_rectangle(
            self._bar_x0, bar_y, self._bar_x0, bar_y + bar_h, fill="#ff5050", outline=""
        )
        self.escalation_id = self.canvas.create_text(cx, cy + 150, text="", fill="#ff9090", font=("Consolas", 13))

        self.win.withdraw()

    def _set_alpha(self, alpha):
        try:
            self.win.attributes("-alpha", alpha)
        except tk.TclError:
            pass

    def _get_alpha(self):
        try:
            return float(self.win.attributes("-alpha"))
        except tk.TclError:
            return 0.0

    def show(self, reason):
        self._phase = "breach"
        self.canvas.itemconfig(self.reason_id, text=reason.upper())
        self.canvas.itemconfig(self.telemetry_id, text="")
        self.canvas.itemconfig(self.escalation_id, text="")
        self.canvas.itemconfig(self.sub_id, text=self.BREACH_MSG)
        self.canvas.itemconfig(self.bar_fill, fill="#ff5050")
        bg_coords = self.canvas.coords(self.bar_bg)
        self.canvas.coords(self.bar_fill, self._bar_x0, bg_coords[1], self._bar_x0, bg_coords[3])

        self.win.deiconify()
        self.win.lift()
        self.visible = True
        self._fade(self._get_alpha(), 0.92)
        self._pulse_t0 = time.time()
        self._pulse()

    def hide(self):
        self.visible = False
        if self._pulse_job:
            self.root.after_cancel(self._pulse_job)
            self._pulse_job = None
        self._fade(self._get_alpha(), 0.0, on_done=self.win.withdraw)

    def _fade(self, start, end, on_done=None):
        steps = self.FADE_STEPS

        def step(i=0):
            frac = i / steps
            self._set_alpha(start + (end - start) * frac)
            if i < steps:
                self.root.after(self.FADE_INTERVAL_MS, step, i + 1)
            elif on_done:
                on_done()

        step()

    def set_phase(self, phase):
        """phase: 'breach' (actively in range, counting down) or 'retreating' (paused)."""
        if phase == self._phase:
            return
        self._phase = phase
        if phase == "retreating":
            self.canvas.itemconfig(self.sub_id, text=self.RETREAT_MSG)
            self.canvas.itemconfig(self.bar_fill, fill="#4fd67a")
        else:
            self.canvas.itemconfig(self.sub_id, text=self.BREACH_MSG)
            self.canvas.itemconfig(self.bar_fill, fill="#ff5050")

    def _pulse(self):
        if not self.visible:
            return
        elapsed = time.time() - self._pulse_t0
        phase_frac = (elapsed % self.PULSE_PERIOD) / self.PULSE_PERIOD
        intensity = 0.5 + 0.5 * math.sin(phase_frac * 2 * math.pi)
        if self._phase == "retreating":
            g = int(120 + 70 * intensity)
            color = f"#20{g:02x}60"
        else:
            r = int(160 + 95 * intensity)
            color = f"#{r:02x}2020"
        self.canvas.itemconfig(self.border_id, outline=color)
        self._pulse_job = self.root.after(self.PULSE_INTERVAL_MS, self._pulse)

    def update_telemetry(self, zone, distance, velocity):
        if not self.visible:
            return
        zone_name = self.ZONE_LABELS.get(zone, zone)
        try:
            text = f"Zone: {zone_name}    Dist: {float(distance):.1f} cm    Vel: {float(velocity):.1f} cm/s"
        except (TypeError, ValueError):
            text = f"Zone: {zone_name}"
        self.canvas.itemconfig(self.telemetry_id, text=text)

    def update_escalation(self, seconds_remaining, total_seconds, paused):
        if not self.visible:
            return
        frac = max(0.0, min(1.0, seconds_remaining / total_seconds)) if total_seconds else 0.0
        x0, y0, _, y1 = self.canvas.coords(self.bar_bg)
        self.canvas.coords(self.bar_fill, x0, y0, x0 + self._bar_w * frac, y1)
        if seconds_remaining <= 0:
            self.canvas.itemconfig(self.escalation_id, text="WORKSTATION LOCKED")
        elif paused:
            self.canvas.itemconfig(
                self.escalation_id, text=f"Escalation paused at {seconds_remaining:.1f}s — clear detected"
            )
        else:
            self.canvas.itemconfig(
                self.escalation_id, text=f"Escalating to full lock in {seconds_remaining:.1f}s"
            )

    def destroy(self):
        try:
            self.win.destroy()
        except tk.TclError:
            pass


# --- Worker: serial I/O + breach state machine (background thread) ------------

class SecurityMonitor:
    def __init__(self, cfg, gui_queue):
        self.cfg = cfg
        self.gui_queue = gui_queue
        self.logger = setup_logger(cfg)
        self.window_mgr = Win32WindowManager(cfg["target_app_keywords"])
        self.serial_conn = None
        self.running = True

        self.consecutive_breaches = 0
        self.clear_frame_count = 0
        self.is_lockdown_active = False
        self.escalated = False

        # Escalation only accumulates while actively in a breach zone; it
        # freezes the instant the object retreats, rather than continuing
        # to run down toward a lock while the perimeter is already clearing.
        self.breach_accumulated = 0.0
        self.last_known_zone = None
        self._last_tick_time = 0.0
        self._last_pushed_phase = "breach"
        self._last_escalation_push = 0.0

        self.stats = {
            "session_start": time.time(),
            "total_breaches": 0,
            "total_lockdowns": 0,
            "total_lockdown_seconds": 0.0,
        }
        self._lockdown_wall_start = None
        self.last_packet_time = time.time()
        self._last_attended_notice = 0.0

        atexit.register(self.cleanup)
        self._setup_hotkey()

    # -- setup ---------------------------------------------------------------

    def _setup_hotkey(self):
        try:
            import keyboard
            keyboard.add_hotkey(self.cfg["test_hotkey"], self._manual_trigger)
            print(f"[+] Manual test hotkey armed: {self.cfg['test_hotkey']}")
        except ImportError:
            print("[-] 'keyboard' module not installed; manual test hotkey disabled (pip install keyboard).")

    def _manual_trigger(self):
        print("\n[TEST] Manual hotkey lockdown trigger fired.")
        self.trigger_lockdown("Manual Test Trigger", distance=0, velocity=0, zone="CR")

    def connect_serial(self):
        delay = self.cfg["reconnect_delay_seconds"]
        while self.running:
            try:
                self.serial_conn = serial.Serial(self.cfg["serial_port"], self.cfg["baud_rate"], timeout=1)
                print(f"[+] Interface bound securely to {self.cfg['serial_port']}")
                return
            except serial.SerialException as e:
                print(f"[-] Connection failed ({e}); retrying in {delay}s...")
                time.sleep(delay)
                delay = min(delay * 2, self.cfg["reconnect_max_delay_seconds"])

    # -- alerting / lockdown ---------------------------------------------------

    def trigger_visual_warning(self, reason, distance, velocity):
        try:
            ctypes.windll.user32.MessageBeep(0x00000030)  # MB_ICONWARNING
        except Exception:
            pass
        print("\n" + "=" * 60)
        print(f"\033[91m[!] SECURITY ALERT: {reason.upper()} [!]\033[0m")
        print(f"\033[93m[!] Telemetry -> Distance: {distance} cm | Velocity: {velocity} cm/s\033[0m")
        print(f"\033[91m[!] STATUS: Workspace under active stealth lockdown.\033[0m")
        print("=" * 60 + "\n")

    def trigger_lockdown(self, reason, distance, velocity, zone):
        self.stats["total_breaches"] += 1
        self.trigger_visual_warning(reason, distance, velocity)
        self.logger.info(f"SECURITY BREACH: {reason} | Dist: {distance}cm | Vel: {velocity}cm/s")

        matched = self.window_mgr.minimize_targets()
        for title in matched:
            print(f"[+] Stealth-minimized: {title}")

        self.is_lockdown_active = True
        self.escalated = False
        self.breach_accumulated = 0.0
        self.last_known_zone = zone
        self._last_tick_time = time.time()
        self._last_pushed_phase = "breach"
        self._last_escalation_push = 0.0
        self._lockdown_wall_start = time.time()
        self.stats["total_lockdowns"] += 1

        self.gui_queue.put(("show", reason))

    def escalate_if_needed(self):
        if not self.is_lockdown_active:
            return

        now = time.time()
        dt = now - self._last_tick_time
        self._last_tick_time = now

        breaching = self.last_known_zone in ("CR", "OV")
        if breaching:
            self.breach_accumulated += dt

        new_phase = "breach" if breaching else "retreating"
        if new_phase != self._last_pushed_phase:
            self._last_pushed_phase = new_phase
            self.gui_queue.put(("phase", new_phase))

        remaining = max(0.0, self.cfg["escalation_seconds"] - self.breach_accumulated)
        if now - self._last_escalation_push >= 0.1:  # throttle GUI updates to ~10/sec
            self._last_escalation_push = now
            self.gui_queue.put(("escalation", remaining, self.cfg["escalation_seconds"], not breaching))

        if not self.escalated and breaching and remaining <= 0:
            print("\n[!!!] Breach persisting — escalating to full workstation lock.")
            self.logger.info("ESCALATION: workstation locked")
            self.escalated = True
            self.window_mgr.lock_workstation()

    def clear_lockdown(self):
        self.window_mgr.restore_targets()
        print("\n\033[92m[+] Perimeter clear. Restoring workspace windows...\033[0m")
        if self._lockdown_wall_start:
            self.stats["total_lockdown_seconds"] += time.time() - self._lockdown_wall_start
        self.is_lockdown_active = False
        self.escalated = False
        self.breach_accumulated = 0.0
        self.last_known_zone = None
        self.consecutive_breaches = 0
        self.clear_frame_count = 0
        self.gui_queue.put(("hide",))

    # -- packet handling -------------------------------------------------------

    def handle_packet(self, raw_line):
        if not raw_line.startswith("{") or not raw_line.endswith("}"):
            return

        if '"sys"' in raw_line:
            try:
                sys_data = json.loads(raw_line)
                if sys_data.get("sys") == "ONLINE":
                    print(f"[+] Sensor calibrated. Active range baseline: {sys_data.get('baseline_cm')} cm")
            except json.JSONDecodeError:
                pass
            return

        end_idx = raw_line.find(',"h":')
        if end_idx == -1:
            return
        core_payload = raw_line[raw_line.find('{') + 1:end_idx]

        try:
            full_json = json.loads(raw_line)
        except json.JSONDecodeError:
            return

        if full_json.get("h") != calculate_adler32(core_payload):
            print("\n[!] WARNING: packet checksum mismatch, dropped.")
            return

        zone = full_json.get("z")
        distance = full_json.get("cm")
        velocity = full_json.get("v")
        self.last_packet_time = time.time()

        sys.stdout.write(f"\r[SECURE] Zone: {zone} | Dist: {distance}cm | Vel: {velocity}cm/s   ")
        sys.stdout.flush()

        if self.is_lockdown_active:
            self.last_known_zone = zone
            self.gui_queue.put(("telemetry", zone, distance, velocity))
            self.escalate_if_needed()
            if zone in ("SF", "AP", "OF"):
                self.clear_frame_count += 1
                if self.clear_frame_count >= self.cfg["required_clear_frames"]:
                    self.clear_lockdown()
            elif zone == "CR":
                self.clear_frame_count = max(0, self.clear_frame_count - 1)
            return

        if zone in ("CR", "OV"):
            self.consecutive_breaches += 1
            if self.consecutive_breaches >= self.cfg["required_breach_frames"]:
                if self.cfg["require_idle_for_lockdown"]:
                    idle = get_idle_seconds()
                    if idle < self.cfg["idle_threshold_seconds"]:
                        # Someone's actively at the keyboard - almost certainly the
                        # owner leaning in, not an unattended-machine breach. Log it
                        # quietly (throttled) and don't escalate.
                        now = time.time()
                        if now - self._last_attended_notice >= 3.0:
                            self._last_attended_notice = now
                            print(f"\n[i] Proximity detected but machine attended (idle {idle:.1f}s) — no action.")
                        self.consecutive_breaches = 0
                        return
                reason = "Critical Perimeter Breach" if zone == "CR" else "Predictive Lunge"
                self.trigger_lockdown(reason, distance, velocity, zone)
        elif self.consecutive_breaches > 0:
            self.consecutive_breaches -= 1

    # -- main loop --------------------------------------------------------------

    def run(self):
        self.connect_serial()
        print("[+] Surveillance active. Multi-cycle protection & warning banner engine online.")
        try:
            while self.running:
                try:
                    if self.serial_conn.in_waiting > 0:
                        raw_line = self.serial_conn.readline().decode("utf-8", errors="ignore").strip()
                        self.handle_packet(raw_line)
                    else:
                        if self.is_lockdown_active:
                            # Watchdog: if the Arduino has gone silent (broken wire,
                            # brownout) for too long, don't sit frozen on stale
                            # CRITICAL/OVERRIDE state — treat it as target-lost.
                            if time.time() - self.last_packet_time > self.cfg["signal_timeout_seconds"]:
                                if self.last_known_zone in ("CR", "OV"):
                                    print("\n[!] WARNING: telemetry signal lost — treating as out-of-frame.")
                                self.last_known_zone = "OF"
                            # Still tick the escalation clock even between telemetry
                            # frames, so the countdown/pause reacts within ~10ms,
                            # not the sensor's ~200ms send interval.
                            self.escalate_if_needed()
                        time.sleep(0.01)
                except serial.SerialException:
                    print("\n[-] Serial connection lost; attempting reconnect...")
                    try:
                        self.serial_conn.close()
                    except Exception:
                        pass
                    self.connect_serial()
        except KeyboardInterrupt:
            print("\n[-] Terminating security daemon.")

    # -- shutdown -----------------------------------------------------------------

    def cleanup(self):
        self.running = False
        if self.is_lockdown_active:
            self.clear_lockdown()
        if self.serial_conn and self.serial_conn.is_open:
            self.serial_conn.close()
        self.print_session_summary()

    def print_session_summary(self):
        elapsed = time.time() - self.stats["session_start"]
        print("\n" + "-" * 60)
        print("[SESSION SUMMARY]")
        print(f"  Runtime: {elapsed / 60:.1f} min")
        print(f"  Total breach events: {self.stats['total_breaches']}")
        print(f"  Total lockdowns triggered: {self.stats['total_lockdowns']}")
        print(f"  Total time in lockdown: {self.stats['total_lockdown_seconds']:.1f}s")
        print("-" * 60)
        self.logger.info(
            f"SESSION END | breaches={self.stats['total_breaches']} "
            f"lockdowns={self.stats['total_lockdowns']} "
            f"lockdown_time={self.stats['total_lockdown_seconds']:.1f}s"
        )


# --- GUI event pump (main thread) ---------------------------------------------

def pump_gui_queue(root, overlay, gui_queue, cfg):
    """Drain worker-thread events and apply them to the overlay. Runs on a fixed
    tick on the main thread so all Tkinter calls stay thread-safe."""
    try:
        while True:
            event = gui_queue.get_nowait()
            kind = event[0]
            if kind == "show" and cfg["overlay_enabled"]:
                overlay.show(event[1])
            elif kind == "hide":
                overlay.hide()
            elif kind == "telemetry":
                overlay.update_telemetry(event[1], event[2], event[3])
            elif kind == "escalation":
                overlay.update_escalation(event[1], event[2], event[3])
            elif kind == "phase":
                overlay.set_phase(event[1])
    except queue.Empty:
        pass
    root.after(30, pump_gui_queue, root, overlay, gui_queue, cfg)


def main():
    cfg = load_config()
    gui_queue = queue.Queue()

    root = tk.Tk()
    root.withdraw()  # no visible main window; the overlay is the only UI

    overlay = AlertOverlay(root)
    monitor = SecurityMonitor(cfg, gui_queue)

    worker = threading.Thread(target=monitor.run, daemon=True)
    worker.start()

    root.after(30, pump_gui_queue, root, overlay, gui_queue, cfg)

    try:
        root.mainloop()
    except KeyboardInterrupt:
        pass
    finally:
        monitor.running = False
        overlay.destroy()


if __name__ == "__main__":
    main()
