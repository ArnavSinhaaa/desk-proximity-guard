# desk-proximity-guard

An Arduino + Python system that watches the space in front of your desk and reacts before someone gets close enough to see your screen — minimizing sensitive windows, sounding an alert, and escalating to a full OS lock if the intrusion persists.

Built on an Arduino Uno + HC-SR04 ultrasonic sensor + buzzer, paired with a Python daemon that adds smarter, context-aware decision-making on the PC side.

## What makes this more than a tripwire

- **Adaptive filtering (AEMA)** — smooths noisy ultrasonic readings without lagging behind real motion.
- **Kinematic lunge detection** — tracks velocity/acceleration, not just distance, to catch a fast approach even before it crosses the critical threshold.
- **Median-of-5 sampling + outlier rejection** — a single stray echo (off a monitor, a hand near the desk) gets outvoted instead of triggering a false alarm.
- **Out-of-frame awareness** — the sensor's beam is narrow and one-directional. Stepping outside it is explicitly detected and reported, instead of going silent and leaving the host guessing.
- **Attended vs. unattended threat classification** — the real concern is "I stepped away and someone approached," not "I leaned in to read something." The Python side cross-references real keyboard/mouse idle time before escalating, and pushes that state back to the Arduino so even the physical buzzer stays quiet while you're legitimately at the keyboard.
- **Checksum-verified telemetry** — every serial packet is Adler-32 checksummed; corrupted packets are dropped rather than acted on.
- **Fullscreen animated warning overlay** — a borderless, topmost alert screen that fades in, pulses red while a breach is active, shifts to amber the moment the object retreats, and shows a live escalation countdown.
- **Auto-reconnect, rotating logs, session stats** — built to run unattended for long stretches, not just as a demo.

## Hardware

- Arduino Uno
- HC-SR04 ultrasonic distance sensor
- Piezo buzzer + LED
- Breadboard + jumper wires

See `circuit.png` in this repo for the wiring diagram.

| Component | Arduino Pin |
|---|---|
| HC-SR04 TRIG | 6 |
| HC-SR04 ECHO | 5 |
| Buzzer | 3 |

## Repo contents

- `perimeter_sensor.ino` — Arduino firmware (sensor filtering, zone state machine, buzzer control, serial telemetry/command protocol)
- `security_monitor.py` — Python daemon (serial handling, breach logic, window control, fullscreen overlay)
- `circuit.png` — wiring diagram

## Setup

### Arduino
1. Open `perimeter_sensor.ino` in the Arduino IDE.
2. Wire the circuit per `circuit.png`.
3. Select your board/port and upload.
4. Open the Serial Monitor at **9600 baud** to confirm you see `{"sys":"ONLINE", ...}` after boot calibration.

### Python (Windows only — uses `ctypes.windll` for window control)
```bash
pip install pyserial
pip install keyboard   # optional, enables the manual test hotkey
```

Edit `SERIAL_PORT` in `monitor_config.json` (auto-created on first run) to match your Arduino's COM port, then run:

```bash
python security_monitor.py
```

A `monitor_config.json` file will be created next to the script on first launch with all tunable settings — thresholds, target window keywords, escalation timing, idle-detection settings, etc. Edit it and restart to apply changes.

## How it responds

| Zone | Meaning | Response |
|---|---|---|
| SAFE | Nothing nearby | Idle |
| APPROACH | Object within range | Soft, distance-scaled chime |
| CRITICAL | Very close | Sharp alert + windows minimized (if unattended) |
| OVERRIDE | Fast lunge detected | Same as CRITICAL, triggered early by velocity |
| OUT OF FRAME | Sensor lost target | Treated as clear |

If a CRITICAL/OVERRIDE state persists while the machine is idle, a fullscreen warning overlay appears and an escalation countdown begins. If it isn't cleared in time, the workstation is fully locked.

## Known limitations

- Windows-only (relies on Win32 APIs for window control and workstation locking).
- The ultrasonic sensor has a narrow (~15°) beam — it only covers what's directly in front of it, not the whole room.
- Idle-time correlation isn't perfect: quiet reading with no keyboard/mouse input can eventually register as "away."

## License

MIT — see `LICENSE`.
