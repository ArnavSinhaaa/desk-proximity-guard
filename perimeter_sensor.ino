#define TRIG_PIN 6  
#define ECHO_PIN 5
#define BUZZER_PIN 3 

// --- Calibrated Spatial Parameters ---
float BASELINE_DISTANCE = 400.0; 
float APPROACH_THRESHOLD = 80.0;  
float CRITICAL_THRESHOLD = 25.0;  

// --- Adaptive DSP (AEMA) ---
float filteredDistance = -1.0; 
float MIN_ALPHA = 0.05; 
float MAX_ALPHA = 0.70; 
float DELTA_THRESHOLD = 25.0; 

// --- Kinematic Engine ---
float previousDistance = -1.0;
float currentVelocity = 0.0;
float previousVelocity = 0.0;
float currentAcceleration = 0.0;
unsigned long previousKinematicMillis = 0;
const int KINEMATIC_INTERVAL = 80;   // widened from 50ms - noisy single readings
                                      // over a short window produce wildly
                                      // exaggerated (fake) velocity spikes
const float LUNGE_VELOCITY_THRESHOLD = -160.0; 

// --- Outlier Rejection ---
// A stray reflection can still slip past the median filter occasionally. This
// requires an implausibly large single-cycle jump to repeat on two
// consecutive fresh readings before it's trusted - one-off spikes are ignored
// and the previous (last-good) state is simply reused for that cycle.
const float MAX_INSTANT_JUMP_CM = 60.0;
float lastOutlierCandidate = -1.0;
uint8_t outlierStreak = 0;

// --- FSM Zone Variables ---
// OUT_OF_FRAME: the HC-SR04 has a narrow (~15 deg) unidirectional beam. If the
// object steps outside that cone, or is beyond max range, the sensor returns
// no echo at all. That is NOT the same as "SAFE" (object present, far away) -
// it means the sensor has lost the target entirely. We report it as its own
// zone so the host app can treat it as an explicit, immediate all-clear signal
// rather than silently going quiet and leaving stale state on the other end.
enum SystemZone { SAFE, APPROACH, CRITICAL, OVERRIDE, OUT_OF_FRAME };
SystemZone activeZone = SAFE;    
SystemZone pendingZone = SAFE;   
uint8_t zoneConfirmationCount = 0;
const uint8_t CONFIRMATION_THRESHOLD = 5;  // raised from 4 for extra noise immunity

// --- Timers & Actuation ---
unsigned long previousTelemetryMillis = 0;
const int TELEMETRY_INTERVAL = 200; 
unsigned long previousBeepMillis = 0;
bool beepState = false;

// Set remotely by the host over serial based on real keyboard/mouse idle
// time. When true, the host has determined a person is actively at the
// desk working (not away), so the physical alarm is muted even if the
// sensor sees something in CRITICAL/OVERRIDE range - that's almost
// certainly just a hand near the keyboard, not an intrusion. Defaults to
// false (alarm always active) so the board fails safe if the host never
// connects or the feature is disabled.
bool systemAttended = false;

uint32_t calculateAdler32(String data) {
  uint32_t a = 1, b = 0;
  for (size_t i = 0; i < data.length(); i++) {
    a = (a + data[i]) % 65521;
    b = (b + a) % 65521;
  }
  return (b << 16) | a;
}

float getValidReading() {
  digitalWrite(TRIG_PIN, LOW); delayMicroseconds(2);              
  digitalWrite(TRIG_PIN, HIGH); delayMicroseconds(10);          
  digitalWrite(TRIG_PIN, LOW);
  long duration = pulseIn(ECHO_PIN, HIGH, 25000); 
  if (duration <= 0) return -1.0;
  float cm = (duration / 2.0) * 0.0343;
  if (cm > 400.0 || cm < 2.0) return -1.0;
  return cm;
}

// Median-of-5 sampling: a single stray echo (bounced off a monitor, cable,
// hand near the desk) will be outvoted by the other 4 samples instead of
// directly corrupting the reading, the way a simple 2-sample average would.
float getMedianReading() {
  const int N = 5;
  float samples[N];
  int count = 0;
  for (int i = 0; i < N; i++) {
    float r = getValidReading();
    if (r > 0) samples[count++] = r;
    delayMicroseconds(500);
  }
  if (count == 0) return -1.0;
  for (int i = 1; i < count; i++) {
    float key = samples[i];
    int j = i - 1;
    while (j >= 0 && samples[j] > key) {
      samples[j + 1] = samples[j];
      j--;
    }
    samples[j + 1] = key;
  }
  return samples[count / 2];
}

void processIncomingCommands() {
  if (Serial.available() > 0) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    if (cmd.startsWith("SET_APPROACH:")) {
      APPROACH_THRESHOLD = cmd.substring(13).toFloat();
      Serial.println("{\"sys\":\"ACK\",\"param\":\"APPROACH\",\"val\":" + String(APPROACH_THRESHOLD, 1) + "}");
    } else if (cmd.startsWith("SET_CRITICAL:")) {
      CRITICAL_THRESHOLD = cmd.substring(13).toFloat();
      Serial.println("{\"sys\":\"ACK\",\"param\":\"CRITICAL\",\"val\":" + String(CRITICAL_THRESHOLD, 1) + "}");
    } else if (cmd.startsWith("SET_ATTENDED:")) {
      systemAttended = (cmd.substring(13).toInt() != 0);
      Serial.println("{\"sys\":\"ACK\",\"param\":\"ATTENDED\",\"val\":" + String(systemAttended ? 1 : 0) + "}");
    }
  }
}

void setup() {
  Serial.begin(9600); 
  pinMode(TRIG_PIN, OUTPUT);
  pinMode(ECHO_PIN, INPUT);
  pinMode(BUZZER_PIN, OUTPUT);
  
  Serial.println("{\"sys\":\"BOOT\",\"status\":\"CALIBRATING_ENVIRONMENT\"}");
  
  const int SAMPLES = 20;
  float readings[SAMPLES];
  int validCount = 0;
  
  for(int i = 0; i < SAMPLES; i++) {
    float r = getValidReading();
    if(r > 0) readings[validCount++] = r;
    delay(30); 
  }
  
  if (validCount > 5) {
    for (int i = 0; i < validCount - 1; i++) {
      for (int j = 0; j < validCount - i - 1; j++) {
        if (readings[j] > readings[j + 1]) {
          float temp = readings[j];
          readings[j] = readings[j + 1];
          readings[j + 1] = temp;
        }
      }
    }
    BASELINE_DISTANCE = readings[validCount / 2];
    APPROACH_THRESHOLD = BASELINE_DISTANCE * 0.75;
  } else {
    BASELINE_DISTANCE = 150.0; 
    APPROACH_THRESHOLD = 100.0;
  }
  
  Serial.println("{\"sys\":\"ONLINE\",\"baseline_cm\":" + String(BASELINE_DISTANCE, 1) + "}");
}

float mapFloat(float x, float in_min, float in_max, float out_min, float out_max) {
  return (x - in_min) * (out_max - out_min) / (in_max - in_min) + out_min;
}

void loop() {
  unsigned long currentMillis = millis();
  processIncomingCommands();

  float currentDistance = getMedianReading();
  bool validReading = (currentDistance > 0);
  bool skipThisCycle = false;
  SystemZone evaluatedZone = activeZone;  // default: reuse last confirmed zone if we skip

  if (!validReading) {
    evaluatedZone = OUT_OF_FRAME;
    noTone(BUZZER_PIN);
    analogWrite(BUZZER_PIN, 0);
    beepState = false;
  } else {
    // Outlier rejection: an implausible single-cycle jump must repeat on the
    // NEXT fresh reading too before we trust it. A one-off spike is ignored
    // entirely for this cycle (state simply carries over unchanged).
    if (filteredDistance >= 0) {
      float jump = abs(currentDistance - filteredDistance);
      if (jump > MAX_INSTANT_JUMP_CM) {
        if (outlierStreak > 0 && abs(currentDistance - lastOutlierCandidate) < 15.0) {
          outlierStreak++;
        } else {
          lastOutlierCandidate = currentDistance;
          outlierStreak = 1;
        }
        if (outlierStreak < 2) {
          skipThisCycle = true;  // not confirmed yet - discard, reuse prior state
        } else {
          outlierStreak = 0;     // confirmed on two consecutive reads - accept it
        }
      } else {
        outlierStreak = 0;
      }
    }

    if (!skipThisCycle) {
      // AEMA Spatial Filter
      if (filteredDistance < 0) {
        filteredDistance = currentDistance; 
        previousDistance = currentDistance;
      } else {
        float delta = abs(currentDistance - filteredDistance);
        float dynamicAlpha = (delta > DELTA_THRESHOLD) ? MAX_ALPHA : mapFloat(delta, 0.0, DELTA_THRESHOLD, MIN_ALPHA, MAX_ALPHA); 
        filteredDistance = (dynamicAlpha * currentDistance) + ((1.0 - dynamicAlpha) * filteredDistance);
      }

      // Kinematic Engine
      unsigned long dt = currentMillis - previousKinematicMillis;
      if (dt >= KINEMATIC_INTERVAL) {
        float timeSeconds = dt / 1000.0;
        float rawVelocity = (filteredDistance - previousDistance) / timeSeconds;
        if (abs(rawVelocity) < 300.0) currentVelocity = rawVelocity;
        
        currentAcceleration = (currentVelocity - previousVelocity) / timeSeconds;
        previousDistance = filteredDistance; 
        previousVelocity = currentVelocity;
        previousKinematicMillis = currentMillis;
      }

      // Spatial Evaluation Matrix
      // Lunge/OVERRIDE is range-gated: a genuine lunge starts from a plausible
      // starting distance. A velocity spike measured while something is far
      // away is much more likely to be sensor noise than a real approach.
      bool withinLungeRange = filteredDistance <= (APPROACH_THRESHOLD * 1.3);
      if (currentVelocity <= LUNGE_VELOCITY_THRESHOLD && withinLungeRange) evaluatedZone = OVERRIDE; 
      else if (filteredDistance <= CRITICAL_THRESHOLD) evaluatedZone = CRITICAL;
      else if (filteredDistance <= APPROACH_THRESHOLD) evaluatedZone = APPROACH;
      else evaluatedZone = SAFE;
    }
  }

  // Discrete Frame Debouncer - only advances when this cycle produced a fresh
  // evaluation; a skipped/rejected cycle leaves pending state untouched.
  if (!skipThisCycle) {
    if (evaluatedZone == pendingZone) {
      if (zoneConfirmationCount < CONFIRMATION_THRESHOLD) zoneConfirmationCount++;
      if (zoneConfirmationCount >= CONFIRMATION_THRESHOLD) activeZone = pendingZone;
    } else {
      pendingZone = evaluatedZone; 
      zoneConfirmationCount = 1; 
    }
  }

  // Geiger-Counter Escalating Actuation Matrix
  if (systemAttended) {
    // Host says a person is actively at the keyboard - a CRITICAL/OVERRIDE
    // reading right now is almost certainly just a hand near the sensor,
    // not an intrusion. Stay silent; telemetry keeps flowing normally.
    noTone(BUZZER_PIN);
    analogWrite(BUZZER_PIN, 0);
    beepState = false;
  } else if (activeZone == CRITICAL || activeZone == OVERRIDE) {
    int beepInterval = map(filteredDistance, 2.0, CRITICAL_THRESHOLD, 60, 150);
    if (currentMillis - previousBeepMillis >= beepInterval) {
      beepState = !beepState;
      previousBeepMillis = currentMillis;
    }
    if (beepState) tone(BUZZER_PIN, 2500); // Sharp high-pitch alert
    else noTone(BUZZER_PIN);
  } else if (activeZone == APPROACH) {
    noTone(BUZZER_PIN);
    int pitch = map(filteredDistance, CRITICAL_THRESHOLD, APPROACH_THRESHOLD, 1800, 400);
    int interval = map(filteredDistance, CRITICAL_THRESHOLD, APPROACH_THRESHOLD, 100, 500);
    if (currentMillis - previousBeepMillis >= interval) {
      beepState = !beepState;
      previousBeepMillis = currentMillis;
    }
    if (beepState) tone(BUZZER_PIN, pitch);
    else noTone(BUZZER_PIN);
  } else {
    noTone(BUZZER_PIN);
    analogWrite(BUZZER_PIN, 0);
    beepState = false;
  }

  // Secure Telemetry Pipeline - now always sends, even on OUT_OF_FRAME frames,
  // so the host never has to guess why it went quiet.
  if (currentMillis - previousTelemetryMillis >= TELEMETRY_INTERVAL) {
    previousTelemetryMillis = currentMillis;
    
    String zoneString = (activeZone == CRITICAL) ? "CR"
                       : (activeZone == OVERRIDE) ? "OV"
                       : (activeZone == APPROACH) ? "AP"
                       : (activeZone == OUT_OF_FRAME) ? "OF"
                       : "SF";

    float reportedDistance = (activeZone == OUT_OF_FRAME) ? BASELINE_DISTANCE : filteredDistance;
    float reportedVelocity = (activeZone == OUT_OF_FRAME) ? 0.0 : currentVelocity;

    String corePayload = "\"cm\":" + String(reportedDistance, 1) + 
                         ",\"v\":" + String(reportedVelocity, 1) + 
                         ",\"z\":\"" + zoneString + "\"";
                         
    uint32_t packetHash = calculateAdler32(corePayload);
    
    Serial.print("{");
    Serial.print(corePayload);
    Serial.print(",\"h\":");
    Serial.print(packetHash);
    Serial.println("}");
  }
  
  delay(10); 
}
