# Sonic

## Description
We intercepted a strange audio transmission. Our audio analysts say it's not music, not speech, and definitely not random noise. Can you figure out what it is?
## Analysis
Start with basic file info:
```
$ file challenge.wav
challenge.wav: RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, mono 44100 Hz
```

So it’s a mono 16‑bit PCM WAV at 44.1 kHz.

Analyze the wav file:
```
import wave
import numpy as np

w = wave.open("challenge.wav", "rb")
print(w.getnchannels(), w.getsampwidth(), w.getframerate(), w.getnframes())

frames = w.readframes(w.getnframes())
samples = np.frombuffer(frames, dtype="<i2")  # 16-bit little-endian
print(np.unique(samples))
```
Output (simplified):

Channels: 1

Sample width: 2

Sample rate: 44100

Unique sample values: [-8000, 2700, 8000]

So instead of typical “analog-looking” audio, we have only three discrete sample values: -8000, +8000, and 2700.

That strongly suggests some kind of digital encoding, not voice or music.

If we check where that middle value (2700) appears:
```python
idx_2700 = np.where(samples == 2700)[0]
print(len(idx_2700), idx_2700[:20], idx_2700[-20:])
```

Exactly 200 samples at 2700

All at the very start: indices 0–199

After that, the signal is only +8000 and -8000.


## Solve