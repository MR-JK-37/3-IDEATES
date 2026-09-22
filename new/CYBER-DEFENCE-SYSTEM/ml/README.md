CyberShield ML Integration Scaffold

This folder contains a small scaffold demonstrating how to integrate an on-device
TFLite model with YARA rule checks for local threat scoring.

Components:
- `requirements.txt` - Python packages recommended for the prototype
- `models/` - place your `model.tflite` here (example format described below)
- `inference.py` - lightweight TFLite wrapper with fallback
- `yara_rules/` - sample YARA rules (ransomware detection examples)
- `runner.py` - demo runner that shows integration between entropy features, YARA, and TFLite

Notes:
- The code falls back to a simple heuristic scorer if TFLite or YARA are not installed,
  so you can run the demo without heavy dependencies.
- For production, use a properly trained TFLite model exported from TensorFlow/Keras
  and keep the YARA rules curated and signed.
