"""TFLite inference wrapper with graceful fallback.

Provides `TFLiteModel` which attempts to load a TFLite interpreter (either
`tflite_runtime` or `tensorflow.lite`). If not available, a simple fallback
scorer is used (linear combination) so the runner can function in CI.
"""

from typing import Sequence, Optional
import os
import numpy as np


class TFLiteModel:
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path
        self.interpreter = None
        self.input_details = None
        self.output_details = None
        self._loaded = False
        self._use_fallback = False

    def load(self):
        """Try to load a TFLite interpreter. If it fails, enable fallback."""
        if not self.model_path or not os.path.isfile(self.model_path):
            self._use_fallback = True
            return

        try:
            try:
                # Prefer lightweight tflite-runtime package
                from tflite_runtime.interpreter import Interpreter
            except Exception:
                from tensorflow.lite import Interpreter

            self.interpreter = Interpreter(self.model_path)
            self.interpreter.allocate_tensors()
            self.input_details = self.interpreter.get_input_details()
            self.output_details = self.interpreter.get_output_details()
            self._loaded = True
        except Exception:
            # Fall back to heuristic scorer if interpreter not available
            self._use_fallback = True

    def predict(self, features: Sequence[float]) -> float:
        """Return a threat score 0.0 - 1.0 for the provided features.

        `features` should be a 1-D sequence of floats matching model input.
        """
        if self._use_fallback or not self._loaded:
            return self._fallback_score(features)

        arr = np.array(features, dtype=np.float32).reshape(self._input_shape())
        self.interpreter.set_tensor(self.input_details[0]['index'], arr)
        self.interpreter.invoke()
        out = self.interpreter.get_tensor(self.output_details[0]['index'])
        # Expect scalar output
        return float(out.flatten()[0])

    def _input_shape(self):
        # returns (1, N) or (N,) depending on model
        shape = self.input_details[0]['shape']
        if len(shape) == 1:
            return (len(shape),)
        if shape[0] == 1:
            return tuple(shape)
        # ensure batch dim
        return (1,) + tuple(shape[1:])

    @staticmethod
    def _fallback_score(features: Sequence[float]) -> float:
        """Simple linear heuristic fallback.

        Weights are tuned as a safety-first heuristic: entropy and mass-mod count
        are strong indicators.
        """
        if not features:
            return 0.0
        # ensure numpy for vector ops
        f = np.array(features, dtype=float)
        # Heuristic weights (example): [entropy, file_size_kb, mass_mod_count, cmd_score, net_score]
        # If fewer features supplied, pad with zeros
        w = np.array([0.5, 0.0001, 0.3, 0.1, 0.1])
        if f.size < w.size:
            f = np.pad(f, (0, w.size - f.size))
        score = float(np.dot(w, f[: w.size]))
        # normalize to 0..1
        score = max(0.0, min(1.0, score / (1.0 + score)))
        return score


def demo():
    m = TFLiteModel(None)
    m.load()
    print("Demo fallback predict:", m.predict([7.8, 1024.0, 60.0, 0.2, 0.0]))


if __name__ == '__main__':
    demo()
