Models folder
-------------

Place a TensorFlow Lite model file named `model.tflite` in this folder. The expected
input is a 1-D float32 vector of feature values (e.g. entropy, file_size_kb, mass_mod_count,
command_score, network_score). The model should output a single float neuron representing
threat score (0.0 - 1.0).

Example Keras -> TFLite export (local):

```python
# model: a compiled Keras model
import tensorflow as tf
converter = tf.lite.TFLiteConverter.from_keras_model(model)
converter.optimizations = [tf.lite.Optimize.DEFAULT]
open('models/model.tflite', 'wb').write(converter.convert())
```
