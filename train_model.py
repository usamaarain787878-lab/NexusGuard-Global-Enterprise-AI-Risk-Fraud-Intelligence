import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib

# Train using pure numpy arrays to prevent any feature name or pandas version mismatch
np.random.seed(42)
n_samples = 1000
X = np.random.rand(n_samples, 12)  # Exactly 12 features
y = np.random.choice([0, 1], size=n_samples, p=[0.95, 0.05])

model = RandomForestClassifier(n_estimators=50, random_state=42)
model.fit(X, y)

joblib.dump(model, "fraud_model.pkl")
print("✅ Numpy-based model trained and saved successfully!")