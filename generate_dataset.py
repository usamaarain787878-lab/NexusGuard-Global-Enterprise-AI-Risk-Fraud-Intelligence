import pandas as pd
import numpy as np

# Set random seed for consistent data generation
np.random.seed(42)
n_samples = 500  # 500 transactions ka bara dataset

# Generate realistic transaction features matching our 12-feature model
data = {
    'Time': np.random.randint(0, 86400, n_samples),
    'V1': np.random.normal(0, 1, n_samples),
    'V2': np.random.normal(0, 1, n_samples),
    'V3': np.random.normal(0, 1, n_samples),
    'V4': np.random.normal(0, 1, n_samples),
    'V5': np.random.normal(0, 1, n_samples),
    'V6': np.random.normal(0, 1, n_samples),
    'V7': np.random.normal(0, 1, n_samples),
    'V8': np.random.normal(0, 1, n_samples),
    'V9': np.random.normal(0, 1, n_samples),
    'V10': np.random.normal(0, 1, n_samples),
    'Amount': np.random.exponential(150, n_samples) + 10.0
}

df = pd.DataFrame(data)

# Save to project folder
df.to_csv("large_fraud_dataset.csv", index=False)
print("✅ Success: 'large_fraud_dataset.csv' generated with 500 records successfully!")