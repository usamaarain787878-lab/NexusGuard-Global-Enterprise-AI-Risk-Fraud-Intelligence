from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from ai.engine import ai_engine

app = FastAPI(
    title="NexusGuard Global API",
    version="3.1.0",
    description="Enterprise Fraud Intelligence REST API"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class TransactionFeatures(BaseModel):
    Time: float
    V1: float
    V2: float
    V3: float
    V4: float
    V5: float
    V6: float
    V7: float
    V8: float
    V9: float
    V10: float
    Amount: float

@app.get("/")
def root():
    return {
        "status": "online",
        "service": "NexusGuard Global API",
        "version": "3.1.0"
    }

@app.get("/api/v1/health")
def health():
    return {
        "status": "healthy",
        "service": "fraud-detection-api",
        "model_loaded": ai_engine.model is not None
    }

@app.get("/api/v1/model-info")
def model_info():
    if ai_engine.model is None:
        raise HTTPException(status_code=503, detail="Fraud model is not loaded")
    return {
        "model_type": type(ai_engine.model).__name__,
        "features": getattr(ai_engine.model, "n_features_in_", None),
        "estimators": getattr(ai_engine.model, "n_estimators", None),
        "classes": getattr(ai_engine.model, "classes_", []).tolist()
    }

@app.post("/api/v1/predict")
def predict(transaction: TransactionFeatures):
    if ai_engine.model is None:
        raise HTTPException(status_code=503, detail="Fraud model is not loaded")
    features = [
        transaction.Time, transaction.V1, transaction.V2, transaction.V3,
        transaction.V4, transaction.V5, transaction.V6, transaction.V7,
        transaction.V8, transaction.V9, transaction.V10, transaction.Amount
    ]
    result = ai_engine.predict(features)
    return {
        "status": "success",
        "prediction": "FRAUD" if result["is_fraud"] else "LEGITIMATE",
        "is_fraud": result["is_fraud"],
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "model": type(ai_engine.model).__name__,
        "feature_count": len(features)
    }
