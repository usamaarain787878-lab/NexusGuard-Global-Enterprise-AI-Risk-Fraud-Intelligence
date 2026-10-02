from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="NexusGuard Global API",
    version="3.0.0",
    description="Enterprise Fraud Intelligence REST API"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {
        "status": "online",
        "service": "NexusGuard Global API",
        "version": "3.0.0"
    }

@app.get("/api/v1/health")
def health():
    return {
        "status": "healthy",
        "service": "fraud-detection-api"
    }
