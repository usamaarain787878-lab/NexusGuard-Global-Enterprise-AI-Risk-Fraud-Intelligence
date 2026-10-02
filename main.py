from fastapi import FastAPI
from database.connection import engine, Base
from api.routes import router as fraud_router

Base.metadata.create_all(bind=engine)

app = FastAPI(title="NexusGuard AI V2", version="2.0.0")
app.include_router(fraud_router)

@app.get("/")
def root():
    return {"system": "NexusGuard AI V2", "status": "Operational"}
