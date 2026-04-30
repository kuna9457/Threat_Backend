from fastapi import FastAPI
from app.api.routes import router
import uvicorn

app = FastAPI(title="URL Threat Intelligence Platform")

app.include_router(router, prefix="/api/v1")

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
