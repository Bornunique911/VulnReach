from api.server import app

# Run via: uvicorn main:app --reload

from fastapi.staticfiles import StaticFiles

# after all your @app routes:
app.mount("/", StaticFiles(directory="dashboard", html=True), name="ui")