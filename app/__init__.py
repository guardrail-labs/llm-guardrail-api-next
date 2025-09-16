# app/__init__.py
"""
Keep this file minimal so 'app' is always a proper package.

Do NOT import submodules here (e.g., don't import main or app).
Tests and runtime should import from 'app.main' directly:
    from app.main import create_app
And Uvicorn should use:
    uvicorn app.main:create_app
"""
