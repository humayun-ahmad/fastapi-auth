import asyncio
import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi import FastAPI, Depends

from app.main import app as real_app
from app.db.base import Base
from app.db.session import get_db

# SQLite test DB
engine = create_engine("sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False}, future=True)
TestingSessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)

@pytest.fixture(autouse=True, scope="session")
def create_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

@pytest.fixture
def app() -> FastAPI:
    app = real_app
    app.dependency_overrides[get_db] = override_get_db
    return app

@pytest.mark.asyncio
async def test_register_login_me(app: FastAPI):
    async with AsyncClient(app=app, base_url="http://test") as client:
        # register
        r = await client.post("/auth/register", json={
            "email": "test@example.com",
            "full_name": "Test User",
            "password": "StrongPass1"
        })
        assert r.status_code == 201
        # login
        r = await client.post("/auth/login", json={"email": "test@example.com", "password": "StrongPass1"})
        assert r.status_code == 200
        tokens = r.json()
        assert "access_token" in tokens and "refresh_token" in tokens
        # me
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}
        r = await client.get("/users/me", headers=headers)
        assert r.status_code == 200
        me = r.json()
        assert me["email"] == "test@example.com"
