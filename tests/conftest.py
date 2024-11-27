# Standard library imports
from builtins import range
from datetime import datetime
from unittest.mock import patch
from uuid import uuid4

# Third-party imports
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, scoped_session
from faker import Faker

# Application-specific imports
from app.main import app
from app.database import Base, Database
from app.models.user_model import User, UserRole
from app.dependencies import get_db, get_settings
from app.utils.security import hash_password
from app.services.jwt_service import create_access_token

fake = Faker()

# Database setup
settings = get_settings()
TEST_DATABASE_URL = settings.database_url.replace("postgresql://", "postgresql+asyncpg://")
engine = create_async_engine(TEST_DATABASE_URL, echo=settings.debug)
AsyncTestingSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
AsyncSessionScoped = scoped_session(AsyncTestingSessionLocal)


@pytest.fixture(scope="function", autouse=True)
async def setup_database():
    """Sets up and tears down the database before and after each test."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.fixture(scope="function")
async def db_session(setup_database):
    """Provides a database session for testing."""
    async with AsyncSessionScoped() as session:
        try:
            yield session
        finally:
            await session.close()


@pytest.fixture(scope="function")
async def async_client(db_session):
    """Provides an HTTP client for testing."""
    async with AsyncClient(app=app, base_url="http://testserver") as client:
        app.dependency_overrides[get_db] = lambda: db_session
        yield client
        app.dependency_overrides.clear()


# User Fixtures
@pytest.fixture(scope="function")
async def user(db_session):
    user_data = {
        "id": uuid4(),
        "nickname": fake.user_name(),
        "first_name": fake.first_name(),
        "last_name": fake.last_name(),
        "email": fake.email(),
        "hashed_password": hash_password("MySuperPassword$1234"),
        "role": UserRole.AUTHENTICATED,
        "email_verified": False,
        "is_locked": False,
    }
    user = User(**user_data)
    db_session.add(user)
    await db_session.commit()
    return user


@pytest.fixture(scope="function")
async def verified_user(db_session):
    user_data = {
        "id": uuid4(),
        "nickname": fake.user_name(),
        "first_name": fake.first_name(),
        "last_name": fake.last_name(),
        "email": fake.email(),
        "hashed_password": hash_password("MySuperPassword$1234"),
        "role": UserRole.AUTHENTICATED,
        "email_verified": True,
        "is_locked": False,
    }
    user = User(**user_data)
    db_session.add(user)
    await db_session.commit()
    return user


@pytest.fixture(scope="function")
async def locked_user(db_session):
    user_data = {
        "id": uuid4(),
        "nickname": fake.user_name(),
        "first_name": fake.first_name(),
        "last_name": fake.last_name(),
        "email": fake.email(),
        "hashed_password": hash_password("MySuperPassword$1234"),
        "role": UserRole.AUTHENTICATED,
        "email_verified": False,
        "is_locked": True,
        "failed_login_attempts": settings.max_login_attempts,
    }
    user = User(**user_data)
    db_session.add(user)
    await db_session.commit()
    return user


@pytest.fixture(scope="function")
async def admin_user(db_session):
    user_data = {
        "id": uuid4(),
        "nickname": "admin_user",
        "first_name": "Admin",
        "last_name": "User",
        "email": "admin@example.com",
        "hashed_password": hash_password("AdminPassword123!"),
        "role": UserRole.ADMIN,
        "email_verified": True,
        "is_locked": False,
    }
    admin = User(**user_data)
    db_session.add(admin)
    await db_session.commit()
    return admin


@pytest.fixture(scope="function")
async def manager_user(db_session):
    user_data = {
        "id": uuid4(),
        "nickname": "manager_user",
        "first_name": "Manager",
        "last_name": "User",
        "email": "manager@example.com",
        "hashed_password": hash_password("ManagerPassword123!"),
        "role": UserRole.MANAGER,
        "email_verified": True,
        "is_locked": False,
    }
    manager = User(**user_data)
    db_session.add(manager)
    await db_session.commit()
    return manager


# Token Fixtures
@pytest.fixture(scope="function")
async def user_token(db_session, user):
    token = create_access_token(data={"sub": user.email, "role": user.role.name})
    return token


@pytest.fixture(scope="function")
async def admin_token(db_session, admin_user):
    token = create_access_token(data={"sub": admin_user.email, "role": admin_user.role.name})
    return token


@pytest.fixture(scope="function")
async def manager_token(db_session, manager_user):
    token = create_access_token(data={"sub": manager_user.email, "role": manager_user.role.name})
    return token
