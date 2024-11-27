"""
File: test_database_operations.py

Overview:
This Python test file utilizes pytest to manage database states and HTTP clients for testing a web application built with FastAPI and SQLAlchemy. It includes detailed fixtures to mock the testing environment, ensuring each test is run in isolation with a consistent setup.

Fixtures:
- `async_client`: Manages an asynchronous HTTP client for testing interactions with the FastAPI application.
- `db_session`: Handles database transactions to ensure a clean database state for each test.
- User fixtures (`user`, `locked_user`, `verified_user`, etc.): Set up various user states to test different behaviors under diverse conditions.
- `token`: Generates an authentication token for testing secured endpoints.
- `initialize_database`: Prepares the database at the session start.
- `setup_database`: Sets up and tears down the database before and after each test.
"""

# Standard library imports
from datetime import datetime
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
from app.utils.template_manager import TemplateManager
from app.services.email_service import EmailService
from app.services.jwt_service import create_access_token

fake = Faker()

settings = get_settings()
TEST_DATABASE_URL = settings.database_url.replace("postgresql://", "postgresql+asyncpg://")
engine = create_async_engine(TEST_DATABASE_URL, echo=settings.debug)
AsyncTestingSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
AsyncSessionScoped = scoped_session(AsyncTestingSessionLocal)


@pytest.fixture
def email_service():
    """
    Fixture to provide an instance of the EmailService for testing.
    """
    template_manager = TemplateManager()
    email_service = EmailService(template_manager=template_manager)
    return email_service


@pytest.fixture(scope="function")
async def async_client(db_session):
    """
    Fixture to provide an asynchronous HTTP client for testing FastAPI endpoints.
    """
    async with AsyncClient(app=app, base_url="http://testserver") as client:
        app.dependency_overrides[get_db] = lambda: db_session
        try:
            yield client
        finally:
            app.dependency_overrides.clear()


@pytest.fixture(scope="session", autouse=True)
def initialize_database():
    """
    Fixture to initialize the database schema at the start of the session.
    """
    try:
        Database.initialize(settings.database_url)
    except Exception as e:
        pytest.fail(f"Failed to initialize the database: {str(e)}")


@pytest.fixture(scope="function", autouse=True)
async def setup_database():
    """
    Fixture to set up and tear down the database schema before and after each test.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.fixture(scope="function")
async def db_session(setup_database):
    """
    Fixture to provide a scoped asynchronous database session for each test.
    """
    async with AsyncSessionScoped() as session:
        try:
            yield session
        finally:
            await session.close()


@pytest.fixture(scope="function")
async def locked_user(db_session):
    """
    Fixture to create a locked user in the database for testing.
    """
    user_data = {
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
async def user(db_session):
    """
    Fixture to create a regular user in the database for testing.
    """
    user_data = {
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
    """
    Fixture to create a verified user in the database for testing.
    """
    user_data = {
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
async def admin_user(db_session):
    """
    Fixture to create an admin user in the database for testing.
    """
    user = User(
        nickname="admin_user",
        email="admin@example.com",
        first_name="John",
        last_name="Doe",
        hashed_password=hash_password("SecurePassword123!"),
        role=UserRole.ADMIN,
        is_locked=False,
    )
    db_session.add(user)
    await db_session.commit()
    return user


@pytest.fixture
def user_base_data():
    """
    Fixture to provide base data for user creation.
    """
    return {
        "username": "john_doe_123",
        "email": "john.doe@example.com",
        "full_name": "John Doe",
        "bio": "I am a software engineer with over 5 years of experience.",
        "profile_picture_url": "https://example.com/profile_pictures/john_doe.jpg",
    }


@pytest.fixture
def user_base_data_invalid():
    """
    Fixture to provide invalid base data for user creation.
    """
    return {
        "username": "john_doe_123",
        "email": "john.doe.example.com",  # Invalid email format
        "full_name": "John Doe",
        "bio": "I am a software engineer with over 5 years of experience.",
        "profile_picture_url": "https://example.com/profile_pictures/john_doe.jpg",
    }


@pytest.fixture
def user_create_data(user_base_data):
    """
    Fixture to provide data for creating a user.
    """
    return {**user_base_data, "password": "SecurePassword123!"}


@pytest.fixture
def user_update_data():
    """
    Fixture to provide data for updating a user.
    """
    return {
        "email": "john.doe.new@example.com",
        "full_name": "John H. Doe",
        "bio": "I specialize in backend development with Python and Node.js.",
        "profile_picture_url": "https://example.com/profile_pictures/john_doe_updated.jpg",
    }


@pytest.fixture
def login_request_data():
    """
    Fixture to provide valid login data.
    """
    return {"username": "john_doe_123", "password": "SecurePassword123!"}


@pytest.fixture(scope="function")
async def user_token(db_session, user):
    """
    Fixture to generate a token for a regular user.
    """
    token = create_access_token(data={"sub": user.email, "role": user.role.name})
    return token


@pytest.fixture(scope="function")
async def admin_token(db_session, admin_user):
    """
    Fixture to generate a token for an admin user.
    """
    token = create_access_token(data={"sub": admin_user.email, "role": admin_user.role.name})
    return token
