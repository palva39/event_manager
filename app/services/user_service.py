from builtins import Exception, bool, classmethod, int, str
from datetime import datetime, timezone
import secrets
from typing import Optional, Dict, List
from pydantic import ValidationError
from sqlalchemy import func, null, update, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from app.dependencies import get_email_service, get_settings
from app.models.user_model import User
from app.schemas.user_schemas import UserCreate, UserUpdate
from app.utils.nickname_gen import generate_nickname
from app.utils.security import generate_verification_token, hash_password, verify_password
from uuid import UUID
from app.services.email_service import EmailService
from app.models.user_model import UserRole
import logging
import re
from fastapi import HTTPException


settings = get_settings()
logger = logging.getLogger(__name__)

class UserService:
    @classmethod
    async def _execute_query(cls, session: AsyncSession, query):
        try:
            result = await session.execute(query)
            await session.commit()
            return result
        except SQLAlchemyError as e:
            logger.error(f"Database error: {e}")
            await session.rollback()
            return None

    @classmethod
    async def _fetch_user(cls, session: AsyncSession, **filters) -> Optional[User]:
        query = select(User).filter_by(**filters)
        result = await cls._execute_query(session, query)
        return result.scalars().first() if result else None

    @classmethod
    async def get_by_id(cls, session: AsyncSession, user_id: UUID) -> Optional[User]:
        return await cls._fetch_user(session, id=user_id)

    @classmethod
    async def get_by_nickname(cls, session: AsyncSession, nickname: str) -> Optional[User]:
        return await cls._fetch_user(session, nickname=nickname)

    @classmethod
    async def get_by_email(cls, session: AsyncSession, email: str) -> Optional[User]:
        return await cls._fetch_user(session, email=email)

    @classmethod
    async def create(cls, session: AsyncSession, user_data: Dict[str, str], email_service: EmailService) -> Optional[User]:
        try:
            # Validate input data
            validated_data = UserCreate(**user_data).model_dump()
            
            # Validate password
            if not cls.validate_password(validated_data['password']):
                logger.error("Password validation failed.")
                return None

            # Check if email already exists
            existing_user = await cls.get_by_email(session, validated_data['email'])
            if existing_user:
                logger.error("User with given email already exists.")
                return None

            # Generate unique nickname
            new_nickname = generate_nickname()
            while await cls.get_by_nickname(session, new_nickname):
                logger.info(f"Generated nickname '{new_nickname}' already exists. Generating a new one.")
                new_nickname = generate_nickname()

            validated_data['nickname'] = new_nickname

            # Hash the password
            validated_data['hashed_password'] = hash_password(validated_data.pop('password'))

            # Create new user instance
            new_user = User(**validated_data)
            new_user.verification_token = generate_verification_token()

            # Add user to session and commit
            session.add(new_user)
            await session.commit()

            # Send verification email
            await email_service.send_verification_email(new_user)

            logger.info(f"User '{new_user.email}' created successfully with nickname '{new_user.nickname}'.")
            return new_user

        except ValidationError as e:
            logger.error(f"Validation error during user creation: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during user creation: {e}")
            return None

    @classmethod
    async def update(cls, session: AsyncSession, user_id: UUID, update_data: Dict[str, str]) -> Optional[User]:
        try:
            # validated_data = UserUpdate(**update_data).dict(exclude_unset=True)
            validated_data = UserUpdate(**update_data).dict(exclude_unset=True)

            if 'password' in validated_data:
                validated_data['hashed_password'] = hash_password(validated_data.pop('password'))
            query = update(User).where(User.id == user_id).values(**validated_data).execution_options(synchronize_session="fetch")
            await cls._execute_query(session, query)
            updated_user = await cls.get_by_id(session, user_id)
            if updated_user:
                session.refresh(updated_user)  # Explicitly refresh the updated user object
                logger.info(f"User {user_id} updated successfully.")
                return updated_user
            else:
                logger.error(f"User {user_id} not found after update attempt.")
            return None
        except Exception as e:  # Broad exception handling for debugging
            logger.error(f"Error during user update: {e}")
            return None

    @classmethod
    async def delete(cls, session: AsyncSession, user_id: UUID) -> bool:
        user = await cls.get_by_id(session, user_id)
        if not user:
            logger.info(f"User with ID {user_id} not found.")
            return False
        await session.delete(user)
        await session.commit()
        return True

    @classmethod
    async def list_users(cls, session: AsyncSession, skip: int = 0, limit: int = 10) -> List[User]:
        query = select(User).offset(skip).limit(limit)
        result = await cls._execute_query(session, query)
        return result.scalars().all() if result else []

    @classmethod
    async def register_user(cls, session: AsyncSession, user_data: Dict[str, str], email_service: EmailService) -> Optional[User]:
        return await cls.create(session, user_data, email_service)
    

    @classmethod
    async def login_user(cls, session: AsyncSession, identifier: str, password: str) -> Optional[User]:
        try:
            # Determine if identifier is an email or nickname
            if "@" in identifier and "." in identifier:  # Simple check for an email
                user = await cls.get_by_email(session, identifier)
            else:
                user = await cls.get_by_nickname(session, identifier)

            if not user:
                logger.error(f"Login failed: User with identifier {identifier} not found.")
                raise ValueError("The email/nickname or password is incorrect.")

            # Check if the email is verified
            if not user.email_verified:
                logger.error(f"Login failed: Email not verified for user {identifier}.")
                raise ValueError("The email is not verified.")

            # Check if the account is locked
            if user.is_locked:
                logger.error(f"Login failed: Account is locked for user {identifier}.")
                raise ValueError("The account is locked.")

            # Validate the password
            if verify_password(password, user.hashed_password):
                # Successful login: reset failed attempts and update last login time
                user.failed_login_attempts = 0
                user.last_login_at = datetime.now(timezone.utc)
                session.add(user)
                await session.commit()
                logger.info(f"User {identifier} logged in successfully.")
                return user
            else:
                # Increment failed login attempts
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= settings.max_login_attempts:
                    user.is_locked = True
                    logger.error(f"Login failed: Account locked due to too many failed attempts for user {identifier}.")
                session.add(user)
                await session.commit()
                raise ValueError("The email/nickname or password is incorrect.")
        except ValueError as ve:
            logger.error(f"Login error for user {identifier}: {ve}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during login for user {identifier}: {e}")
            return None

    @classmethod
    async def is_account_locked(cls, session: AsyncSession, email: str) -> bool:
        user = await cls.get_by_email(session, email)
        return user.is_locked if user else False


    @classmethod
    async def reset_password(cls, session: AsyncSession, user_id: UUID, new_password: str) -> bool:
        hashed_password = hash_password(new_password)
        user = await cls.get_by_id(session, user_id)
        if user:
            user.hashed_password = hashed_password
            user.failed_login_attempts = 0  # Resetting failed login attempts
            user.is_locked = False  # Unlocking the user account, if locked
            session.add(user)
            await session.commit()
            return True
        return False

    @classmethod
    async def verify_email_with_token(cls, session: AsyncSession, user_id: UUID, token: str) -> bool:
        user = await cls.get_by_id(session, user_id)
        if user and user.verification_token == token:
            user.email_verified = True
            user.verification_token = None  # Clear the token once used
            user.role = UserRole.AUTHENTICATED
            session.add(user)
            await session.commit()
            return True
        return False

    @classmethod
    async def count(cls, session: AsyncSession) -> int:
        """
        Count the number of users in the database.

        :param session: The AsyncSession instance for database access.
        :return: The count of users.
        """
        query = select(func.count()).select_from(User)
        result = await session.execute(query)
        count = result.scalar()
        return count
    
    @classmethod
    async def unlock_user_account(cls, session: AsyncSession, user_id: UUID) -> bool:
        user = await cls.get_by_id(session, user_id)
        if user and user.is_locked:
            user.is_locked = False
            user.failed_login_attempts = 0  # Optionally reset failed login attempts
            session.add(user)
            await session.commit()
            return True
        return False

    @classmethod
    async def validate_username(cls, session: AsyncSession, username: Optional[str]):
        if not username:
            raise ValueError("Username cannot be None or empty.")
        # Length constraint
        if len(username) < 3 or len(username) > 20:
            raise ValueError("Username must be between 3 and 20 characters.")
        # Allowed characters: letters, numbers, and underscores only
        if not re.match(r"^[a-zA-Z0-9_]+$", username):
            raise ValueError("Username can only contain letters, numbers, and underscores.")
        # Uniqueness check
        existing_user = await cls.get_by_nickname(session, username)
        if existing_user:
            raise ValueError("Username already exists.")
        
    @classmethod
    def validate_password(cls, password: str) -> bool:
        if len(password) < 8:
            logger.error("Password must be at least 8 characters long.")
            return False
        if not re.search(r'[A-Z]', password):
            logger.error("Password must contain at least one uppercase letter.")
            return False
        if not re.search(r'[a-z]', password):
            logger.error("Password must contain at least one lowercase letter.")
            return False
        if not re.search(r'[0-9]', password):
            logger.error("Password must contain at least one digit.")
            return False
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            logger.error("Password must contain at least one special character.")
            return False
        return True