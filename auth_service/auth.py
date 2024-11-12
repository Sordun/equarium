import os
from datetime import datetime, timedelta
from typing import Dict, Optional

from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from dotenv import load_dotenv

from .models import User
from .schemas import UserCreate
from common.logger import logger

load_dotenv()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = os.getenv("SECRET_KEY")  # Замените на ваш секретный ключ
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

http_bearer = HTTPBearer(auto_error=False)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def create_access_token(data: Dict[str, datetime | str], expires_delta: Optional[timedelta] = None) -> str:
    """
    Создание JWT-токена доступа.

    :param data: (Dict[str, str]): Данные, которые будут закодированы в токене.
    :param expires_delta: timedelta - Время истечения токена. Если не указано, используется значение по умолчанию.
    :returns: str - Закодированный JWT-токен.
    :raises ValueError: Если данные не могут быть закодированы.
    """
    to_encode = data.copy()

    # Установка времени истечения
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})

    try:
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        logger.info("Токен доступа успешно создан.")
        return encoded_jwt
    except Exception as e:
        logger.error(f"Ошибка при создании токена доступа: {e}")
        raise ValueError(f"Не удалось создать токен доступа {e}.")


def get_user_by_email(db: Session, email: str) -> User | None:
    """
    Получить пользователя по адресу электронной почты.

    :param db: Сессия базы данных.
    :param email: Адрес электронной почты пользователя.
    :return: Пользователь, если найден, иначе None.
    """
    try:
        user = db.query(User).filter(User.email == email).first()

        if user:
            logger.info(f"Пользователь с email {email} найден.")
        else:
            logger.info(f"Пользователь с email {email} не найден.")

        return user

    except SQLAlchemyError as e:
        # Обработка ошибок базы данных
        logger.error(f"Ошибка при выполнении запроса к базе данных: {e}")
    except ValueError as e:
        # Обработка ошибок валидации email
        logger.warning(f"Некорректный адрес электронной почты: {e}")


def verify_token(token: str = Depends(oauth2_scheme)) -> Optional[str]:
    """
    Проверяет токен и извлекает адрес электронной почты из полезной нагрузки.

    :param token: JWT токен, переданный в заголовке авторизации.
    :return: Адрес электронной почты, если токен действителен, иначе None.
    :raises HTTPException: Возникает, если токен недействителен или не содержит адреса электронной почты.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Декодирование токена
        payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
        email: str = payload.get("sub")

        if email is None:
            logger.warning("Токен не содержит адреса электронной почты.")
            raise credentials_exception

        logger.info(f"Токен успешно проверен. Адрес электронной почты: {email}")

    except JWTError as e:
        logger.error(f"Ошибка при декодировании токена: {e}")
        raise credentials_exception

    return email


def hash_password(password: str) -> str:
    """
    Хеширует пароль с использованием алгоритма bcrypt.

    :param password: Пароль, который нужно хешировать.
    :return: Хешированный пароль.
    :raises ValueError: Возникает, если пароль пустой.
    """
    if not password:
        logger.error("Пароль не может быть пустым.")
        raise ValueError("Пароль не может быть пустым.")

    try:
        hashed_password = pwd_context.hash(password)
        logger.info("Пароль успешно хеширован.")
        return hashed_password
    except Exception as e:
        logger.error(f"Ошибка при хешировании пароля: {e}")
        raise


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Проверяет, соответствует ли введенный пароль хешированному паролю.

    :param plain_password: Введенный пользователем пароль.
    :param hashed_password: Хешированный пароль для проверки.
    :return: True, если пароли совпадают, иначе False.
    :raises ValueError: Возникает, если один из паролей пустой.
    """
    if not plain_password or not hashed_password:
        logger.error("Оба пароля должны быть указаны.")
        raise ValueError("Оба пароля должны быть указаны.")

    try:
        is_valid = pwd_context.verify(plain_password, hashed_password)
        if is_valid:
            logger.info("Пароль успешно подтвержден.")
        else:
            logger.warning("Пароль не совпадает.")
        return is_valid
    except Exception as e:
        logger.error(f"Ошибка при проверке пароля: {e}")
        raise


def register_user(user: UserCreate, db: Session) -> User:
    """
    Регистрирует нового пользователя в системе.

    :param user: Объект UserCreate с данными пользователя.
    :param db: Сессия базы данных для выполнения запросов.
    :return: Объект нового пользователя.
    :raises ValueError: Возникает, если email уже зарегистрирован.
    """
    if not user.email or not user.password:
        logger.error("Email и пароль должны быть указаны.")
        raise ValueError("Email и пароль должны быть указаны.")

    try:
        db_user = db.query(User).filter(User.email == user.email).first()
        if db_user:
            logger.warning(f"Попытка регистрации с уже зарегистрированным email: {user.email}.")
            raise ValueError("Email already registered")

        hashed_password = hash_password(user.password)
        new_user = User(email=user.email, hashed_password=hashed_password)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        logger.info(f"Пользователь {user.email} успешно зарегистрирован.")
        return new_user

    except Exception as e:
        logger.error(f"Ошибка при регистрации пользователя: {e}")
        db.rollback()  # Откат транзакции в случае ошибки
        raise


def authenticate_user(email: str, password: str, db: Session) -> User:
    """
    Аутентифицирует пользователя по его электронной почте и паролю.

    :param email: Электронная почта пользователя.
    :param password: Пароль пользователя.
    :param db: Сессия базы данных для выполнения запросов.
    :return: Объект пользователя, если аутентификация успешна.
    :raises ValueError: Возникает, если учетные данные недействительны.
    """
    if not email or not password:
        logger.error("Email и пароль должны быть указаны.")
        raise ValueError("Email и пароль должны быть указаны.")

    try:
        user = db.query(User).filter(User.email == email).first()

        if not user:
            logger.warning(f"Пользователь с email {email} не найден.")
            raise ValueError("Invalid credentials")

        if not pwd_context.verify(password, user.hashed_password):
            logger.warning("Пароль не совпадает.")
            raise ValueError("Invalid credentials")

        logger.info(f"Пользователь {email} успешно аутентифицирован.")
        return user

    except Exception as e:
        logger.error(f"Ошибка при аутентификации пользователя: {e}")
        raise
