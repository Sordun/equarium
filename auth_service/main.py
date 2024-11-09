from typing import Dict

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from .models import Base
from .schemas import UserResponse, TokenResponse, UserInfo, UserCreate, ChangePassword
from .auth import (
    ALGORITHM,
    create_access_token,
    get_user_by_email,
    http_bearer,
    register_user,
    SECRET_KEY,
    verify_password,
    hash_password,
    verify_token,
    authenticate_user,
)

from common.database import engine, get_db
from common.logger import logger

app = FastAPI()
Base.metadata.create_all(bind=engine)


@app.post("/register", response_model=UserResponse)
def register(user: UserCreate, db: Session = Depends(get_db)) -> UserResponse:
    """
    Регистрация нового пользователя в системе.

    :param user: Данные для регистрации пользователя, включающие:
        - email (str): Адрес электронной почты пользователя.
        - password (str): Пароль пользователя.
    :param db: Сессия базы данных для выполнения операций.
    :return: UserResponse: Объект зарегистрированного пользователя, содержащий:
        - id (int): Уникальный идентификатор пользователя.
        - email (str): Адрес электронной почты пользователя.
    :raises HTTPException: В случае ошибки регистрации.
    """
    logger.info(f"Регистрация пользователя: {user.email}")
    try:
        new_user = register_user(user, db)
        return new_user
    except Exception as e:
        logger.error(f"Ошибка при регистрации пользователя: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ошибка при регистрации пользователя. Пожалуйста, проверьте данные и попробуйте снова."
        )


@app.post("/login", response_model=TokenResponse)
def login(email: str, password: str, db: Session = Depends(get_db)) -> TokenResponse:
    """
    Вход пользователя в систему.

    :param email: Электронная почта пользователя.
    :param password: Пароль пользователя.
    :param db: Сессия базы данных.
    :return: TokenResponse: Объект с токеном доступа.
    :raises HTTPException: В случае неверных данных для входа.
    """
    logger.info(f"Попытка входа для: {email}")
    try:
        user = authenticate_user(email, password, db)
        access_token = create_access_token(data={"sub": user.email})
        logger.info(f"Пользователь {user.email} успешно вошел в систему.")

        # Создаем и возвращаем экземпляр TokenResponse
        return TokenResponse(access_token=access_token, token_type="bearer")

    except Exception as e:
        logger.error(f"Ошибка входа для {email}: {e}")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Неверные учетные данные.")


@app.post("/change-password")
def change_password(
        password: ChangePassword,
        token: HTTPAuthorizationCredentials = Depends(http_bearer),
        db: Session = Depends(get_db)
) -> Dict[str, str]:
    """
    Смена пароля пользователя.

    :param password: Объект, содержащий данные для смены пароля.
    :param token: Токен авторизации для проверки пользователя.
    :param db: Сессия базы данных для выполнения операций.
    :return: dict: Сообщение об успешной смене пароля.
    :raises HTTPException: В случае ошибок при смене пароля.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token.credentials, SECRET_KEY, algorithms=ALGORITHM)
        email: str = payload.get("sub")
        if email is None:
            logger.error("Не удалось извлечь email из токена.")
            raise credentials_exception
        else:
            logger.info(f"Смена пароля для: {email}")
    except JWTError as e:
        logger.error(f"Ошибка декодирования JWT: {e}")
        raise credentials_exception

    user = get_user_by_email(db, email=email)
    if user is None:
        logger.error(f"Пользователь с email {email} не найден.")
        raise credentials_exception

    if not verify_password(password.current_password, user.hashed_password):
        logger.error(f"Текущий пароль пользователя {email} неверен.")
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    if password.new_password != password.confirm_new_password:
        logger.error(f"Новый пароль и подтверждение у пользователя {email} не совпадают.")
        raise HTTPException(status_code=400, detail="New password and confirmation do not match")

    try:
        user.hashed_password = hash_password(password.new_password)
        db.commit()
        logger.info(f"Пароль успешно изменен для пользователя {email}.")
        return {"msg": "Password changed successfully"}
    except Exception as e:
        logger.error(f"Ошибка при обновлении пароля в базе данных: {e}")
        raise HTTPException(status_code=500, detail="Error updating password in the database")


@app.get("/users/me", response_model=UserInfo)
def read_users_me(credentials: HTTPAuthorizationCredentials = Depends(http_bearer),
                  db: Session = Depends(get_db)) -> UserInfo:
    """
    Получение информации о текущем пользователе.

    :param credentials: Токен авторизации для проверки пользователя.
    :param db: Сессия базы данных для выполнения операций.
    :return: UserInfo: Информация о пользователе.
    :raises HTTPException:
        - 401, если токен недействителен.
        - 404, если пользователь не найден.
    """
    try:
        email = verify_token(credentials.credentials)
        logger.info(f"Запрос информации о пользователе: {email}")
    except Exception as e:
        logger.error("Недействительный токен")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))

    user = get_user_by_email(db, email=email)  # Получаем пользователя по email
    if user is None:
        logger.warning(f"Пользователь с {email} не найден")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User  not found")

    return UserInfo(email=user.email, created_at=user.created_at, updated_at=user.updated_at, balance=user.balance)
