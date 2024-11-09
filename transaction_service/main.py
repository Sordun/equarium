from datetime import date
from typing import Optional, Dict, List

from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session

from auth_service.models import User
from .models import Transaction, Base
from .schemas import TransferSchema, TransactionSchema
from common.database import engine, get_db
from common.logger import logger

app = FastAPI()
Base.metadata.create_all(bind=engine)


@app.post("/transfer", response_model=Dict[str, str])
def transfer(transfer_data: TransferSchema, db: Session = Depends(get_db)) -> dict[str, str]:
    """
    Обрабатывает запрос на перевод средств от одного пользователя к другому.

    Args:
        transfer_data (TransferSchema): Данные о переводе, содержащие следующую информацию:
            - sender_id (int): ID отправителя.
            - receiver_id (int): ID получателя.
            - amount (float): Сумма для перевода.
            - date (date): Дата перевода (необязательный параметр).
            - status (str): Статус перевода (по умолчанию "completed").
        db (Session): Сессия базы данных.
    :return: (dict) Статус перевода.

    :raises HTTPException:
        - 400, Недостаточный баланс.
        - 404, отправитель или получатель не найден.
        - 500, Внутренняя ошибка сервера.
    """
    # Проверяем существование отправителя
    if not check_user_exists(transfer_data.sender_id, db):
        logger.error(f"Попытка перевода от несуществующего отправителя: {transfer_data.sender_id}")
        raise HTTPException(status_code=404, detail="Sender does not exist")
    # Проверяем существование получателя
    if not check_user_exists(transfer_data.receiver_id, db):
        logger.error(f"Попытка перевода к несуществующему получателю: {transfer_data.receiver_id}")
        raise HTTPException(status_code=404, detail="Receiver does not exist")
    # Проверяем баланс
    if not check_balance(transfer_data.sender_id, transfer_data.amount, db):
        logger.error(f"Недостаточный баланс у отправителя: {transfer_data.sender_id}")
        raise HTTPException(status_code=400, detail="Insufficient balance")
    # Выполняем перевод
    try:
        sender = db.query(User).filter(User.id == transfer_data.sender_id).first()
        receiver = db.query(User).filter(User.id == transfer_data.receiver_id).first()

        sender.balance -= transfer_data.amount
        receiver.balance += transfer_data.amount
        # Создаем запись о транзакции
        transaction = Transaction(
            sender_id=transfer_data.sender_id,
            receiver_id=transfer_data.receiver_id,
            amount=transfer_data.amount,
            status="completed"
        )
        db.add(transaction)
        db.commit()
        logger.info(
            f"Перевод завершен: ID:{transfer_data.sender_id} отправил сумму {transfer_data.amount} "
            f"ID:{transfer_data.receiver_id}"
        )
        return {"msg": "Transfer successful"}
    except Exception as e:
        logger.error(f"Ошибка при выполнении перевода: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


def check_user_exists(user_id: int, db: Session) -> bool:
    """
    Проверяет, существует ли пользователь с заданным идентификатором.

    :param user_id: Идентификатор пользователя.
    :param db: Сессия базы данных.
    :return: True, если пользователь существует, иначе False.
    """
    try:
        return db.query(User).filter(User.id == user_id).first() is not None
    except Exception as e:
        logger.error(f"Ошибка при проверке существования пользователя с ID {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error while checking user existence")


def check_balance(user_id: int, amount: float, db: Session) -> bool:
    """
    Проверяет, достаточно ли средств на счете пользователя для совершения транзакции.

    :param user_id: Идентификатор пользователя.
    :param amount: Сумма, которую необходимо проверить.
    :param db: Сессия базы данных.
    :return: True, если баланс достаточен, иначе выбрасывает исключение.
    """
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            raise HTTPException(status_code=404, detail="User  not found")
        return user.balance >= amount
    except Exception as e:
        logger.error(f"Ошибка при проверке баланса пользователя с ID {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error while checking balance")


@app.get("/transaction-history", response_model=dict)
def get_transaction_history(
        user_id: int,
        page: int = 1,
        limit: int = 10,
        start_date: Optional[date] = None,
        end_date: Optional[date] = None,
        status: Optional[str] = None,
        db: Session = Depends(get_db)
) -> Dict[str, List[TransactionSchema]]:
    """
    Получает историю транзакций для указанного пользователя.

    :param user_id: Идентификатор пользователя.
    :param page: Номер страницы для пагинации.
    :param limit: Количество транзакций на странице.
    :param start_date: Дата начала для фильтрации транзакций.
    :param end_date: Дата конца для фильтрации транзакций.
    :param status: Статус транзакции для фильтрации.
    :param db: Сессия базы данных.
    :return: Словарь с историей транзакций.
    """
    try:
        # Проверка существования пользователя
        if not check_user_exists(user_id, db):
            logger.error(f"Пользователь с ID {user_id} не найден.")
            raise HTTPException(status_code=404, detail="User  does not exist")
        # Формирование запроса к базе данных
        query = db.query(Transaction).filter(
            (Transaction.sender_id == user_id) | (Transaction.receiver_id == user_id)
        )
        # Применение фильтров
        if start_date:
            query = query.filter(Transaction.created_at >= start_date)
            logger.info(f"Фильтр по дате начала: {start_date}")
        if end_date:
            query = query.filter(Transaction.created_at <= end_date)
            logger.info(f"Фильтр по дате окончания: {end_date}")
        if status:
            query = query.filter(Transaction.status == status)
            logger.info(f"Фильтр по статусу транзакции: {status}")
        # Получение данных
        total_transactions = query.count()
        transactions = query.offset((page - 1) * limit).limit(limit).all()
        if not transactions:
            logger.info(f"Транзакции не найдены для пользователя {user_id} по заданным фильтрам.")
        else:
            logger.info(f"Найдено транзакций: {total_transactions} для пользователя {user_id}.")
        return {
            "total": total_transactions,
            "page": page,
            "limit": limit,
            "transactions": [TransactionSchema.from_orm(transaction) for transaction in transactions]
        }

    except HTTPException as e:
        # Обработка HTTPException
        logger.error(f"HTTP ошибка: {e.detail}")
        raise e
    except Exception as e:
        # Обработка всех остальных ошибок
        logger.error(f"Ошибка при выполнении запроса к истории транзакций пользователя {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
